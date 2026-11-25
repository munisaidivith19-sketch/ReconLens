"""Runs scanners as asyncio background tasks and saves per-stage progress to MongoDB.

* At most MAX_CONCURRENT_SCANS scans run at once (asyncio.Semaphore); others wait "queued".
* Within a scan, scanners run concurrently (bounded) unless they declare depends_on.
* Every scanner has its own timeout; a failure marks only that stage as failed.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

from bson import ObjectId

from app.config import get_settings
from app.core.cache import set_cached_scan
from app.core.ssrf_guard import SafeHttpClient
from app.models.finding import SEVERITY_ORDER, Severity
from app.models.scan import ScanStatus, StageStatus
from app.scanners import Scanner, get_scanners
from app.scanners.base import ScanContext, describe_error

log = logging.getLogger(__name__)

SCANNER_PARALLELISM = 3

_semaphore: asyncio.Semaphore | None = None
_tasks: set[asyncio.Task] = set()

PostStage = tuple[str, str, Callable[[Any, ObjectId, dict[str, Any]], Any]]


def _now() -> datetime:
    return datetime.now(UTC)


def get_semaphore() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(get_settings().MAX_CONCURRENT_SCANS)
    return _semaphore


def reset_state() -> None:
    """Testing helper."""
    global _semaphore
    _semaphore = None
    _tasks.clear()


def post_stages() -> list[PostStage]:
    """Stages that run after all scanners, in order."""
    from app.services.ai_report import ai_report_stage
    from app.services.risk_score import risk_stage

    return [
        ("risk_score", "Risk score", risk_stage),
        ("ai_report", "AI report", ai_report_stage),
    ]


def initial_stages(scanners: Sequence[Scanner] | None = None) -> list[dict[str, Any]]:
    scanners = scanners if scanners is not None else get_scanners()
    stages = [
        {
            "name": s.name,
            "label": s.label,
            "status": StageStatus.PENDING.value,
            "started_at": None,
            "finished_at": None,
            "error": None,
        }
        for s in scanners
    ]
    for name, label, _fn in post_stages():
        stages.append(
            {
                "name": name,
                "label": label,
                "status": StageStatus.PENDING.value,
                "started_at": None,
                "finished_at": None,
                "error": None,
            }
        )
    return stages


def mongo_safe(value: Any) -> Any:
    """Make keys storable in MongoDB (no '.' or leading '$')."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = str(k).replace(".", "_")
            if key.startswith("$"):
                key = "_" + key[1:]
            out[key] = mongo_safe(v)
        return out
    if isinstance(value, list | tuple):
        return [mongo_safe(v) for v in value]
    return value


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: -SEVERITY_ORDER.index(Severity(f["severity"])))


def start_scan(db: Any, scan_id: ObjectId) -> asyncio.Task:
    task = asyncio.create_task(run_scan(db, scan_id), name=f"scan-{scan_id}")
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return task


async def _set(db: Any, scan_id: ObjectId, fields: dict[str, Any]) -> None:
    await db.scans.update_one({"_id": scan_id}, {"$set": fields})


async def run_scan(
    db: Any,
    scan_id: ObjectId,
    scanners: Sequence[Scanner] | None = None,
    client_factory: Callable[[], SafeHttpClient] = SafeHttpClient,
) -> None:
    scanners = list(scanners) if scanners is not None else get_scanners()
    async with get_semaphore():
        doc = await db.scans.find_one({"_id": scan_id})
        if not doc or doc.get("status") != ScanStatus.QUEUED.value:
            return
        await _set(db, scan_id, {"status": ScanStatus.RUNNING.value, "started_at": _now()})
        try:
            async with client_factory() as client:
                ctx = ScanContext(domain=doc["domain"], db=db, client=client)
                findings = await _run_scanners(db, scan_id, scanners, ctx)
            findings = sort_findings(findings)
            await _set(db, scan_id, {"findings": findings})

            offset = len(scanners)
            state = {"domain": doc["domain"], "results": ctx.results, "findings": findings}
            for i, (name, _label, fn) in enumerate(post_stages()):
                idx = offset + i
                await _set(
                    db,
                    scan_id,
                    {f"stages.{idx}.status": StageStatus.RUNNING.value, f"stages.{idx}.started_at": _now()},
                )
                try:
                    update = await fn(db, scan_id, state)
                    fields = {
                        f"stages.{idx}.status": StageStatus.DONE.value,
                        f"stages.{idx}.finished_at": _now(),
                    }
                    if update:
                        fields.update(mongo_safe(update))
                        state.update(update)
                    await _set(db, scan_id, fields)
                except Exception as exc:  # noqa: BLE001 - a failed post stage must not fail the scan
                    log.warning("post stage %s failed for scan %s: %s", name, scan_id, type(exc).__name__)
                    await _set(
                        db,
                        scan_id,
                        {
                            f"stages.{idx}.status": StageStatus.FAILED.value,
                            f"stages.{idx}.finished_at": _now(),
                            f"stages.{idx}.error": describe_error(exc),
                        },
                    )

            await _set(db, scan_id, {"status": ScanStatus.COMPLETED.value, "finished_at": _now()})
            await set_cached_scan(db, doc["domain"], str(scan_id))
        except Exception as exc:  # noqa: BLE001 - the scan document must always reach a final state
            log.error("scan %s failed: %s", scan_id, type(exc).__name__)
            await _set(
                db,
                scan_id,
                {
                    "status": ScanStatus.FAILED.value,
                    "finished_at": _now(),
                    "error": "The scan stopped unexpectedly. Please try again later.",
                },
            )


async def _run_scanners(
    db: Any, scan_id: ObjectId, scanners: list[Scanner], ctx: ScanContext
) -> list[dict[str, Any]]:
    done_events = {s.name: asyncio.Event() for s in scanners}
    limiter = asyncio.Semaphore(SCANNER_PARALLELISM)
    findings: list[dict[str, Any]] = []

    async def run_one(idx: int, scanner: Scanner) -> None:
        try:
            for dep in scanner.depends_on:
                if dep in done_events:
                    await done_events[dep].wait()
            async with limiter:
                await _set(
                    db,
                    scan_id,
                    {f"stages.{idx}.status": StageStatus.RUNNING.value, f"stages.{idx}.started_at": _now()},
                )
                try:
                    result = await asyncio.wait_for(scanner.run(ctx), timeout=scanner.timeout)
                except TimeoutError:
                    await _fail(idx, f"Timed out after {scanner.timeout:.0f} seconds.")
                    return
                except Exception as exc:  # noqa: BLE001 - one scanner never stops the others
                    log.info("scanner %s failed: %s", scanner.name, type(exc).__name__)
                    await _fail(idx, describe_error(exc))
                    return
                data = mongo_safe(result.data)
                ctx.results[scanner.name] = data
                findings.extend(f.model_dump(mode="json") for f in result.findings)
                await _set(
                    db,
                    scan_id,
                    {
                        f"stages.{idx}.status": StageStatus.DONE.value,
                        f"stages.{idx}.finished_at": _now(),
                        f"results.{scanner.name}": data,
                        "findings": sort_findings(list(findings)),
                    },
                )
        finally:
            done_events[scanner.name].set()

    async def _fail(idx: int, error: str) -> None:
        await _set(
            db,
            scan_id,
            {
                f"stages.{idx}.status": StageStatus.FAILED.value,
                f"stages.{idx}.finished_at": _now(),
                f"stages.{idx}.error": error,
            },
        )

    await asyncio.gather(*(run_one(i, s) for i, s in enumerate(scanners)))
    return findings


async def mark_interrupted(db: Any) -> int:
    """On startup: scans left queued/running by a previous process can never finish."""
    result = await db.scans.update_many(
        {"status": {"$in": [ScanStatus.RUNNING.value, ScanStatus.QUEUED.value]}},
        {
            "$set": {
                "status": ScanStatus.INTERRUPTED.value,
                "finished_at": _now(),
                "error": "The server restarted while this scan was running. Start a new scan.",
            }
        },
    )
    return getattr(result, "modified_count", 0)
