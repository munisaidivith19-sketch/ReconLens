import json
import re
from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import Response

from app.api.deps import CurrentUser, Database
from app.core.cache import get_cached_scan_id
from app.core.rate_limit import QuotaExceededError, consume_scan_quota, get_quota_status
from app.core.ssrf_guard import BlockedTargetError, validate_target
from app.models.scan import ScanCreate, ScanDetail, ScanPage, ScanStatus, ScanSummary
from app.services import scan_runner

router = APIRouter(prefix="/api/scans", tags=["scans"])

_NOT_FOUND = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail={"code": "not_found", "message": "Scan not found."},
)


def _summary(doc: dict[str, Any]) -> ScanSummary:
    return ScanSummary(
        id=str(doc["_id"]),
        domain=doc["domain"],
        input=doc.get("input", doc["domain"]),
        status=doc["status"],
        risk_score=doc.get("risk_score"),
        findings_count=len(doc.get("findings") or []),
        created_at=doc["created_at"],
        finished_at=doc.get("finished_at"),
        cached=bool(doc.get("cached_from")),
    )


def _detail(doc: dict[str, Any]) -> ScanDetail:
    s = _summary(doc)
    return ScanDetail(
        **s.model_dump(),
        stages=doc.get("stages", []),
        results=doc.get("results") or {},
        findings=doc.get("findings") or [],
        score_factors=doc.get("score_factors") or [],
        ai_report=doc.get("ai_report"),
        confirmed_authorized=doc["confirmed_authorized"],
        authorized_at=doc["authorized_at"],
        started_at=doc.get("started_at"),
        error=doc.get("error"),
    )


async def _owned_scan(db: Any, scan_id: str, user: dict[str, Any]) -> dict[str, Any]:
    try:
        oid = ObjectId(scan_id)
    except (InvalidId, TypeError):
        raise _NOT_FOUND from None
    doc = await db.scans.find_one({"_id": oid, "user_id": str(user["_id"])})
    if not doc:
        raise _NOT_FOUND  # same response whether it doesn't exist or isn't yours
    return doc


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scan(body: ScanCreate, user: CurrentUser, db: Database) -> dict[str, Any]:
    if body.confirmed_authorized is not True:  # also enforced by the schema
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "scope_not_confirmed",
                "message": "Confirm you are authorized to test this target.",
            },
        )
    try:
        target, _ips = await validate_target(body.target)
    except BlockedTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": f"blocked_target.{exc.code}", "message": exc.message},
        ) from None

    user_id = str(user["_id"])
    now = datetime.now(UTC)
    domain = target.host

    # Same user already scanning this domain: return that scan instead of starting another.
    active = await db.scans.find_one(
        {
            "user_id": user_id,
            "domain": domain,
            "status": {"$in": [ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]},
        }
    )
    if active:
        return {"scan": _summary(active).model_dump(mode="json"), "cached": False, "quota_remaining": None}

    base_doc = {
        "user_id": user_id,
        "input": body.target.strip()[:300],
        "domain": domain,
        "confirmed_authorized": True,
        "authorized_at": now,
        "created_at": now,
    }

    # Domain scanned in the last 24h: copy the finished results for this user (no quota used).
    cached_id = await get_cached_scan_id(db, domain)
    if cached_id:
        try:
            cached = await db.scans.find_one(
                {"_id": ObjectId(cached_id), "status": ScanStatus.COMPLETED.value}
            )
        except InvalidId:
            cached = None
        if cached:
            doc = {
                **base_doc,
                "status": ScanStatus.COMPLETED.value,
                "stages": cached.get("stages", []),
                "results": cached.get("results", {}),
                "findings": cached.get("findings", []),
                "risk_score": cached.get("risk_score"),
                "score_factors": cached.get("score_factors", []),
                "ai_report": cached.get("ai_report"),
                "started_at": cached.get("started_at"),
                "finished_at": cached.get("finished_at"),
                "cached_from": str(cached["_id"]),
            }
            res = await db.scans.insert_one(doc)
            doc["_id"] = res.inserted_id
            return {"scan": _summary(doc).model_dump(mode="json"), "cached": True, "quota_remaining": None}

    try:
        remaining = await consume_scan_quota(db, user_id)
    except QuotaExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "quota_exceeded",
                "message": f"You've reached today's limit of {exc.limit} scans. The quota resets at 00:00 UTC.",
            },
        ) from None

    doc = {
        **base_doc,
        "status": ScanStatus.QUEUED.value,
        "stages": scan_runner.initial_stages(),
        "results": {},
        "findings": [],
        "risk_score": None,
        "score_factors": [],
        "ai_report": None,
    }
    res = await db.scans.insert_one(doc)
    doc["_id"] = res.inserted_id
    scan_runner.start_scan(db, res.inserted_id)
    return {"scan": _summary(doc).model_dump(mode="json"), "cached": False, "quota_remaining": remaining}


@router.get("", response_model=ScanPage)
async def list_scans(
    user: CurrentUser,
    db: Database,
    page: int = Query(1, ge=1, le=1000),
    page_size: int = Query(20, ge=1, le=50),
) -> ScanPage:
    flt = {"user_id": str(user["_id"])}
    total = await db.scans.count_documents(flt)
    projection = {"results": 0, "ai_report": 0, "stages": 0, "score_factors": 0}
    cursor = (
        db.scans.find(flt, projection).sort("created_at", -1).skip((page - 1) * page_size).limit(page_size)
    )
    docs = await cursor.to_list(length=page_size)
    # findings were projected in, so counts stay accurate
    return ScanPage(items=[_summary(d) for d in docs], total=total, page=page, page_size=page_size)


@router.get("/quota")
async def quota(user: CurrentUser, db: Database) -> dict[str, int]:
    return await get_quota_status(db, str(user["_id"]))


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, user: CurrentUser, db: Database) -> ScanDetail:
    return _detail(await _owned_scan(db, scan_id, user))


@router.get("/{scan_id}/export")
async def export_scan(scan_id: str, user: CurrentUser, db: Database) -> Response:
    doc = await _owned_scan(db, scan_id, user)
    detail = _detail(doc).model_dump(mode="json")
    payload = {
        "tool": "ReconLens",
        "format_version": 1,
        "exported_at": datetime.now(UTC).isoformat(),
        "disclaimer": (
            "Generated by passive, automated checks against a target the user confirmed they are "
            "authorized to test. Results may be incomplete; verify before acting."
        ),
        **detail,
    }
    safe_domain = re.sub(r"[^a-z0-9.-]", "_", doc["domain"])
    filename = f"reconlens-{safe_domain}-{doc['created_at']:%Y%m%d}.json"
    return Response(
        content=json.dumps(payload, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
