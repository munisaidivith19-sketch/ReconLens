import asyncio
from datetime import UTC, datetime

import pytest

from app.models.finding import Severity
from app.scanners.base import Scanner, ScannerResult
from app.services import scan_runner


class DummyClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None


class OkScanner(Scanner):
    name = "ok"
    label = "OK"
    category = "Test"
    timeout = 5

    async def run(self, ctx):
        return ScannerResult(
            data={"value": 1, "dotted.key": {"$bad": True}},
            findings=[self.finding("thing", "Low thing", Severity.LOW)],
        )


class BoomScanner(Scanner):
    name = "boom"
    label = "Boom"
    category = "Test"
    timeout = 5

    async def run(self, ctx):
        raise RuntimeError("kaboom\nTraceback secret line")


class SlowScanner(Scanner):
    name = "slow"
    label = "Slow"
    category = "Test"
    timeout = 0.05

    async def run(self, ctx):
        await asyncio.sleep(5)
        return ScannerResult()


class DependentScanner(Scanner):
    name = "dependent"
    label = "Dependent"
    category = "Test"
    timeout = 5
    depends_on = ("ok",)

    async def run(self, ctx):
        assert "ok" in ctx.results
        return ScannerResult(
            data={"saw": ctx.results["ok"]["value"]},
            findings=[self.finding("crit", "Critical thing", Severity.CRITICAL)],
        )


SCANNERS = [DependentScanner(), OkScanner(), BoomScanner(), SlowScanner()]


@pytest.fixture(autouse=True)
def _reset():
    scan_runner.reset_state()
    yield
    scan_runner.reset_state()


async def _make_scan(fake_db, status="queued"):
    doc = {
        "user_id": "u1",
        "domain": "example.com",
        "input": "example.com",
        "status": status,
        "stages": scan_runner.initial_stages(SCANNERS),
        "results": {},
        "findings": [],
        "confirmed_authorized": True,
        "authorized_at": datetime.now(UTC),
        "created_at": datetime.now(UTC),
    }
    res = await fake_db.scans.insert_one(doc)
    return res.inserted_id


async def test_runner_isolates_failures_and_saves_progress(fake_db):
    scan_id = await _make_scan(fake_db)
    await scan_runner.run_scan(fake_db, scan_id, scanners=SCANNERS, client_factory=DummyClient)
    doc = await fake_db.scans.find_one({"_id": scan_id})

    assert doc["status"] == "completed"
    stages = {s["name"]: s for s in doc["stages"]}
    assert stages["ok"]["status"] == "done"
    assert stages["dependent"]["status"] == "done"
    assert stages["boom"]["status"] == "failed"
    assert stages["boom"]["error"] == "RuntimeError: kaboom"  # first line only, no traceback
    assert stages["slow"]["status"] == "failed"
    assert "Timed out" in stages["slow"]["error"]
    assert all(s["started_at"] and s["finished_at"] for s in doc["stages"])

    assert doc["results"]["dependent"] == {"saw": 1}
    assert doc["results"]["ok"]["dotted_key"] == {"_bad": True}  # Mongo-safe keys
    assert [f["severity"] for f in doc["findings"]] == ["critical", "low"]  # sorted

    assert stages["risk_score"]["status"] == "done"
    assert stages["ai_report"]["status"] == "done"
    assert 0 < doc["risk_score"] <= 100
    assert doc["score_factors"][0]["severity"] == "critical"
    assert doc["ai_report"]["generated_by"] == "template"  # no GROQ_API_KEY in tests
    assert any("Boom" in g for g in doc["ai_report"]["data_gaps"])

    cache = await fake_db.scan_cache.find_one({"domain": "example.com"})
    assert cache["scan_id"] == str(scan_id)


async def test_runner_skips_non_queued(fake_db):
    scan_id = await _make_scan(fake_db, status="completed")
    await scan_runner.run_scan(fake_db, scan_id, scanners=SCANNERS, client_factory=DummyClient)
    doc = await fake_db.scans.find_one({"_id": scan_id})
    assert doc["results"] == {}


async def test_concurrency_cap(fake_db, monkeypatch):
    running = 0
    peak = 0

    class Tracking(Scanner):
        name = "tracking"
        label = "Tracking"
        category = "Test"
        timeout = 5

        async def run(self, ctx):
            nonlocal running, peak
            running += 1
            peak = max(peak, running)
            await asyncio.sleep(0.05)
            running -= 1
            return ScannerResult()

    ids = []
    for _ in range(5):
        ids.append(await _make_scan(fake_db))
    await asyncio.gather(
        *(scan_runner.run_scan(fake_db, i, scanners=[Tracking()], client_factory=DummyClient) for i in ids)
    )
    assert peak == 2  # MAX_CONCURRENT_SCANS default


async def test_unexpected_error_marks_scan_failed(fake_db):
    class Exploding:
        async def __aenter__(self):
            raise OSError("cannot create client")

        async def __aexit__(self, *a):
            return None

    scan_id = await _make_scan(fake_db)
    await scan_runner.run_scan(fake_db, scan_id, scanners=SCANNERS, client_factory=Exploding)
    doc = await fake_db.scans.find_one({"_id": scan_id})
    assert doc["status"] == "failed"
    assert "cannot create client" not in doc["error"]


async def test_mark_interrupted(fake_db):
    a = await _make_scan(fake_db, status="running")
    b = await _make_scan(fake_db, status="queued")
    c = await _make_scan(fake_db, status="completed")
    await scan_runner.mark_interrupted(fake_db)
    statuses = {d["_id"]: d["status"] for d in fake_db.scans.docs}
    assert statuses[a] == statuses[b] == "interrupted"
    assert statuses[c] == "completed"
