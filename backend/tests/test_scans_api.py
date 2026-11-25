from datetime import UTC, datetime

import pytest

from app.core.cache import set_cached_scan
from app.services import scan_runner


@pytest.fixture
def no_background(monkeypatch):
    started = []
    monkeypatch.setattr(scan_runner, "start_scan", lambda db, scan_id: started.append(scan_id))
    return started


async def test_create_scan_requires_auth(client):
    r = await client.post("/api/scans", json={"target": "example.com", "confirmed_authorized": True})
    assert r.status_code == 401


async def test_scope_confirmation_required(client, auth_headers, public_dns, no_background):
    r = await client.post(
        "/api/scans", json={"target": "example.com", "confirmed_authorized": False}, headers=auth_headers
    )
    assert r.status_code == 422
    r = await client.post("/api/scans", json={"target": "example.com"}, headers=auth_headers)
    assert r.status_code == 422
    assert no_background == []


async def test_create_scan_stores_authorization(client, auth_headers, fake_db, public_dns, no_background):
    r = await client.post(
        "/api/scans",
        json={"target": "https://Example.com/path", "confirmed_authorized": True},
        headers=auth_headers,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["scan"]["domain"] == "example.com"
    assert body["scan"]["status"] == "queued"
    assert body["quota_remaining"] == 2
    doc = fake_db.scans.docs[0]
    assert doc["confirmed_authorized"] is True
    assert isinstance(doc["authorized_at"], datetime)
    assert len(no_background) == 1


@pytest.mark.parametrize(
    ("target", "dns", "code"),
    [
        ("127.0.0.1", None, "blocked_target.ip_address"),
        ("localhost", None, "blocked_target.invalid_host"),
        ("internal.example.org", ["10.0.0.8"], "blocked_target.private_ip"),
        ("meta.example.org", ["169.254.169.254"], "blocked_target.private_ip"),
        ("https://example.com:8443", None, "blocked_target.port"),
    ],
)
async def test_blocked_targets(client, auth_headers, public_dns, no_background, target, dns, code):
    if dns:
        public_dns[target] = dns
    r = await client.post(
        "/api/scans", json={"target": target, "confirmed_authorized": True}, headers=auth_headers
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == code
    assert no_background == []


async def test_quota_enforced(client, auth_headers, public_dns, no_background, fake_db):
    for i in range(3):
        r = await client.post(
            "/api/scans",
            json={"target": f"site{i}.example.com", "confirmed_authorized": True},
            headers=auth_headers,
        )
        assert r.status_code == 201
    r = await client.post(
        "/api/scans", json={"target": "site9.example.com", "confirmed_authorized": True}, headers=auth_headers
    )
    assert r.status_code == 429
    assert r.json()["detail"]["code"] == "quota_exceeded"


async def test_duplicate_active_scan_reused(client, auth_headers, public_dns, no_background):
    body = {"target": "example.com", "confirmed_authorized": True}
    a = await client.post("/api/scans", json=body, headers=auth_headers)
    b = await client.post("/api/scans", json=body, headers=auth_headers)
    assert a.json()["scan"]["id"] == b.json()["scan"]["id"]
    assert len(no_background) == 1


async def test_cached_scan_cloned_for_other_user(client, auth_headers, public_dns, no_background, fake_db):
    now = datetime.now(UTC)
    res = await fake_db.scans.insert_one(
        {
            "user_id": "someone-else",
            "domain": "example.com",
            "input": "example.com",
            "status": "completed",
            "stages": [],
            "results": {"dns_records": {"records": {}}},
            "findings": [{"id": "x", "title": "t", "severity": "low", "category": "c", "scanner": "s"}],
            "risk_score": 12,
            "confirmed_authorized": True,
            "authorized_at": now,
            "created_at": now,
            "finished_at": now,
        }
    )
    await set_cached_scan(fake_db, "example.com", str(res.inserted_id))
    r = await client.post(
        "/api/scans", json={"target": "example.com", "confirmed_authorized": True}, headers=auth_headers
    )
    assert r.status_code == 201
    body = r.json()
    assert body["cached"] is True
    assert body["scan"]["status"] == "completed"
    assert body["scan"]["id"] != str(res.inserted_id)
    assert no_background == []
    detail = await client.get(f"/api/scans/{body['scan']['id']}", headers=auth_headers)
    assert detail.json()["risk_score"] == 12
    assert detail.json()["confirmed_authorized"] is True


async def test_owner_only_and_export(client, auth_headers, public_dns, no_background):
    r = await client.post(
        "/api/scans", json={"target": "example.com", "confirmed_authorized": True}, headers=auth_headers
    )
    scan_id = r.json()["scan"]["id"]

    detail = await client.get(f"/api/scans/{scan_id}", headers=auth_headers)
    assert detail.status_code == 200
    assert [s["status"] for s in detail.json()["stages"]] == ["pending"] * len(detail.json()["stages"])

    export = await client.get(f"/api/scans/{scan_id}/export", headers=auth_headers)
    assert export.status_code == 200
    assert "attachment" in export.headers["content-disposition"]
    assert export.json()["tool"] == "ReconLens"

    other = await client.post(
        "/api/auth/register", json={"email": "other@example.org", "password": "another-long-pass"}
    )
    other_headers = {"Authorization": f"Bearer {other.json()['access_token']}"}
    assert (await client.get(f"/api/scans/{scan_id}", headers=other_headers)).status_code == 404
    assert (await client.get(f"/api/scans/{scan_id}/export", headers=other_headers)).status_code == 404
    assert (await client.get("/api/scans/not-an-id", headers=auth_headers)).status_code == 404


async def test_history_paginated(client, auth_headers, public_dns, no_background):
    for i in range(3):
        await client.post(
            "/api/scans",
            json={"target": f"s{i}.example.com", "confirmed_authorized": True},
            headers=auth_headers,
        )
    r = await client.get("/api/scans?page=1&page_size=2", headers=auth_headers)
    body = r.json()
    assert body["total"] == 3
    assert len(body["items"]) == 2
    assert body["items"][0]["domain"] == "s2.example.com"  # newest first
    r2 = await client.get("/api/scans?page=2&page_size=2", headers=auth_headers)
    assert len(r2.json()["items"]) == 1
    q = await client.get("/api/scans/quota", headers=auth_headers)
    assert q.json() == {"limit": 3, "used": 3, "remaining": 0}
