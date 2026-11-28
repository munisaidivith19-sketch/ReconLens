"""Multi-domain batches, finding triage and personal API keys."""

from datetime import UTC, datetime

import pytest

from app.services import scan_runner


@pytest.fixture
def no_background(monkeypatch):
    started = []
    monkeypatch.setattr(scan_runner, "start_scan", lambda db, scan_id: started.append(scan_id))
    return started


async def _register(client, email):
    r = await client.post("/api/auth/register", json={"email": email, "password": "correct-horse-battery"})
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ---------------------------------------------------------------- batches


async def test_batch_starts_each_target_and_reports_errors(client, auth_headers, public_dns, no_background):
    body = {
        "targets": ["example.com", "EXAMPLE.com", "example.org", "localhost"],
        "confirmed_authorized": True,
    }
    r = await client.post("/api/scans/batch", json=body, headers=auth_headers)
    assert r.status_code == 201, r.text
    data = r.json()
    items = data["items"]
    assert [i["target"] for i in items] == ["example.com", "example.org", "localhost"]  # duplicate removed
    assert [i["ok"] for i in items] == [True, True, False]
    assert items[2]["error"]["code"].startswith("blocked_target")
    assert len(no_background) == 2

    batch = await client.get(f"/api/scans/batch/{data['batch_id']}", headers=auth_headers)
    assert batch.status_code == 200
    b = batch.json()
    assert [s["domain"] for s in b["scans"]] == ["example.com", "example.org"]
    assert all(s["batch_id"] == data["batch_id"] for s in b["scans"])
    assert b["errors"][0]["target"] == "localhost"

    other = await _register(client, "other@example.org")
    assert (await client.get(f"/api/scans/batch/{data['batch_id']}", headers=other)).status_code == 404


async def test_batch_rules(client, auth_headers, public_dns, no_background):
    too_many = {"targets": [f"d{i}.example.com" for i in range(6)], "confirmed_authorized": True}
    assert (await client.post("/api/scans/batch", json=too_many, headers=auth_headers)).status_code == 422
    unconfirmed = {"targets": ["example.com"], "confirmed_authorized": False}
    assert (await client.post("/api/scans/batch", json=unconfirmed, headers=auth_headers)).status_code == 422
    guest = (await client.post("/api/auth/guest")).json()["access_token"]
    r = await client.post(
        "/api/scans/batch",
        json={"targets": ["example.com"], "confirmed_authorized": True},
        headers={"Authorization": f"Bearer {guest}"},
    )
    assert r.status_code == 401
    assert (await client.get("/api/scans/batch/not-hex", headers=auth_headers)).status_code == 404


async def test_batch_respects_daily_quota(client, auth_headers, public_dns, no_background):
    # DAILY_SCAN_LIMIT is 3 in tests.
    body = {"targets": [f"s{i}.example.com" for i in range(5)], "confirmed_authorized": True}
    items = (await client.post("/api/scans/batch", json=body, headers=auth_headers)).json()["items"]
    assert [i["ok"] for i in items] == [True, True, True, False, False]
    assert items[3]["error"]["code"] == "quota_exceeded"


# ---------------------------------------------------------------- triage


async def _completed_scan(client, headers, fake_db, domain="example.com"):
    uid = (await client.get("/api/auth/me", headers=headers)).json()["id"]
    now = datetime.now(UTC)
    res = await fake_db.scans.insert_one(
        {
            "user_id": uid,
            "domain": domain,
            "input": domain,
            "status": "completed",
            "stages": [],
            "results": {},
            "findings": [
                {
                    "id": "security_headers.missing_csp",
                    "title": "No CSP",
                    "severity": "medium",
                    "category": "c",
                    "scanner": "s",
                }
            ],
            "risk_score": 10,
            "confirmed_authorized": True,
            "authorized_at": now,
            "created_at": now,
            "finished_at": now,
        }
    )
    return str(res.inserted_id)


async def test_triage_set_carries_over_and_resets(client, auth_headers, fake_db):
    first = await _completed_scan(client, auth_headers, fake_db)
    url = f"/api/scans/{first}/triage/security_headers.missing_csp"
    r = await client.put(
        url, json={"status": "false_positive", "note": "CSP set by the CDN"}, headers=auth_headers
    )
    assert r.status_code == 200
    assert r.json()["item"]["status"] == "false_positive"

    # A later scan of the same domain sees the same decision.
    second = await _completed_scan(client, auth_headers, fake_db)
    items = (await client.get(f"/api/scans/{second}/triage", headers=auth_headers)).json()["items"]
    assert items["security_headers.missing_csp"]["note"] == "CSP set by the CDN"

    # Back to open with no note removes the record.
    await client.put(url, json={"status": "open"}, headers=auth_headers)
    assert (await client.get(f"/api/scans/{first}/triage", headers=auth_headers)).json()["items"] == {}


async def test_triage_validation_and_ownership(client, auth_headers, fake_db):
    scan_id = await _completed_scan(client, auth_headers, fake_db)
    bad_status = await client.put(
        f"/api/scans/{scan_id}/triage/security_headers.missing_csp",
        json={"status": "ignored"},
        headers=auth_headers,
    )
    assert bad_status.status_code == 422
    unknown = await client.put(
        f"/api/scans/{scan_id}/triage/not.a.finding", json={"status": "fixed"}, headers=auth_headers
    )
    assert unknown.status_code == 404
    other = await _register(client, "other@example.org")
    r = await client.put(
        f"/api/scans/{scan_id}/triage/security_headers.missing_csp", json={"status": "fixed"}, headers=other
    )
    assert r.status_code == 404


# ---------------------------------------------------------------- API keys


async def test_api_key_lifecycle(client, auth_headers, fake_db, public_dns, no_background):
    r = await client.post("/api/keys", json={"name": "ci pipeline"}, headers=auth_headers)
    assert r.status_code == 201
    created = r.json()
    key = created["key"]
    assert key.startswith("rl_") and created["prefix"] == key[:10]
    stored = await fake_db.api_keys.find_one({})
    assert key not in str(stored)  # only the hash is stored

    listed = (await client.get("/api/keys", headers=auth_headers)).json()["items"]
    assert [k["name"] for k in listed] == ["ci pipeline"] and "key" not in listed[0]

    key_headers = {"Authorization": f"Bearer {key}"}
    scan = await client.post(
        "/api/scans", json={"target": "example.com", "confirmed_authorized": True}, headers=key_headers
    )
    assert scan.status_code == 201
    assert (await client.get("/api/scans", headers=key_headers)).json()["total"] == 1
    assert (await client.get("/api/keys", headers=auth_headers)).json()["items"][0]["last_used_at"]

    # A key cannot manage keys.
    assert (await client.post("/api/keys", json={"name": "x"}, headers=key_headers)).status_code == 403
    assert (await client.get("/api/keys", headers=key_headers)).status_code == 403

    assert (await client.delete(f"/api/keys/{created['id']}", headers=auth_headers)).status_code == 204
    revoked = await client.get("/api/scans", headers=key_headers)
    assert revoked.status_code == 401
    assert revoked.json()["detail"]["code"] == "invalid_api_key"


async def test_api_key_limits(client, auth_headers):
    for i in range(5):
        assert (
            await client.post("/api/keys", json={"name": f"k{i}"}, headers=auth_headers)
        ).status_code == 201
    r = await client.post("/api/keys", json={"name": "k6"}, headers=auth_headers)
    assert r.status_code == 409
    assert (
        await client.post("/api/keys", json={"name": "<script>"}, headers=auth_headers)
    ).status_code == 422
    fake = {"Authorization": "Bearer rl_" + "A" * 43}
    assert (await client.get("/api/scans", headers=fake)).status_code == 401
    other = await _register(client, "other@example.org")
    key_id = (await client.get("/api/keys", headers=auth_headers)).json()["items"][0]["id"]
    assert (await client.delete(f"/api/keys/{key_id}", headers=other)).status_code == 404
