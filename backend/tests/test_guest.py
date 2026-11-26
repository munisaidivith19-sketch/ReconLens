"""Guest access: a few scans without an account, then sign-up is required."""

import pytest

from app.services import scan_runner


@pytest.fixture
def no_background(monkeypatch):
    started = []
    monkeypatch.setattr(scan_runner, "start_scan", lambda db, scan_id: started.append(scan_id))
    return started


async def _guest_headers(client) -> dict[str, str]:
    r = await client.post("/api/auth/guest")
    assert r.status_code == 201, r.text
    assert r.json()["guest_id"].startswith("guest:")
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def _scan(client, headers, target):
    return await client.post(
        "/api/scans", json={"target": target, "confirmed_authorized": True}, headers=headers
    )


async def test_guest_can_scan_three_times_then_must_sign_up(client, public_dns, no_background, fake_db):
    headers = await _guest_headers(client)

    q = (await client.get("/api/scans/quota", headers=headers)).json()
    assert q == {"limit": 3, "used": 0, "remaining": 3, "guest": True}

    for i in range(3):
        r = await _scan(client, headers, f"site{i}.example.com")
        assert r.status_code == 201, r.text
        assert r.json()["quota_remaining"] == 2 - i

    r = await _scan(client, headers, "site9.example.com")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "guest_limit_reached"
    assert len(no_background) == 3

    q = (await client.get("/api/scans/quota", headers=headers)).json()
    assert q["remaining"] == 0


async def test_new_guest_token_does_not_reset_limit(client, public_dns, no_background):
    for i in range(3):
        assert (await _scan(client, await _guest_headers(client), f"a{i}.example.com")).status_code == 201
    r = await _scan(client, await _guest_headers(client), "b.example.com")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "guest_limit_reached"


async def test_blocked_target_does_not_use_guest_scan(client, public_dns, no_background):
    headers = await _guest_headers(client)
    assert (await _scan(client, headers, "127.0.0.1")).status_code == 400
    q = (await client.get("/api/scans/quota", headers=headers)).json()
    assert q["used"] == 0


async def test_guest_sees_own_scan_only(client, auth_headers, public_dns, no_background):
    guest = await _guest_headers(client)
    scan_id = (await _scan(client, guest, "mine.example.com")).json()["scan"]["id"]
    assert (await client.get(f"/api/scans/{scan_id}", headers=guest)).status_code == 200
    assert (await client.get(f"/api/scans/{scan_id}", headers=auth_headers)).status_code == 404
    other = await _guest_headers(client)
    assert (await client.get(f"/api/scans/{scan_id}", headers=other)).status_code == 404


async def test_guest_token_is_not_an_account(client):
    headers = await _guest_headers(client)
    assert (await client.get("/api/auth/me", headers=headers)).status_code == 401


async def test_signed_in_user_uses_daily_limit_not_guest_limit(
    client, auth_headers, public_dns, no_background
):
    q = (await client.get("/api/scans/quota", headers=auth_headers)).json()
    assert q["guest"] is False
    assert q["limit"] == 3  # DAILY_SCAN_LIMIT in tests
    # Guest usage from the same IP doesn't affect a signed-in user.
    for i in range(3):
        assert (await _scan(client, await _guest_headers(client), f"g{i}.example.com")).status_code == 201
    assert (await _scan(client, auth_headers, "user.example.com")).status_code == 201
