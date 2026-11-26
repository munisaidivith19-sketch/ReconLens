"""Previous-scan comparison, domain filter and read-only share links."""

from datetime import UTC, datetime, timedelta

from bson import ObjectId


async def _user_id(client, headers) -> str:
    return (await client.get("/api/auth/me", headers=headers)).json()["id"]


async def _insert_scan(fake_db, user_id, domain="example.com", status="completed", age_days=0, score=10):
    when = datetime.now(UTC) - timedelta(days=age_days)
    res = await fake_db.scans.insert_one(
        {
            "user_id": user_id,
            "domain": domain,
            "input": domain,
            "status": status,
            "stages": [],
            "results": {},
            "findings": [
                {"id": f"f{score}", "title": "t", "severity": "low", "category": "c", "scanner": "s"}
            ],
            "risk_score": score,
            "confirmed_authorized": True,
            "authorized_at": when,
            "created_at": when,
            "finished_at": when,
        }
    )
    return str(res.inserted_id)


async def test_previous_scan_and_domain_filter(client, auth_headers, fake_db):
    uid = await _user_id(client, auth_headers)
    old = await _insert_scan(fake_db, uid, age_days=5, score=40)
    await _insert_scan(fake_db, uid, age_days=3, status="failed")
    await _insert_scan(fake_db, uid, domain="other.org", age_days=2)
    new = await _insert_scan(fake_db, uid, age_days=0, score=20)

    r = await client.get(f"/api/scans/{new}/previous", headers=auth_headers)
    assert r.status_code == 200
    assert r.json()["previous"]["id"] == old
    assert r.json()["previous"]["risk_score"] == 40

    r = await client.get(f"/api/scans/{old}/previous", headers=auth_headers)
    assert r.json()["previous"] is None

    page = await client.get("/api/scans?domain=example.com", headers=auth_headers)
    assert page.json()["total"] == 3
    assert (await client.get("/api/scans?domain=bad/value", headers=auth_headers)).status_code == 422


async def test_share_link_lifecycle(client, auth_headers, fake_db):
    uid = await _user_id(client, auth_headers)
    scan_id = await _insert_scan(fake_db, uid)

    assert (await client.get(f"/api/scans/{scan_id}/share", headers=auth_headers)).json() == {"share": None}
    r = await client.post(f"/api/scans/{scan_id}/share", headers=auth_headers)
    assert r.status_code == 201
    token = r.json()["share"]["token"]
    # Creating again returns the same link.
    again = await client.post(f"/api/scans/{scan_id}/share", headers=auth_headers)
    assert again.json()["share"]["token"] == token

    public = await client.get(f"/api/shared/{token}")  # no auth header
    assert public.status_code == 200
    assert public.json()["scan"]["id"] == scan_id
    assert "input" not in public.json()["scan"]

    assert (await client.delete(f"/api/scans/{scan_id}/share", headers=auth_headers)).status_code == 204
    assert (await client.get(f"/api/shared/{token}")).status_code == 404


async def test_share_rules(client, auth_headers, fake_db):
    uid = await _user_id(client, auth_headers)
    running = await _insert_scan(fake_db, uid, status="running")
    assert (await client.post(f"/api/scans/{running}/share", headers=auth_headers)).status_code == 409

    # Guests cannot create share links.
    guest = (await client.post("/api/auth/guest")).json()["access_token"]
    done = await _insert_scan(fake_db, uid)
    r = await client.post(f"/api/scans/{done}/share", headers={"Authorization": f"Bearer {guest}"})
    assert r.status_code in (401, 403)

    # Expired and malformed tokens are rejected.
    await fake_db.shares.insert_one(
        {
            "token": "x" * 32,
            "scan_id": done,
            "user_id": uid,
            "created_at": datetime.now(UTC),
            "expires_at": datetime.now(UTC) - timedelta(minutes=1),
        }
    )
    assert (await client.get(f"/api/shared/{'x' * 32}")).status_code == 404
    assert (await client.get("/api/shared/bad!token")).status_code == 404
    assert (await client.get(f"/api/shared/{ObjectId()}")).status_code == 404
