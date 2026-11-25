from datetime import UTC, datetime, timedelta

import jwt

from app.config import get_settings


async def test_health(client):
    resp = await client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.headers["x-content-type-options"] == "nosniff"


async def test_register_login_me(client):
    creds = {"email": "Alice@Example.org", "password": "a-very-long-password"}
    r = await client.post("/api/auth/register", json=creds)
    assert r.status_code == 201
    body = r.json()
    assert body["user"]["email"] == "alice@example.org"
    assert "password_hash" not in body["user"]

    r = await client.post("/api/auth/login", json=creds)
    assert r.status_code == 200
    token = r.json()["access_token"]

    r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    assert r.json()["email"] == "alice@example.org"


async def test_password_is_hashed_with_argon2(client, fake_db):
    await client.post("/api/auth/register", json={"email": "b@example.org", "password": "another-password"})
    user = await fake_db.users.find_one({"email": "b@example.org"})
    assert user["password_hash"].startswith("$argon2")


async def test_duplicate_registration_generic_error(client):
    creds = {"email": "dup@example.org", "password": "a-very-long-password"}
    assert (await client.post("/api/auth/register", json=creds)).status_code == 201
    r = await client.post("/api/auth/register", json=creds)
    assert r.status_code == 400
    assert "exist" not in r.text.lower()


async def test_login_errors_are_generic(client):
    await client.post(
        "/api/auth/register", json={"email": "c@example.org", "password": "a-very-long-password"}
    )
    wrong_pw = await client.post(
        "/api/auth/login", json={"email": "c@example.org", "password": "nope-nope-nope"}
    )
    no_user = await client.post(
        "/api/auth/login", json={"email": "ghost@example.org", "password": "nope-nope-nope"}
    )
    assert wrong_pw.status_code == no_user.status_code == 401
    assert wrong_pw.json() == no_user.json()


async def test_weak_password_rejected(client):
    r = await client.post("/api/auth/register", json={"email": "d@example.org", "password": "short"})
    assert r.status_code == 422


async def test_me_requires_token(client):
    assert (await client.get("/api/auth/me")).status_code == 401
    r = await client.get("/api/auth/me", headers={"Authorization": "Bearer garbage"})
    assert r.status_code == 401
    assert r.json()["detail"]["code"] == "session_expired"


async def test_expired_token_rejected(client, auth_headers):
    me = await client.get("/api/auth/me", headers=auth_headers)
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": me.json()["id"],
            "iat": now - timedelta(hours=2),
            "exp": now - timedelta(hours=1),
            "iss": "reconlens",
            "aud": "reconlens-api",
            "type": "access",
        },
        get_settings().JWT_SECRET,
        algorithm="HS256",
    )
    r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


async def test_alg_none_token_rejected(client, auth_headers):
    me = await client.get("/api/auth/me", headers=auth_headers)
    token = jwt.encode(
        {"sub": me.json()["id"], "iss": "reconlens", "aud": "reconlens-api", "type": "access"},
        key=None,
        algorithm="none",
    )
    r = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


async def test_login_rate_limited_per_ip(client):
    creds = {"email": "e@example.org", "password": "wrong-password-x"}
    codes = [(await client.post("/api/auth/login", json=creds)).status_code for _ in range(11)]
    assert codes[:10] == [401] * 10
    assert codes[10] == 429


async def test_body_size_limit(client):
    r = await client.post(
        "/api/auth/login",
        content=b'{"email":"' + b"a" * 20000 + b'"}',
        headers={"Content-Type": "application/json"},
    )
    assert r.status_code == 413


async def test_cors_only_frontend_origin(client):
    ok = await client.options(
        "/api/auth/login",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"},
    )
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    bad = await client.options(
        "/api/auth/login",
        headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"},
    )
    assert "access-control-allow-origin" not in bad.headers
