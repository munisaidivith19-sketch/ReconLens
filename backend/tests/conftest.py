import os

os.environ.setdefault("JWT_SECRET", "test-secret-" + "x" * 40)
os.environ.setdefault("MONGODB_URI", "mongodb://localhost:27017")
os.environ.setdefault("FRONTEND_ORIGIN", "http://localhost:5173")
os.environ["DAILY_SCAN_LIMIT"] = "3"
os.environ["TRUSTED_PROXY_HOPS"] = "1"
os.environ["MAX_CONCURRENT_SCANS"] = "2"
os.environ["GROQ_API_KEY"] = ""
os.environ["VT_API_KEY"] = ""
os.environ["NVD_API_KEY"] = ""

import httpx
import pytest

from app import db as app_db
from app.core import rate_limit
from tests.fakedb import FakeDatabase


@pytest.fixture
async def fake_db():
    database = FakeDatabase()
    await app_db.create_indexes(database)
    app_db.set_db(database)
    yield database
    app_db.set_db(None)


@pytest.fixture
async def client(fake_db, monkeypatch):
    """HTTP client against the app, with lifespan DB connection replaced by the fake."""
    from app.main import app

    async def _noop() -> None:
        return None

    monkeypatch.setattr(app_db, "connect", _noop)
    monkeypatch.setattr(app_db, "close", _noop)
    rate_limit.login_limiter.reset()
    rate_limit.register_limiter.reset()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest.fixture
async def auth_headers(client):
    resp = await client.post(
        "/api/auth/register", json={"email": "hunter@example.org", "password": "correct-horse-battery"}
    )
    assert resp.status_code == 201, resp.text
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.fixture
def public_dns(monkeypatch):
    """Make every hostname resolve to a fixed public IP (no real DNS in tests)."""
    from app.core import ssrf_guard

    table: dict[str, list[str]] = {}

    async def fake_lookup(host: str) -> list[str]:
        return list(table.get(host, ["93.184.216.34"]))

    monkeypatch.setattr(ssrf_guard, "_dns_lookup", fake_lookup)
    return table
