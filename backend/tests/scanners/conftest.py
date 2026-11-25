import pytest

from app.core.ssrf_guard import SafeHttpClient
from app.scanners import base
from app.scanners.base import ScanContext

TARGET_IP = "93.184.216.34"


@pytest.fixture
async def ctx(public_dns, fake_db):
    async with SafeHttpClient() as client:
        yield ScanContext(domain="example.com", db=fake_db, client=client)


@pytest.fixture
def fake_dns(monkeypatch):
    """Patch base.dns_query with a lookup table {(name, type): [values]}."""
    table: dict[tuple[str, str], list[str] | Exception] = {}

    async def lookup(name: str, rdtype: str) -> list[str]:
        value = table.get((name, rdtype), [])
        if isinstance(value, Exception):
            raise value
        return list(value)

    monkeypatch.setattr(base, "dns_query", lookup)
    return table
