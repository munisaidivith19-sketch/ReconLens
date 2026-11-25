import httpx
import pytest
import respx

from app.config import get_settings
from app.scanners import virustotal
from app.scanners.virustotal import VirusTotalScanner

VT_IP = "104.16.2.2"


@pytest.fixture
def vt_key(monkeypatch, public_dns):
    public_dns["www.virustotal.com"] = [VT_IP]
    monkeypatch.setattr(get_settings(), "VT_API_KEY", "test-key")
    virustotal.vt_limiter.reset()
    yield
    virustotal.vt_limiter.reset()


def vt_doc(malicious=0, suspicious=0, reputation=0):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": 70,
                    "undetected": 20,
                },
                "reputation": reputation,
                "categories": {"Forcepoint ThreatSeeker": "information technology", "alphaMountain.ai": "IT"},
            }
        }
    }


async def test_skipped_without_key(ctx):
    res = await VirusTotalScanner().run(ctx)
    assert res.data["status"] == "skipped"
    assert "not configured" in res.data["message"]


@respx.mock
async def test_clean_domain(ctx, vt_key):
    route = respx.get(f"https://{VT_IP}/api/v3/domains/example.com").mock(
        return_value=httpx.Response(200, json=vt_doc())
    )
    res = await VirusTotalScanner().run(ctx)
    assert route.calls.last.request.headers["x-apikey"] == "test-key"
    assert res.data["status"] == "ok"
    assert res.data["stats"]["malicious"] == 0
    assert {"engine": "alphaMountain.ai", "category": "IT"} in res.data["categories"]
    assert res.findings == []


@respx.mock
async def test_malicious_domain_flagged(ctx, vt_key):
    respx.get(f"https://{VT_IP}/api/v3/domains/example.com").mock(
        return_value=httpx.Response(200, json=vt_doc(malicious=5, reputation=-20))
    )
    res = await VirusTotalScanner().run(ctx)
    ids = {f.id: f.severity for f in res.findings}
    assert ids["virustotal.malicious"] == "high"
    assert "virustotal.negative_reputation" in ids


@respx.mock
async def test_rate_limit_path_returns_skipped(ctx, vt_key, monkeypatch):
    async def no_slot(max_wait=0.0):
        return False

    monkeypatch.setattr(virustotal.vt_limiter, "acquire", no_slot)
    route = respx.get(url__startswith=f"https://{VT_IP}/")
    res = await VirusTotalScanner().run(ctx)
    assert not route.called
    assert res.data == {"status": "skipped", "message": "reputation check skipped: rate limit"}


@respx.mock
async def test_http_429_returns_skipped(ctx, vt_key):
    respx.get(url__startswith=f"https://{VT_IP}/").mock(return_value=httpx.Response(429))
    res = await VirusTotalScanner().run(ctx)
    assert res.data["message"] == "reputation check skipped: rate limit"


@respx.mock
async def test_cache_avoids_second_call(ctx, vt_key):
    route = respx.get(url__startswith=f"https://{VT_IP}/").mock(
        return_value=httpx.Response(200, json=vt_doc())
    )
    await VirusTotalScanner().run(ctx)
    await VirusTotalScanner().run(ctx)
    assert route.call_count == 1


async def test_limiter_allows_four_per_minute():
    limiter = virustotal.AsyncRateLimiter(max_calls=4, period=60)
    assert all([await limiter.acquire() for _ in range(4)])
    assert await limiter.acquire(max_wait=0) is False
