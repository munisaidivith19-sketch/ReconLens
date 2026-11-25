import pytest

from app.core.rate_limit import (
    QuotaExceededError,
    RateLimitedError,
    SlidingWindowLimiter,
    consume_scan_quota,
    get_quota_status,
    refund_scan_quota,
)


async def test_daily_quota_enforced(fake_db):
    # DAILY_SCAN_LIMIT=3 in conftest
    assert await consume_scan_quota(fake_db, "u1") == 2
    assert await consume_scan_quota(fake_db, "u1") == 1
    assert await consume_scan_quota(fake_db, "u1") == 0
    with pytest.raises(QuotaExceededError):
        await consume_scan_quota(fake_db, "u1")
    status = await get_quota_status(fake_db, "u1")
    assert status == {"limit": 3, "used": 3, "remaining": 0}


async def test_quota_is_per_user(fake_db):
    for _ in range(3):
        await consume_scan_quota(fake_db, "u1")
    assert await consume_scan_quota(fake_db, "u2") == 2


async def test_refund(fake_db):
    for _ in range(3):
        await consume_scan_quota(fake_db, "u1")
    await refund_scan_quota(fake_db, "u1")
    assert await consume_scan_quota(fake_db, "u1") == 0


def test_sliding_window_limiter():
    limiter = SlidingWindowLimiter(max_requests=2, window_seconds=60)
    limiter.hit("1.2.3.4")
    limiter.hit("1.2.3.4")
    with pytest.raises(RateLimitedError) as exc:
        limiter.hit("1.2.3.4")
    assert exc.value.retry_after >= 1
    limiter.hit("5.6.7.8")  # different IP unaffected


def test_client_ip_ignores_spoofed_forwarded_for():
    from starlette.requests import Request

    from app.api.deps import client_ip

    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", b"6.6.6.6, 203.0.113.9")],
        "client": ("10.0.0.1", 1234),
    }
    assert client_ip(Request(scope)) == "203.0.113.9"
