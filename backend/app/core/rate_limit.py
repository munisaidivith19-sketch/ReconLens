"""Abuse controls: per-user daily scan quota (MongoDB) and per-IP auth limits (in memory).

The service runs as a single process on Render, so an in-memory sliding window is
sufficient for auth endpoints.
"""

import asyncio
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from typing import Any

from pymongo import ReturnDocument

from app.config import get_settings


class QuotaExceededError(Exception):
    def __init__(self, limit: int):
        super().__init__(f"Daily scan limit of {limit} reached")
        self.limit = limit


class RateLimitedError(Exception):
    def __init__(self, retry_after: int):
        super().__init__("Too many requests")
        self.retry_after = retry_after


def _today() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%d")


async def consume_scan_quota(db: Any, user_id: str) -> int:
    """Atomically count one scan for today; raise QuotaExceededError if over the limit.

    Returns the number of scans remaining today.
    """
    limit = get_settings().DAILY_SCAN_LIMIT
    date = _today()
    doc = await db.usage.find_one_and_update(
        {"user_id": user_id, "date": date},
        {"$inc": {"scan_count": 1}, "$setOnInsert": {"created_at": datetime.now(UTC)}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    count = int(doc.get("scan_count", 1))
    if count > limit:
        await db.usage.update_one({"user_id": user_id, "date": date}, {"$inc": {"scan_count": -1}})
        raise QuotaExceededError(limit)
    return limit - count


async def refund_scan_quota(db: Any, user_id: str) -> None:
    await db.usage.update_one(
        {"user_id": user_id, "date": _today(), "scan_count": {"$gt": 0}},
        {"$inc": {"scan_count": -1}},
    )


async def get_quota_status(db: Any, user_id: str) -> dict[str, int]:
    limit = get_settings().DAILY_SCAN_LIMIT
    doc = await db.usage.find_one({"user_id": user_id, "date": _today()})
    used = int(doc.get("scan_count", 0)) if doc else 0
    return {"limit": limit, "used": used, "remaining": max(0, limit - used)}


class SlidingWindowLimiter:
    """Simple per-key sliding-window limiter."""

    def __init__(self, max_requests: int, window_seconds: int, max_keys: int = 50_000):
        self.max_requests = max_requests
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str) -> None:
        now = time.monotonic()
        q = self._hits[key]
        while q and now - q[0] > self.window:
            q.popleft()
        if len(q) >= self.max_requests:
            raise RateLimitedError(retry_after=max(1, int(self.window - (now - q[0]))))
        q.append(now)
        if len(self._hits) > self.max_keys:
            self._prune(now)

    def _prune(self, now: float) -> None:
        for k in [k for k, q in self._hits.items() if not q or now - q[-1] > self.window]:
            del self._hits[k]

    def reset(self) -> None:
        self._hits.clear()


# 10 login attempts and 5 registrations per IP per 15 minutes.
login_limiter = SlidingWindowLimiter(max_requests=10, window_seconds=15 * 60)
register_limiter = SlidingWindowLimiter(max_requests=5, window_seconds=15 * 60)
# New (non-cached) scans per IP per 24 hours, so farming accounts can't multiply the per-user quota.
scan_ip_limiter = SlidingWindowLimiter(max_requests=30, window_seconds=24 * 3600)


class AsyncRateLimiter:
    """At most ``max_calls`` per ``period`` seconds for an outbound API (process-wide).

    ``acquire(max_wait)`` waits for a free slot up to ``max_wait`` seconds and returns
    False instead of waiting longer, so callers can degrade gracefully.
    """

    def __init__(self, max_calls: int, period: float):
        self.max_calls = max_calls
        self.period = period
        self._calls: deque[float] = deque()

    async def acquire(self, max_wait: float = 0.0) -> bool:
        deadline = time.monotonic() + max_wait
        while True:
            # No awaits in this block, so it is atomic within the event loop (no lock needed).
            now = time.monotonic()
            while self._calls and now - self._calls[0] >= self.period:
                self._calls.popleft()
            if len(self._calls) < self.max_calls:
                self._calls.append(now)
                return True
            wait = self.period - (now - self._calls[0])
            if time.monotonic() + wait > deadline:
                return False
            await asyncio.sleep(min(wait, max(0.0, deadline - time.monotonic())) + 0.01)

    def reset(self) -> None:
        self._calls.clear()
