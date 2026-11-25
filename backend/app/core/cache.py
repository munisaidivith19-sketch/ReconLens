"""24-hour caches stored in MongoDB (TTL indexes expire them)."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from app.db import CACHE_TTL_SECONDS

log = logging.getLogger(__name__)


def _fresh_cutoff() -> datetime:
    # TTL monitors run about once a minute, so also check the age on read.
    return datetime.now(UTC) - timedelta(seconds=CACHE_TTL_SECONDS)


async def get_cached_scan_id(db: Any, domain: str) -> str | None:
    doc = await db.scan_cache.find_one({"domain": domain, "created_at": {"$gte": _fresh_cutoff()}})
    return doc["scan_id"] if doc else None


async def set_cached_scan(db: Any, domain: str, scan_id: str) -> None:
    await db.scan_cache.update_one(
        {"domain": domain},
        {"$set": {"scan_id": scan_id, "created_at": datetime.now(UTC)}},
        upsert=True,
    )


async def api_cache_get(db: Any, key: str) -> Any | None:
    try:
        doc = await db.api_cache.find_one({"key": key, "created_at": {"$gte": _fresh_cutoff()}})
    except Exception:  # noqa: BLE001 - cache failures must never break a scan
        log.warning("api cache read failed")
        return None
    return doc["value"] if doc else None


async def api_cache_set(db: Any, key: str, value: Any) -> None:
    try:
        await db.api_cache.update_one(
            {"key": key},
            {"$set": {"value": value, "created_at": datetime.now(UTC)}},
            upsert=True,
        )
    except Exception:  # noqa: BLE001
        log.warning("api cache write failed")
