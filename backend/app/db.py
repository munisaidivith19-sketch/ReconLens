"""Async MongoDB access (PyMongo async API) and index creation."""

import logging
from typing import Any

from pymongo import ASCENDING, DESCENDING, AsyncMongoClient

from app.config import get_settings

log = logging.getLogger(__name__)

SCAN_TTL_SECONDS = 30 * 24 * 3600
CACHE_TTL_SECONDS = 24 * 3600
USAGE_TTL_SECONDS = 2 * 24 * 3600
GUEST_USAGE_TTL_SECONDS = 30 * 24 * 3600
BATCH_TTL_SECONDS = 30 * 24 * 3600  # batches expire with their scans
TRIAGE_TTL_SECONDS = 365 * 24 * 3600  # triage decisions kept a year after the last change
SHARE_DAYS = 7  # read-only share links expire after a week (or with the scan, if sooner)

_client: AsyncMongoClient | None = None
_db: Any = None


async def connect() -> None:
    global _client, _db
    settings = get_settings()
    _client = AsyncMongoClient(
        settings.MONGODB_URI,
        serverSelectionTimeoutMS=10_000,
        connectTimeoutMS=10_000,
        maxPoolSize=10,
        tz_aware=True,
        appname="reconlens",
    )
    _db = _client[settings.MONGODB_DB]
    await _client.admin.command("ping")
    await create_indexes(_db)
    log.info("Connected to MongoDB")


async def close() -> None:
    global _client, _db
    if _client is not None:
        await _client.close()
    _client = None
    _db = None


def get_db() -> Any:
    if _db is None:
        raise RuntimeError("Database is not connected")
    return _db


def set_db(db: Any) -> None:
    """Used by tests to inject an in-memory database."""
    global _db
    _db = db


async def create_indexes(db: Any) -> None:
    await db.users.create_index([("email", ASCENDING)], unique=True)

    await db.scans.create_index([("user_id", ASCENDING), ("created_at", DESCENDING)])
    await db.scans.create_index([("status", ASCENDING)])
    await db.scans.create_index([("created_at", ASCENDING)], expireAfterSeconds=SCAN_TTL_SECONDS)

    await db.scan_cache.create_index([("domain", ASCENDING)], unique=True)
    await db.scan_cache.create_index([("created_at", ASCENDING)], expireAfterSeconds=CACHE_TTL_SECONDS)

    await db.api_cache.create_index([("key", ASCENDING)], unique=True)
    await db.api_cache.create_index([("created_at", ASCENDING)], expireAfterSeconds=CACHE_TTL_SECONDS)

    await db.usage.create_index([("user_id", ASCENDING), ("date", ASCENDING)], unique=True)
    await db.usage.create_index([("created_at", ASCENDING)], expireAfterSeconds=USAGE_TTL_SECONDS)

    await db.guest_usage.create_index([("ip", ASCENDING)], unique=True)
    await db.guest_usage.create_index([("created_at", ASCENDING)], expireAfterSeconds=GUEST_USAGE_TTL_SECONDS)

    await db.shares.create_index([("token", ASCENDING)], unique=True)
    await db.shares.create_index([("scan_id", ASCENDING)])
    await db.shares.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)

    await db.batches.create_index([("batch_id", ASCENDING)], unique=True)
    await db.batches.create_index([("created_at", ASCENDING)], expireAfterSeconds=BATCH_TTL_SECONDS)

    await db.triage.create_index(
        [("user_id", ASCENDING), ("domain", ASCENDING), ("finding_id", ASCENDING)], unique=True
    )
    await db.triage.create_index([("updated_at", ASCENDING)], expireAfterSeconds=TRIAGE_TTL_SECONDS)

    await db.api_keys.create_index([("hash", ASCENDING)], unique=True)
    await db.api_keys.create_index([("user_id", ASCENDING)])
