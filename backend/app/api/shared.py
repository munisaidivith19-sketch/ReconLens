"""Public, read-only access to a scan through a share link created by its owner."""

import re
from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, HTTPException, Path, status

from app.api.deps import Database
from app.api.scans import _detail
from app.models.scan import ScanStatus

router = APIRouter(prefix="/api/shared", tags=["shared"])

_GONE = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail={"code": "share_not_found", "message": "This link is invalid or has expired."},
)
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{20,64}$")


@router.get("/{token}")
async def get_shared(db: Database, token: str = Path(max_length=64)) -> dict[str, Any]:
    if not TOKEN_RE.fullmatch(token):
        raise _GONE
    share = await db.shares.find_one({"token": token, "expires_at": {"$gt": datetime.now(UTC)}})
    if not share:
        raise _GONE  # Mongo's TTL monitor only runs every minute, so check expiry here too
    try:
        oid = ObjectId(share["scan_id"])
    except (InvalidId, TypeError):
        raise _GONE from None
    doc = await db.scans.find_one({"_id": oid, "user_id": share["user_id"]})
    if not doc or doc["status"] != ScanStatus.COMPLETED.value:
        raise _GONE
    detail = _detail(doc).model_dump(mode="json")
    detail.pop("input", None)
    return {"scan": detail, "expires_at": share["expires_at"]}
