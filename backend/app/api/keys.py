"""Personal API keys: run scans from scripts and CI with `Authorization: Bearer rl_...`.

Keys are shown once at creation; only their SHA-256 hash is stored. Keys can use the scan
endpoints (same quotas as the account) but cannot create, list or revoke keys.
"""

from datetime import UTC, datetime
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.api.deps import Database, SessionUser
from app.core.security import generate_api_key

router = APIRouter(prefix="/api/keys", tags=["api-keys"])

MAX_KEYS = 5
_NOT_FOUND = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND, detail={"code": "not_found", "message": "API key not found."}
)


class KeyCreate(BaseModel):
    name: str = Field(min_length=1, max_length=60, pattern=r"^[\w .\-]+$")


def _out(doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": str(doc["_id"]),
        "name": doc["name"],
        "prefix": doc["prefix"],
        "created_at": doc["created_at"],
        "last_used_at": doc.get("last_used_at"),
    }


@router.get("")
async def list_keys(user: SessionUser, db: Database) -> dict[str, Any]:
    docs = (
        await db.api_keys.find({"user_id": str(user["_id"])}).sort("created_at", -1).to_list(length=MAX_KEYS)
    )
    return {"items": [_out(d) for d in docs], "max": MAX_KEYS}


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_key(body: KeyCreate, user: SessionUser, db: Database) -> dict[str, Any]:
    if await db.api_keys.count_documents({"user_id": str(user["_id"])}) >= MAX_KEYS:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": "too_many_keys",
                "message": f"You can have at most {MAX_KEYS} API keys. Revoke one first.",
            },
        )
    key, key_hash, prefix = generate_api_key()
    doc = {
        "user_id": str(user["_id"]),
        "name": body.name.strip(),
        "hash": key_hash,
        "prefix": prefix,
        "created_at": datetime.now(UTC),
        "last_used_at": None,
    }
    res = await db.api_keys.insert_one(doc)
    doc["_id"] = res.inserted_id
    return {**_out(doc), "key": key}  # the only time the full key is returned


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(key_id: str, user: SessionUser, db: Database) -> Response:
    try:
        oid = ObjectId(key_id)
    except (InvalidId, TypeError):
        raise _NOT_FOUND from None
    res = await db.api_keys.delete_many({"_id": oid, "user_id": str(user["_id"])})
    if not res.deleted_count:
        raise _NOT_FOUND
    return Response(status_code=status.HTTP_204_NO_CONTENT)
