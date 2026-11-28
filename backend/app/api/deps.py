from datetime import UTC, datetime
from typing import Annotated, Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings
from app.core.security import (
    InvalidTokenError,
    decode_access_token,
    hash_api_key,
    is_guest_id,
    looks_like_api_key,
)
from app.db import get_db

_bearer = HTTPBearer(auto_error=False)

_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"code": "session_expired", "message": "Your session has expired. Please sign in again."},
    headers={"WWW-Authenticate": "Bearer"},
)


def get_database() -> Any:
    return get_db()


Database = Annotated[Any, Depends(get_database)]


_KEY_NOT_ALLOWED = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail={"code": "api_key_not_allowed", "message": "Sign in with your password to manage API keys."},
)
_BAD_KEY = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"code": "invalid_api_key", "message": "This API key is invalid or has been revoked."},
    headers={"WWW-Authenticate": "Bearer"},
)


async def _resolve_api_key(db: Any, key: str) -> dict[str, Any]:
    record = await db.api_keys.find_one({"hash": hash_api_key(key)})
    if not record:
        raise _BAD_KEY
    try:
        oid = ObjectId(record["user_id"])
    except (InvalidId, TypeError):
        raise _BAD_KEY from None
    user = await db.users.find_one({"_id": oid}, {"password_hash": 0})
    if not user:
        raise _BAD_KEY
    await db.api_keys.update_one({"_id": record["_id"]}, {"$set": {"last_used_at": datetime.now(UTC)}})
    return {**user, "api_key_id": str(record["_id"])}


async def _resolve(
    db: Any,
    credentials: HTTPAuthorizationCredentials | None,
    allow_guest: bool,
    allow_api_key: bool = True,
) -> dict[str, Any]:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise _UNAUTHORIZED
    if looks_like_api_key(credentials.credentials):
        if not allow_api_key:
            raise _KEY_NOT_ALLOWED
        return await _resolve_api_key(db, credentials.credentials)
    try:
        subject = decode_access_token(credentials.credentials)
    except InvalidTokenError:
        raise _UNAUTHORIZED from None
    if is_guest_id(subject):
        if not allow_guest:
            raise _UNAUTHORIZED
        return {"_id": subject, "guest": True}
    try:
        oid = ObjectId(subject)
    except (InvalidId, TypeError):
        raise _UNAUTHORIZED from None
    user = await db.users.find_one({"_id": oid}, {"password_hash": 0})
    if not user:
        raise _UNAUTHORIZED
    return user


async def get_current_user(
    db: Database,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict[str, Any]:
    """A signed-in account. Guest tokens are rejected."""
    return await _resolve(db, credentials, allow_guest=False)


async def get_scan_user(
    db: Database,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict[str, Any]:
    """A signed-in account or a guest (``{"_id": "guest:...", "guest": True}``)."""
    return await _resolve(db, credentials, allow_guest=True)


async def get_session_user(
    db: Database,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> dict[str, Any]:
    """A signed-in account using a browser session. API keys can't manage API keys."""
    return await _resolve(db, credentials, allow_guest=False, allow_api_key=False)


CurrentUser = Annotated[dict[str, Any], Depends(get_current_user)]
SessionUser = Annotated[dict[str, Any], Depends(get_session_user)]
ScanUser = Annotated[dict[str, Any], Depends(get_scan_user)]


def client_ip(request: Request) -> str:
    """Client IP for rate limiting.

    Clients can prepend fake entries to X-Forwarded-For, so we count TRUSTED_PROXY_HOPS
    entries from the right (the ones appended by our own proxies) instead of taking the
    leftmost value.
    """
    hops = get_settings().TRUSTED_PROXY_HOPS
    fwd = request.headers.get("x-forwarded-for")
    if fwd and hops > 0:
        parts = [p.strip() for p in fwd.split(",") if p.strip()]
        if parts:
            return parts[max(0, len(parts) - hops)][:64]
    return request.client.host if request.client else "unknown"
