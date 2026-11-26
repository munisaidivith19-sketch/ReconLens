import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import Response

from app.api.deps import CurrentUser, Database, ScanUser, client_ip
from app.config import get_settings
from app.core.cache import get_cached_scan_id
from app.core.rate_limit import (
    GuestLimitError,
    QuotaExceededError,
    RateLimitedError,
    consume_guest_quota,
    consume_scan_quota,
    get_guest_quota_status,
    get_quota_status,
    refund_guest_quota,
    scan_ip_limiter,
)
from app.core.ssrf_guard import BlockedTargetError, validate_target
from app.db import SCAN_TTL_SECONDS, SHARE_DAYS
from app.models.scan import ScanCreate, ScanDetail, ScanPage, ScanStatus, ScanSummary
from app.services import scan_runner

router = APIRouter(prefix="/api/scans", tags=["scans"])

_NOT_FOUND = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail={"code": "not_found", "message": "Scan not found."},
)


def _summary(doc: dict[str, Any]) -> ScanSummary:
    return ScanSummary(
        id=str(doc["_id"]),
        domain=doc["domain"],
        input=doc.get("input", doc["domain"]),
        status=doc["status"],
        risk_score=doc.get("risk_score"),
        findings_count=len(doc.get("findings") or []),
        created_at=doc["created_at"],
        finished_at=doc.get("finished_at"),
        cached=bool(doc.get("cached_from")),
    )


def _detail(doc: dict[str, Any]) -> ScanDetail:
    s = _summary(doc)
    return ScanDetail(
        **s.model_dump(),
        stages=doc.get("stages", []),
        results=doc.get("results") or {},
        findings=doc.get("findings") or [],
        score_factors=doc.get("score_factors") or [],
        ai_report=doc.get("ai_report"),
        confirmed_authorized=doc["confirmed_authorized"],
        authorized_at=doc["authorized_at"],
        started_at=doc.get("started_at"),
        error=doc.get("error"),
    )


async def _owned_scan(db: Any, scan_id: str, user: dict[str, Any]) -> dict[str, Any]:
    try:
        oid = ObjectId(scan_id)
    except (InvalidId, TypeError):
        raise _NOT_FOUND from None
    doc = await db.scans.find_one({"_id": oid, "user_id": str(user["_id"])})
    if not doc:
        raise _NOT_FOUND  # same response whether it doesn't exist or isn't yours
    return doc


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_scan(body: ScanCreate, request: Request, user: ScanUser, db: Database) -> dict[str, Any]:
    if body.confirmed_authorized is not True:  # also enforced by the schema
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "scope_not_confirmed",
                "message": "Confirm you are authorized to test this target.",
            },
        )
    try:
        target, _ips = await validate_target(body.target)
    except BlockedTargetError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": f"blocked_target.{exc.code}", "message": exc.message},
        ) from None

    user_id = str(user["_id"])
    now = datetime.now(UTC)
    domain = target.host

    # Same user already scanning this domain: return that scan instead of starting another.
    active = await db.scans.find_one(
        {
            "user_id": user_id,
            "domain": domain,
            "status": {"$in": [ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]},
        }
    )
    if active:
        return {"scan": _summary(active).model_dump(mode="json"), "cached": False, "quota_remaining": None}

    # Guests get GUEST_SCAN_LIMIT scans per IP in total, cached results included.
    is_guest = bool(user.get("guest"))
    ip = client_ip(request)
    guest_remaining: int | None = None
    if is_guest:
        try:
            guest_remaining = await consume_guest_quota(db, ip)
        except GuestLimitError as exc:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "guest_limit_reached",
                    "message": (
                        f"You've used your {exc.limit} free scans. Create a free account or sign in "
                        f"to run {get_settings().DAILY_SCAN_LIMIT} scans a day."
                    ),
                },
            ) from None

    base_doc = {
        "user_id": user_id,
        "input": body.target.strip()[:300],
        "domain": domain,
        "confirmed_authorized": True,
        "authorized_at": now,
        "created_at": now,
    }

    # Domain scanned in the last 24h: copy the finished results for this user (no quota used).
    cached_id = await get_cached_scan_id(db, domain)
    if cached_id:
        try:
            cached = await db.scans.find_one(
                {"_id": ObjectId(cached_id), "status": ScanStatus.COMPLETED.value}
            )
        except InvalidId:
            cached = None
        if cached:
            doc = {
                **base_doc,
                "status": ScanStatus.COMPLETED.value,
                "stages": cached.get("stages", []),
                "results": cached.get("results", {}),
                "findings": cached.get("findings", []),
                "risk_score": cached.get("risk_score"),
                "score_factors": cached.get("score_factors", []),
                "ai_report": cached.get("ai_report"),
                "started_at": cached.get("started_at"),
                "finished_at": cached.get("finished_at"),
                "cached_from": str(cached["_id"]),
            }
            res = await db.scans.insert_one(doc)
            doc["_id"] = res.inserted_id
            return {
                "scan": _summary(doc).model_dump(mode="json"),
                "cached": True,
                "quota_remaining": guest_remaining,
            }

    try:
        scan_ip_limiter.hit(ip)
    except RateLimitedError:
        if is_guest:
            await refund_guest_quota(db, ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "quota_exceeded",
                "message": "Too many scans from your network today. Please try again tomorrow.",
            },
        ) from None
    try:
        remaining = guest_remaining if is_guest else await consume_scan_quota(db, user_id)
    except QuotaExceededError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "quota_exceeded",
                "message": f"You've reached today's limit of {exc.limit} scans. The quota resets at 00:00 UTC.",
            },
        ) from None

    doc = {
        **base_doc,
        "status": ScanStatus.QUEUED.value,
        "stages": scan_runner.initial_stages(),
        "results": {},
        "findings": [],
        "risk_score": None,
        "score_factors": [],
        "ai_report": None,
    }
    res = await db.scans.insert_one(doc)
    doc["_id"] = res.inserted_id
    scan_runner.start_scan(db, res.inserted_id)
    return {"scan": _summary(doc).model_dump(mode="json"), "cached": False, "quota_remaining": remaining}


@router.get("", response_model=ScanPage)
async def list_scans(
    user: ScanUser,
    db: Database,
    page: int = Query(1, ge=1, le=1000),
    page_size: int = Query(20, ge=1, le=50),
    domain: str | None = Query(None, max_length=253, pattern=r"^[A-Za-z0-9.-]+$"),
) -> ScanPage:
    flt: dict[str, Any] = {"user_id": str(user["_id"])}
    if domain:
        flt["domain"] = domain.lower()
    total = await db.scans.count_documents(flt)
    projection = {"results": 0, "ai_report": 0, "stages": 0, "score_factors": 0}
    cursor = (
        db.scans.find(flt, projection).sort("created_at", -1).skip((page - 1) * page_size).limit(page_size)
    )
    docs = await cursor.to_list(length=page_size)
    # findings were projected in, so counts stay accurate
    return ScanPage(items=[_summary(d) for d in docs], total=total, page=page, page_size=page_size)


@router.get("/quota")
async def quota(request: Request, user: ScanUser, db: Database) -> dict[str, Any]:
    if user.get("guest"):
        return {**await get_guest_quota_status(db, client_ip(request)), "guest": True}
    return {**await get_quota_status(db, str(user["_id"])), "guest": False}


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, user: ScanUser, db: Database) -> ScanDetail:
    return _detail(await _owned_scan(db, scan_id, user))


@router.get("/{scan_id}/previous")
async def previous_scan(scan_id: str, user: ScanUser, db: Database) -> dict[str, Any]:
    """The user's last completed scan of the same domain before this one, for comparison."""
    doc = await _owned_scan(db, scan_id, user)
    prev = await db.scans.find_one(
        {
            "user_id": str(user["_id"]),
            "domain": doc["domain"],
            "status": ScanStatus.COMPLETED.value,
            "created_at": {"$lt": doc["created_at"]},
        },
        sort=[("created_at", -1)],
    )
    return {"previous": _detail(prev).model_dump(mode="json") if prev else None}


# ------------------------------------------------------------------ read-only share links


def _share_out(share: dict[str, Any] | None) -> dict[str, Any]:
    if not share:
        return {"share": None}
    return {
        "share": {
            "token": share["token"],
            "expires_at": share["expires_at"],
            "created_at": share["created_at"],
        }
    }


@router.get("/{scan_id}/share")
async def get_share(scan_id: str, user: CurrentUser, db: Database) -> dict[str, Any]:
    doc = await _owned_scan(db, scan_id, user)
    share = await db.shares.find_one({"scan_id": str(doc["_id"]), "expires_at": {"$gt": datetime.now(UTC)}})
    return _share_out(share)


@router.post("/{scan_id}/share", status_code=status.HTTP_201_CREATED)
async def create_share(scan_id: str, user: CurrentUser, db: Database) -> dict[str, Any]:
    """Create (or return the existing) read-only link. Registered accounts only."""
    doc = await _owned_scan(db, scan_id, user)
    if doc["status"] != ScanStatus.COMPLETED.value:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "not_completed", "message": "Only completed scans can be shared."},
        )
    now = datetime.now(UTC)
    existing = await db.shares.find_one({"scan_id": str(doc["_id"]), "expires_at": {"$gt": now}})
    if existing:
        return _share_out(existing)
    # A share never outlives the scan it points to.
    created = doc["created_at"] if doc["created_at"].tzinfo else doc["created_at"].replace(tzinfo=UTC)
    expires = min(now + timedelta(days=SHARE_DAYS), created + timedelta(seconds=SCAN_TTL_SECONDS))
    share = {
        "token": secrets.token_urlsafe(24),
        "scan_id": str(doc["_id"]),
        "user_id": str(user["_id"]),
        "created_at": now,
        "expires_at": expires,
    }
    await db.shares.insert_one(share)
    return _share_out(share)


@router.delete("/{scan_id}/share", status_code=status.HTTP_204_NO_CONTENT)
async def delete_share(scan_id: str, user: CurrentUser, db: Database) -> Response:
    doc = await _owned_scan(db, scan_id, user)
    await db.shares.delete_many({"scan_id": str(doc["_id"]), "user_id": str(user["_id"])})
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{scan_id}/export")
async def export_scan(scan_id: str, user: ScanUser, db: Database) -> Response:
    doc = await _owned_scan(db, scan_id, user)
    detail = _detail(doc).model_dump(mode="json")
    payload = {
        "tool": "ReconLens",
        "format_version": 1,
        "exported_at": datetime.now(UTC).isoformat(),
        "disclaimer": (
            "Generated by passive, automated checks against a target the user confirmed they are "
            "authorized to test. Results may be incomplete; verify before acting."
        ),
        **detail,
    }
    safe_domain = re.sub(r"[^a-z0-9.-]", "_", doc["domain"])
    filename = f"reconlens-{safe_domain}-{doc['created_at']:%Y%m%d}.json"
    return Response(
        content=json.dumps(payload, indent=2, ensure_ascii=False),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
