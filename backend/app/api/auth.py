from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status
from pymongo.errors import DuplicateKeyError

from app.api.deps import CurrentUser, Database, client_ip
from app.core.rate_limit import RateLimitedError, guest_limiter, login_limiter, register_limiter
from app.core.security import create_access_token, create_guest_token, hash_password, verify_password
from app.models.user import GuestTokenResponse, TokenResponse, UserCreate, UserLogin, UserPublic

router = APIRouter(prefix="/api/auth", tags=["auth"])

_REGISTER_FAILED = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail={
        "code": "registration_failed",
        "message": "Registration could not be completed with these details.",
    },
)
_LOGIN_FAILED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail={"code": "invalid_credentials", "message": "Invalid email or password."},
)


def _rate_limit(limiter, request: Request) -> None:
    try:
        limiter.hit(client_ip(request))
    except RateLimitedError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "rate_limited",
                "message": "Too many attempts. Please wait a few minutes and try again.",
            },
            headers={"Retry-After": str(exc.retry_after)},
        ) from None


def _public(user: dict) -> UserPublic:
    return UserPublic(id=str(user["_id"]), email=user["email"], created_at=user["created_at"])


def _token_response(user: dict) -> TokenResponse:
    token, expires_in = create_access_token(str(user["_id"]))
    return TokenResponse(access_token=token, expires_in=expires_in, user=_public(user))


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(body: UserCreate, request: Request, db: Database) -> TokenResponse:
    _rate_limit(register_limiter, request)
    email = body.email.lower()
    # Hash before the uniqueness check so both paths take similar time.
    password_hash = hash_password(body.password)
    user = {"email": email, "password_hash": password_hash, "created_at": datetime.now(UTC)}
    try:
        result = await db.users.insert_one(user)
    except DuplicateKeyError:
        raise _REGISTER_FAILED from None
    user["_id"] = result.inserted_id
    return _token_response(user)


@router.post("/login", response_model=TokenResponse)
async def login(body: UserLogin, request: Request, db: Database) -> TokenResponse:
    _rate_limit(login_limiter, request)
    user = await db.users.find_one({"email": body.email.lower()})
    if not verify_password(body.password, user.get("password_hash") if user else None) or not user:
        raise _LOGIN_FAILED
    return _token_response(user)


@router.post("/guest", response_model=GuestTokenResponse, status_code=status.HTTP_201_CREATED)
async def guest(request: Request) -> GuestTokenResponse:
    """Token for trying ReconLens without an account (limited by GUEST_SCAN_LIMIT per IP)."""
    _rate_limit(guest_limiter, request)
    token, guest_id, expires_in = create_guest_token()
    return GuestTokenResponse(access_token=token, expires_in=expires_in, guest_id=guest_id)


@router.get("/me", response_model=UserPublic)
async def me(user: CurrentUser) -> UserPublic:
    return _public(user)
