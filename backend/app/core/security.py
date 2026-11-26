"""Password hashing (Argon2 via pwdlib) and JWT access tokens (PyJWT)."""

import secrets
from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.config import get_settings

ALGORITHM = "HS256"
ISSUER = "reconlens"
AUDIENCE = "reconlens-api"

GUEST_PREFIX = "guest:"
GUEST_TOKEN_SECONDS = 7 * 24 * 3600

_password_hash = PasswordHash((Argon2Hasher(),))
# Used to keep login timing constant when the email does not exist.
_DUMMY_HASH = _password_hash.hash("reconlens-timing-equalizer-password")


class InvalidTokenError(Exception):
    pass


def hash_password(password: str) -> str:
    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        _password_hash.verify(password, _DUMMY_HASH)
        return False
    try:
        return _password_hash.verify(password, password_hash)
    except Exception:  # noqa: BLE001 - malformed hash counts as a failed login
        return False


def create_guest_token() -> tuple[str, str, int]:
    """Token for a visitor without an account. Returns (token, guest_id, expires_in)."""
    guest_id = GUEST_PREFIX + secrets.token_hex(16)
    token, expires_in = create_access_token(guest_id, expires_in=GUEST_TOKEN_SECONDS)
    return token, guest_id, expires_in


def is_guest_id(subject: str) -> bool:
    rest = subject.removeprefix(GUEST_PREFIX)
    return subject.startswith(GUEST_PREFIX) and len(rest) == 32 and all(c in "0123456789abcdef" for c in rest)


def create_access_token(user_id: str, expires_in: int | None = None) -> tuple[str, int]:
    settings = get_settings()
    now = datetime.now(UTC)
    if expires_in is None:
        expires_in = settings.JWT_EXPIRE_MINUTES * 60
    payload = {
        "sub": user_id,
        "iat": now,
        "nbf": now,
        "exp": now + timedelta(seconds=expires_in),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "type": "access",
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM), expires_in


def decode_access_token(token: str) -> str:
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
            options={"require": ["exp", "iat", "sub", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError("Invalid or expired token") from exc
    if payload.get("type") != "access" or not isinstance(payload.get("sub"), str):
        raise InvalidTokenError("Invalid token")
    return payload["sub"]
