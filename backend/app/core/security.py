"""Password hashing (Argon2 via pwdlib) and JWT access tokens (PyJWT)."""

from datetime import UTC, datetime, timedelta

import jwt
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from app.config import get_settings

ALGORITHM = "HS256"
ISSUER = "reconlens"
AUDIENCE = "reconlens-api"

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


def create_access_token(user_id: str) -> tuple[str, int]:
    settings = get_settings()
    now = datetime.now(UTC)
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
