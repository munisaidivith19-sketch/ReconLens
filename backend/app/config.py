"""Application settings, loaded only from environment variables (or a local .env file)."""

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "reconlens"

    JWT_SECRET: str = Field(min_length=32)
    JWT_EXPIRE_MINUTES: int = Field(default=60, ge=5, le=60 * 24)

    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "openai/gpt-oss-120b"
    VT_API_KEY: str = ""
    NVD_API_KEY: str = ""
    ABUSECH_AUTH_KEY: str = ""  # free abuse.ch account key for URLhaus (optional)

    FRONTEND_ORIGIN: str = "http://localhost:5173"
    DAILY_SCAN_LIMIT: int = Field(default=10, ge=1, le=1000)
    # Scans a visitor can run without an account (per IP address, over GUEST_USAGE_TTL in db.py).
    GUEST_SCAN_LIMIT: int = Field(default=3, ge=0, le=100)

    MAX_CONCURRENT_SCANS: int = Field(default=2, ge=1, le=4)
    LOG_LEVEL: str = "INFO"
    # Number of reverse proxies in front of the app that append to X-Forwarded-For.
    TRUSTED_PROXY_HOPS: int = Field(default=1, ge=0, le=5)

    @field_validator("FRONTEND_ORIGIN")
    @classmethod
    def _strip_origin(cls, v: str) -> str:
        return v.strip().rstrip("/")

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip().rstrip("/") for o in self.FRONTEND_ORIGIN.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
