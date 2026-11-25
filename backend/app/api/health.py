from fastapi import APIRouter

from app.db import get_db

router = APIRouter(tags=["health"])


@router.get("/api/health")
async def health() -> dict[str, str]:
    db_state = "ok"
    try:
        await get_db().command("ping")
    except Exception:  # noqa: BLE001 - never leak connection details
        db_state = "unavailable"
    return {"status": "ok", "database": db_state, "service": "reconlens"}
