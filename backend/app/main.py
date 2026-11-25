"""FastAPI application: routers, middleware, startup/shutdown."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app import db
from app.api import auth, health, scans
from app.config import get_settings
from app.services import scan_runner

MAX_BODY_BYTES = 16 * 1024

log = logging.getLogger("reconlens")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=settings.LOG_LEVEL.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # httpx logs full URLs at INFO; keep them out of the logs.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    await db.connect()
    interrupted = await scan_runner.mark_interrupted(db.get_db())
    if interrupted:
        log.info("Marked %d leftover scans as interrupted", interrupted)
    yield
    await db.close()


class BodySizeLimitMiddleware:
    """Reject request bodies larger than MAX_BODY_BYTES (checks header and streamed size)."""

    def __init__(self, app: ASGIApp, max_bytes: int = MAX_BODY_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    too_big = int(value) > self.max_bytes
                except ValueError:
                    too_big = True
                if too_big:
                    await _too_large(scope, receive, send)
                    return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await _too_large(scope, receive, send)


class _BodyTooLarge(Exception):
    pass


async def _too_large(scope: Scope, receive: Receive, send: Send) -> None:
    response = JSONResponse(
        {"detail": {"code": "body_too_large", "message": "Request body is too large."}},
        status_code=413,
    )
    await response(scope, receive, send)


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-site",
    "Cache-Control": "no-store",
}


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ReconLens API",
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        if "server" in response.headers:
            del response.headers["server"]
        return response

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
        max_age=600,
    )
    app.add_middleware(BodySizeLimitMiddleware)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException):
        detail = exc.detail
        if not isinstance(detail, dict):
            detail = {"code": "error", "message": str(detail)}
        return JSONResponse({"detail": detail}, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError):
        errors = [
            {"field": ".".join(str(p) for p in e.get("loc", [])[1:]), "message": e.get("msg", "")}
            for e in exc.errors()
        ]
        return JSONResponse(
            {
                "detail": {
                    "code": "validation_error",
                    "message": "Some fields are invalid.",
                    "errors": errors,
                }
            },
            status_code=422,
        )

    @app.exception_handler(Exception)
    async def unhandled_error(request: Request, exc: Exception):
        log.error("Unhandled error on %s %s: %s", request.method, request.url.path, type(exc).__name__)
        return JSONResponse(
            {"detail": {"code": "internal_error", "message": "Something went wrong on our side."}},
            status_code=500,
        )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(scans.router)
    return app


app = create_app()
