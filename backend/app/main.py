"""
AWASAP FastAPI application entry point.

Usage:
    # from backend/ directory
    uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

Architecture notes:
  - CORS origins are loaded from Settings (config.py) — never hardcoded here.
  - Exception handlers are registered via register_exception_handlers() from
    core/exceptions.py so error shapes match the frontend's ApiError interface.
  - The lifespan context manager is the modern FastAPI replacement for
    on_event("startup") / on_event("shutdown").
  - All routers are mounted under the API_V1_PREFIX (/api/v1) defined in Settings.
"""

import logging
import uuid
from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.router import api_v1_router
from app.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, set_correlation_id
from app.database.session import get_db

settings = get_settings()
configure_logging()
logger = logging.getLogger("awsap.security")


# ── Lifespan ─────────────────────────────────────────────────────


import sys

from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.core.config_validation import validate_production_configuration
from app.core.token_cleanup import ExpiredTokenCleanupWorker

cleanup_worker = ExpiredTokenCleanupWorker()


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.
    """
    # ── startup ──────────────────────────────────────────────────
    if not settings.DEBUG and "pytest" not in sys.modules:
        validate_production_configuration(settings)

    if "pytest" not in sys.modules:
        from app.services.scan import recover_interrupted_scans
        try:
            await recover_interrupted_scans()
        except Exception as rec_err:
            logger.error("Startup scan recovery encountered error: %s", rec_err)

        from app.database.session import async_session_factory
        from app.services.seed import seed_all_existing_users
        try:
            async with async_session_factory() as seed_session:
                seeded_count = await seed_all_existing_users(seed_session)
                logger.info("Startup seeder verified default targets for %d user(s)", seeded_count)
        except Exception as seed_err:
            logger.error("Startup default target seeding error: %s", seed_err)

    application.state.cleanup_worker = cleanup_worker
    cleanup_worker.start()
    yield
    # ── shutdown ─────────────────────────────────────────────────
    from app.services.scan import cancel_all_active_scans
    await cancel_all_active_scans()
    if getattr(application.state, "cleanup_worker", None):
        await cleanup_worker.stop()


# ── Application factory ──────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Autonomous Web Application Security Assessment Platform — REST API. "
        "Provides authentication, project management, target tracking, "
        "vulnerability scanning, findings management and report generation."
    ),
    contact={
        "name": "Ankit Kumar",
        "email": "ankitkumarsahani07@gmail.com",
    },
    license_info={"name": "MIT"},
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ── Request Correlation ID Middleware ─────────────────────────────


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next) -> Response:
    """Propagate correlation ID across async execution and inject in response headers."""
    incoming_id = request.headers.get("X-Request-ID") or request.headers.get("X-Correlation-ID")
    correlation_id = incoming_id.strip() if incoming_id else uuid.uuid4().hex
    set_correlation_id(correlation_id)
    request.state.correlation_id = correlation_id

    response: Response = await call_next(request)
    response.headers["X-Request-ID"] = correlation_id
    return response


# ── Security Response Headers Middleware ──────────────────────────


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    """Inject hardened application security headers on all responses."""
    response: Response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

    # Prevent client/intermediate caching of sensitive authenticated API responses
    if request.url.path.startswith(settings.API_V1_PREFIX):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    return response


# ── CORS Middleware ───────────────────────────────────────────────

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "User-Agent",
        "X-Requested-With",
        "X-Request-ID",
        "X-Correlation-ID",
    ],
    expose_headers=["X-Request-ID"],
)

# ── Trusted Host Middleware ───────────────────────────────────────

if settings.ALLOWED_HOSTS and settings.ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)


# ── Exception handlers ───────────────────────────────────────────

register_exception_handlers(app)

# ── Routers ──────────────────────────────────────────────────────

app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)


# ── Health & Readiness Probes ────────────────────────────────────


@app.get("/health", tags=["Health"], summary="Liveness probe")
@app.get("/health/live", tags=["Health"], summary="Liveness probe alias")
async def health() -> dict[str, str]:
    """
    Simple liveness check used by load balancers and container orchestrators.
    Returns 200 OK with `{"status": "ok"}` when the process is running.
    """
    return {"status": "ok", "version": settings.APP_VERSION}


@app.get("/readiness", tags=["Health"], summary="Readiness probe")
@app.get("/health/ready", tags=["Health"], summary="Readiness probe alias")
async def readiness(db: AsyncSession = Depends(get_db)) -> Response:
    """
    Readiness probe that safely verifies database connectivity.

    Returns:
      200 OK: when database responds and application is ready for traffic.
      503 Service Unavailable: when database connectivity fails.

    Guarantees zero leakage of internal database URLs, credentials, or stack traces.
    """
    import asyncio
    from sqlalchemy import text

    is_db_ready = False
    try:
        await asyncio.wait_for(db.execute(text("SELECT 1")), timeout=2.0)
        is_db_ready = True
    except Exception as err:
        logger.error("Readiness probe check failed: %s", type(err).__name__)
        is_db_ready = False

    if is_db_ready:
        return JSONResponse(
            status_code=200,
            content={"status": "ready", "components": {"database": "connected"}},
        )
    return JSONResponse(
        status_code=503,
        content={"status": "unhealthy", "components": {"database": "disconnected"}},
    )
