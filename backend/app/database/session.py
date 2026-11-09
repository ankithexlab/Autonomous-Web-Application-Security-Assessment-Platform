"""
Async database engine and session factory.

Provides:
    - AsyncEngine configured from settings
    - async_sessionmaker for creating request-scoped sessions
    - get_db() async generator for FastAPI dependency injection
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings

settings = get_settings()

# ── Engine ───────────────────────────────────────────────────────
# SQLite does not support pool_size / max_overflow, so we conditionally
# pass those arguments only for non-SQLite databases.

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")

_engine_kwargs: dict = {
    "echo": settings.DEBUG,
}
if not _is_sqlite:
    _engine_kwargs.update(
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_recycle=settings.DB_POOL_RECYCLE,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_pre_ping=True,
    )
    if "postgresql" in settings.DATABASE_URL:
        _engine_kwargs["connect_args"] = {
            "timeout": settings.DB_CONNECT_TIMEOUT,
            "command_timeout": settings.DB_COMMAND_TIMEOUT,
            "server_settings": {"application_name": settings.APP_NAME},
        }
else:
    _engine_kwargs["connect_args"] = {
        "timeout": settings.DB_CONNECT_TIMEOUT,
    }

try:
    engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs)
except ModuleNotFoundError as e:
    # If asyncpg is missing and the DATABASE_URL expects PostgreSQL, fall back to SQLite for testing/development
    if "asyncpg" in str(e):
        fallback_url = "sqlite+aiosqlite:///./awsap.db"
        engine = create_async_engine(fallback_url, **{k: v for k, v in _engine_kwargs.items() if k != "connect_args"})
    else:
        raise

# ── Session Factory ──────────────────────────────────────────────

async_session_factory = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Dependency ───────────────────────────────────────────────────


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a request-scoped async DB session.

    Usage:
        @router.get("/items")
        async def list_items(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
