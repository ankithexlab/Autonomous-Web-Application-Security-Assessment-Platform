"""
pytest fixtures for the AWASAP backend test suite.

Strategy:
  - A dedicated PostgreSQL test database (awasap_test) is used for isolation.
  - Each test receives a DB session that automatically truncates all tables
    after the test completes, ensuring full isolation without recreating the
    schema on every test.
  - The FastAPI app's `get_db` dependency is overridden to use the test session
    so that the HTTP test client and assertions share the same transaction.

Database: postgresql+asyncpg (matches production driver)
HTTP client: httpx.AsyncClient with ASGITransport (in-process, no real TCP)
"""

import asyncio
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
import uuid
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import text

import app.models  # noqa: F401 — ensure all ORM models are registered on Base.metadata
from app.database.base import Base
from app.database.session import get_db
from app.main import app

import builtins
import uuid
builtins.uuid = uuid
from app.config import get_settings

# ── Test database ────────────────────────────────────────────────
# Use a file‑based SQLite DB for tests (isolated from production)
# This avoids reliance on an external PostgreSQL server and works for both
# SQLite and PostgreSQL driver branches.
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"


from sqlalchemy.pool import NullPool

@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """
    Create the test database engine once per session.

    Tables are created at the start and dropped at the end.
    Uses NullPool so connections are created per-operation on the active event loop.
    For SQLite, synchronous engine is used for DDL to prevent aiosqlite worker-thread transaction deadlocks.
    """
    if "sqlite" in TEST_DATABASE_URL:
        from sqlalchemy import create_engine
        sync_url = TEST_DATABASE_URL.replace("+aiosqlite", "")
        sync_engine = create_engine(sync_url)
        with sync_engine.connect() as sconn:
            sconn.execute(text("PRAGMA journal_mode=WAL"))
            sconn.execute(text("PRAGMA busy_timeout=30000"))
        Base.metadata.create_all(sync_engine)
        sync_engine.dispose()

    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
        connect_args={"timeout": 30.0} if "sqlite" in TEST_DATABASE_URL else {},
    )
    if "sqlite" not in TEST_DATABASE_URL:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    yield engine

    if "sqlite" in TEST_DATABASE_URL:
        from sqlalchemy import create_engine
        sync_url = TEST_DATABASE_URL.replace("+aiosqlite", "")
        sync_engine = create_engine(sync_url)
        Base.metadata.drop_all(sync_engine)
        sync_engine.dispose()
    else:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(autouse=True)
async def clean_active_scan_registry():
    """Ensure _ACTIVE_SCAN_TASKS is clean before and after every test."""
    from app.services.scan import _ACTIVE_SCAN_TASKS
    for t in list(_ACTIVE_SCAN_TASKS.values()):
        if not t.done():
            t.cancel()
    _ACTIVE_SCAN_TASKS.clear()
    yield
    tasks = [t for t in list(_ACTIVE_SCAN_TASKS.values()) if not t.done()]
    for t in tasks:
        t.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _ACTIVE_SCAN_TASKS.clear()


@pytest_asyncio.fixture()
async def db(test_engine):
    """
    Provide a per-test async session that truncates all tables after each test.

    Uses TRUNCATE ... CASCADE for PostgreSQL which is faster than row-by-row DELETE
    and handles FK constraints automatically.
    """
    session_factory = async_sessionmaker(test_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session

    # ── Cleanup: truncate/delete all tables via clean connection ──────
    async with test_engine.begin() as conn:
        table_names = [table.name for table in reversed(Base.metadata.sorted_tables)]
        if table_names:
            if "sqlite" in str(test_engine.url):
                for table_name in table_names:
                    await conn.execute(text(f"DELETE FROM {table_name}"))
            else:
                truncate_sql = f"TRUNCATE TABLE {', '.join(table_names)} CASCADE"
                await conn.execute(text(truncate_sql))


@pytest_asyncio.fixture()
async def client(db: AsyncSession):
    """
    Provide an httpx AsyncClient wired to the FastAPI test app.

    The `get_db` dependency is overridden so the client and any direct
    repository calls in tests share the same database session.
    """
    async def _override_get_db():
        yield db

    app.dependency_overrides[get_db] = _override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as http_client:
        yield http_client

    app.dependency_overrides.clear()


# ── Helper factories ─────────────────────────────────────────────

@pytest_asyncio.fixture()
async def registered_user(client: AsyncClient) -> dict:
    """
    Register a real user via the API and return the full response payload.

    Use this in tests that need an existing, authenticated user.
    """
    payload = {
        "name": "Test User",
        "email": f"test_{uuid.uuid4().hex}@example.com",
        "password": "TestPass123!",
    }
    response = await client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


@pytest_asyncio.fixture()
async def setup_project_and_target(client: AsyncClient, registered_user: dict):
    token = registered_user["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Create project
    proj_resp = await client.post(
        "/api/v1/projects",
        json={"name": "Acme Web App", "description": "Main web portal", "risk_level": "high"},
        headers=headers,
    )
    assert proj_resp.status_code == 201, proj_resp.text
    project = proj_resp.json()

    # Create target
    target_resp = await client.post(
        f"/api/v1/projects/{project['id']}/targets",
        json={"url": "https://app.acmecorp.com", "type": "web"},
        headers=headers,
    )
    assert target_resp.status_code == 201, target_resp.text
    target = target_resp.json()

    return {
        "user": registered_user,
        "headers": headers,
        "project": project,
        "target": target,
    }
