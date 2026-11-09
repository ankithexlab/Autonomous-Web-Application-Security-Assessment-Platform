"""
Alembic migration environment.

Key design choices:
  - DATABASE_URL is read from Settings (same source as the application) so
    there is a single source of truth for the connection string.
  - The async driver prefix (sqlite+aiosqlite, postgresql+asyncpg) is stripped
    here and replaced with the synchronous equivalent because Alembic's migration
    runner does not use asyncio — this is the official SQLAlchemy recommendation.
  - All ORM models are imported via `app.models` so that Base.metadata contains
    every table definition and autogenerate works correctly.
"""

import sys
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# ── Path setup ───────────────────────────────────────────────────
# Ensure the backend/ directory (where pyproject.toml lives) is on sys.path
# so that `import app.*` works when running `alembic` from the backend/ dir.
_backend_dir = Path(__file__).resolve().parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

# ── Import application components ────────────────────────────────
from app.config import get_settings          # noqa: E402
from app.database.base import Base           # noqa: E402
import app.models  # noqa: E402, F401  — registers all models with Base.metadata

# ── Resolve database URL ─────────────────────────────────────────
settings = get_settings()

_ASYNC_TO_SYNC: dict[str, str] = {
    "sqlite+aiosqlite://": "sqlite://",
    "postgresql+asyncpg://": "postgresql://",
    "mysql+aiomysql://": "mysql://",
}

_db_url = settings.DATABASE_URL
for async_prefix, sync_prefix in _ASYNC_TO_SYNC.items():
    if _db_url.startswith(async_prefix):
        _db_url = _db_url.replace(async_prefix, sync_prefix, 1)
        break

# ── Alembic config ───────────────────────────────────────────────
config = context.config
config.set_main_option("sqlalchemy.url", _db_url)

target_metadata = Base.metadata


# ── Migration runners ────────────────────────────────────────────


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode (generate SQL script without a live DB).

    Useful for generating a SQL diff to review before applying.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode (connect to DB and apply migrations).
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,  # NullPool: no connection reuse; safe for migrations
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


# ── Entry point ──────────────────────────────────────────────────

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
