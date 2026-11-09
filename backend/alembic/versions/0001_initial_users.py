"""initial_users

Revision ID: 0001
Revises:
Create Date: 2026-08-10 00:00:00.000000

Creates the `users` table with all columns defined by the User ORM model.
This migration is written by hand to be deterministic and database-agnostic
(works with both SQLite for local dev and PostgreSQL for production).

Note on the `role` column:
  - The ORM model uses Enum(UserRole, native_enum=False) which stores the
    value as a plain VARCHAR, not a database-native ENUM type.
  - This makes the migration portable between SQLite (no ENUM support) and
    PostgreSQL without conditional logic.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        # ── Primary key ──────────────────────────────────────────
        sa.Column(
            "id",
            sa.Uuid(),
            nullable=False,
            comment="UUID v4 primary key — matches frontend string UUID convention",
        ),
        # ── Auth ─────────────────────────────────────────────────
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column(
            "hashed_password",
            sa.String(255),
            nullable=False,
            comment="bcrypt hash — plaintext password never stored",
        ),
        # ── Profile ──────────────────────────────────────────────
        sa.Column("avatar", sa.String(512), nullable=True),
        sa.Column(
            "role",
            sa.String(length=20),
            nullable=False,
            server_default="analyst",
            comment="UserRole enum stored as VARCHAR: admin | analyst | viewer",
        ),
        # ── Timestamps ───────────────────────────────────────────
        sa.Column(
            "last_login_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("(CURRENT_TIMESTAMP)"),
            nullable=False,
        ),
        # ── Constraints ───────────────────────────────────────────
        sa.PrimaryKeyConstraint("id", name="pk_users"),
    )

    # Indexes
    op.create_index("ix_users_id", "users", ["id"], unique=False)
    op.create_index("ix_users_email", "users", ["email"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_email", table_name="users")
    op.drop_index("ix_users_id", table_name="users")
    op.drop_table("users")
