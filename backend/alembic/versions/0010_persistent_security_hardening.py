"""create security hardening tables (revoked_tokens, user_revocations, rate_limit_hits)

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-18 15:45:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. revoked_tokens table
    op.create_table(
        "revoked_tokens",
        sa.Column("jti", sa.String(length=64), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("jti"),
    )
    op.create_index(op.f("ix_revoked_tokens_user_id"), "revoked_tokens", ["user_id"], unique=False)
    op.create_index(op.f("ix_revoked_tokens_expires_at"), "revoked_tokens", ["expires_at"], unique=False)

    # 2. user_revocations table
    op.create_table(
        "user_revocations",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )

    # 3. rate_limit_hits table
    op.create_table(
        "rate_limit_hits",
        sa.Column("id", sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column("bucket_key", sa.String(length=255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_rate_limit_hits_bucket_key"), "rate_limit_hits", ["bucket_key"], unique=False)
    op.create_index(op.f("ix_rate_limit_hits_created_at"), "rate_limit_hits", ["created_at"], unique=False)
    op.create_index("ix_rate_limit_hits_key_time", "rate_limit_hits", ["bucket_key", "created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_rate_limit_hits_key_time", table_name="rate_limit_hits")
    op.drop_index(op.f("ix_rate_limit_hits_created_at"), table_name="rate_limit_hits")
    op.drop_index(op.f("ix_rate_limit_hits_bucket_key"), table_name="rate_limit_hits")
    op.drop_table("rate_limit_hits")

    op.drop_table("user_revocations")

    op.drop_index(op.f("ix_revoked_tokens_expires_at"), table_name="revoked_tokens")
    op.drop_index(op.f("ix_revoked_tokens_user_id"), table_name="revoked_tokens")
    op.drop_table("revoked_tokens")
