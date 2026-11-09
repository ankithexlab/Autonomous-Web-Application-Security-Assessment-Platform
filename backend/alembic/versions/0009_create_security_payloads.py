"""create security_payloads table

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-09 20:50:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_payloads",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("payload", sa.Text(), nullable=False),
        sa.Column("context", sa.Text(), nullable=False),
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=32), nullable=False),
        sa.Column("example_usage", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_security_payloads")),
    )
    op.create_index(op.f("ix_security_payloads_id"), "security_payloads", ["id"], unique=False)
    op.create_index(op.f("ix_security_payloads_type"), "security_payloads", ["type"], unique=False)
    op.create_index(op.f("ix_security_payloads_severity"), "security_payloads", ["severity"], unique=False)
    op.create_index("ix_security_payloads_type_severity", "security_payloads", ["type", "severity"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_security_payloads_type_severity", table_name="security_payloads")
    op.drop_index(op.f("ix_security_payloads_severity"), table_name="security_payloads")
    op.drop_index(op.f("ix_security_payloads_type"), table_name="security_payloads")
    op.drop_index(op.f("ix_security_payloads_id"), table_name="security_payloads")
    op.drop_table("security_payloads")
