"""create_findings

Revision ID: 0003
Revises: 0002
Create Date: 2026-08-10 13:00:00.000000

Creates the `findings` table for vulnerability findings.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers
revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("target_id", sa.Uuid(), nullable=False),
        sa.Column("project_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(50), server_default="medium", nullable=False),
        sa.Column("status", sa.String(50), server_default="open", nullable=False),
        sa.Column("category", sa.String(100), server_default="Web Security", nullable=False),
        sa.Column("owasp_category", sa.String(100), nullable=True),
        sa.Column("cwe_id", sa.String(50), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("affected_url", sa.String(512), nullable=True),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("proof_of_concept", sa.Text(), nullable=True),
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
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
    )

    op.create_index("ix_findings_id", "findings", ["id"], unique=False)
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index("ix_findings_target_id", "findings", ["target_id"], unique=False)
    op.create_index("ix_findings_project_id", "findings", ["project_id"], unique=False)
    op.create_index("ix_findings_user_id", "findings", ["user_id"], unique=False)
    op.create_index("ix_findings_severity", "findings", ["severity"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_severity", table_name="findings")
    op.drop_index("ix_findings_user_id", table_name="findings")
    op.drop_index("ix_findings_project_id", table_name="findings")
    op.drop_index("ix_findings_target_id", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_index("ix_findings_id", table_name="findings")
    op.drop_table("findings")
