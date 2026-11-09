"""add modules_json to scans table

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-09 19:30:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("modules_json", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "modules_json")
