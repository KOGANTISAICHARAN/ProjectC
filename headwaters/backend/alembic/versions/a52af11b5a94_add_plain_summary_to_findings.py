"""add plain_summary to findings

Revision ID: a52af11b5a94
Revises: 75398574be98
Create Date: 2026-09-08 03:13:25.327803
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "a52af11b5a94"
down_revision: str | None = "75398574be98"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the plain-language summary alongside the technical detail.

    Nullable, because every existing finding predates it and backfilling
    generated prose into stored evidence would rewrite the record of what an
    analysis actually said.
    """
    op.add_column("findings", sa.Column("plain_summary", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "plain_summary")
