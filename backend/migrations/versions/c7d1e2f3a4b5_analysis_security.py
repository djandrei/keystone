"""analysis.security — injection report

Revision ID: c7d1e2f3a4b5
Revises: b2f1a9c4d7e3
Create Date: 2026-08-27

Persist the per-analysis prompt-injection signal (SEC.4) so the UI can warn a
reviewer and history carries the flag.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "c7d1e2f3a4b5"
down_revision = "b2f1a9c4d7e3"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("analyses", sa.Column("security", JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("analyses", "security")
