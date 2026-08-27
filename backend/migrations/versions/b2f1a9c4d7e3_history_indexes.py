"""history indexes: analyses.created_at, binaries.filename

Revision ID: b2f1a9c4d7e3
Revises: c93cc2704540
Create Date: 2026-08-27

Back the M4 history/search hot paths (sort by recency, search by filename).
"""

from __future__ import annotations

from alembic import op

revision = "b2f1a9c4d7e3"
down_revision = "c93cc2704540"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_analyses_created_at", "analyses", ["created_at"])
    op.create_index("ix_binaries_filename", "binaries", ["filename"])


def downgrade() -> None:
    op.drop_index("ix_binaries_filename", table_name="binaries")
    op.drop_index("ix_analyses_created_at", table_name="analyses")
