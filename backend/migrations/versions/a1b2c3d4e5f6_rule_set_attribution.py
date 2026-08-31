"""rule_sets.attribution — credit imported rules to their author

Revision ID: a1b2c3d4e5f6
Revises: f0a1b2c3d4e5
Create Date: 2026-08-31

Adds a nullable JSONB `attribution` ({author, license, url, commit}) to
`rule_sets`. NULL for rule sets authored in Keystone; set by
`rule_import.ensure_vendored_rulesets` for imported ones, which backfills it on
the next bootstrap — no data migration needed here.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Matches models.JsonB — JSONB on Postgres, plain JSON on SQLite.
JSONB = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

revision = "a1b2c3d4e5f6"
down_revision = "f0a1b2c3d4e5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("rule_sets", sa.Column("attribution", JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("rule_sets", "attribution")
