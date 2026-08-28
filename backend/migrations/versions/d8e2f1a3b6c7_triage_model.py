"""system_settings: triage_model + triage_endpoint_url

Revision ID: d8e2f1a3b6c7
Revises: c7d1e2f3a4b5
Create Date: 2026-08-28

Two-model cascade: an optional cheaper model for the high-volume VR triage step.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "d8e2f1a3b6c7"
down_revision = "c7d1e2f3a4b5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "system_settings", sa.Column("triage_model", sa.String(length=120), nullable=True)
    )
    op.add_column(
        "system_settings", sa.Column("triage_endpoint_url", sa.String(length=255), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("system_settings", "triage_endpoint_url")
    op.drop_column("system_settings", "triage_model")
