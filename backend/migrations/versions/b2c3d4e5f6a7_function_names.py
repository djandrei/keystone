"""function names: friendly names per binary, selection per analysis

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-08-31

Adds `function_names` (a friendly name + one-line purpose per function of a
binary, keyed on address) and `analysis_functions` (which of them a given
analysis's report shows).

Names are scoped to a binary, so a second analysis of the same sample reuses
them; team visibility rides on `binaries.team_id` and needs no new column.
Nothing is written back into Ghidra — see docs/function-naming-plan.md §3.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "b2c3d4e5f6a7"
down_revision = "a1b2c3d4e5f6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "function_names",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "binary_id",
            sa.Integer(),
            sa.ForeignKey("binaries.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("address", sa.String(length=32), nullable=False),
        sa.Column("original_name", sa.String(length=255), nullable=False),
        sa.Column("suggested_name", sa.String(length=255), nullable=True),
        sa.Column("purpose", sa.Text(), nullable=True),
        sa.Column("source", sa.String(length=16), nullable=False, server_default="llm"),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("binary_id", "address", name="uq_fn_binary_addr"),
    )

    op.create_table(
        "analysis_functions",
        sa.Column(
            "analysis_id",
            sa.Integer(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "function_name_id",
            sa.Integer(),
            sa.ForeignKey("function_names.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("included", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_table("analysis_functions")
    op.drop_table("function_names")
