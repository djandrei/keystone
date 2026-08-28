"""projects: group binaries into per-team buckets

Revision ID: e9f3a1b2c4d5
Revises: d8e2f1a3b6c7
Create Date: 2026-08-28

Adds a `projects` table (a named bucket scoped to a team), gives every existing
team an 'Unassigned' default project, and adds a NOT NULL `binaries.project_id`
backfilled to each binary's team default.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "e9f3a1b2c4d5"
down_revision = "d8e2f1a3b6c7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "team_id",
            sa.Integer(),
            sa.ForeignKey("teams.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("is_default", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("team_id", "name", name="uq_project_team_name"),
    )

    # one 'Unassigned' default project per existing team
    op.execute(
        "INSERT INTO projects (team_id, name, is_default, created_at) "
        "SELECT id, 'Unassigned', true, now() FROM teams"
    )

    # add binaries.project_id, backfill to the team default, then lock it down
    op.add_column("binaries", sa.Column("project_id", sa.Integer(), nullable=True))
    op.execute(
        "UPDATE binaries b SET project_id = p.id "
        "FROM projects p WHERE p.team_id = b.team_id AND p.is_default = true"
    )
    op.alter_column("binaries", "project_id", nullable=False)
    op.create_index("ix_binaries_project_id", "binaries", ["project_id"])
    op.create_foreign_key(
        "fk_binaries_project_id",
        "binaries",
        "projects",
        ["project_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def downgrade() -> None:
    op.drop_constraint("fk_binaries_project_id", "binaries", type_="foreignkey")
    op.drop_index("ix_binaries_project_id", table_name="binaries")
    op.drop_column("binaries", "project_id")
    op.drop_table("projects")
