"""rule sets: a team-scoped, immutably-versioned Semgrep pattern library

Revision ID: f0a1b2c3d4e5
Revises: e9f3a1b2c4d5
Create Date: 2026-08-31

Adds `rule_sets` (identity; team_id NULL = system built-in), `rule_set_versions`
(immutable content) and `analysis_rule_sets` (the per-analysis pin), plus
`system_settings.default_rule_set_id` and `vr_findings.rule_set_version_id`.

No data migration: the built-in ruleset is seeded idempotently by
`services.ensure_builtin_rulesets`, called from `bootstrap()`. Seeding from the
app rather than here keeps file I/O out of Alembic, where a missing rules file
would wedge a deployment mid-migration.

`system_settings.semgrep_config` is left in place but unused — its replacement is
`default_rule_set_id`. Drop it a release later, not in the same migration that
supersedes it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# Matches models.JsonB — JSONB on Postgres, plain JSON on SQLite. Using bare
# sa.JSON() here would pass the round-trip test and still fail `alembic check`.
JSONB = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

revision = "f0a1b2c3d4e5"
down_revision = "e9f3a1b2c4d5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rule_sets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "team_id",
            sa.Integer(),
            sa.ForeignKey("teams.id", ondelete="CASCADE"),
            nullable=True,  # NULL => system built-in
            index=True,
        ),
        sa.Column("name", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("languages", JSONB, nullable=True),
        sa.Column("is_builtin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    # Partial uniqueness: a plain (team_id, name) constraint would not stop two
    # built-ins sharing a name, since NULLs compare distinct.
    op.create_index(
        "uq_rule_set_team_name",
        "rule_sets",
        ["team_id", "name"],
        unique=True,
        postgresql_where=sa.text("team_id IS NOT NULL"),
        sqlite_where=sa.text("team_id IS NOT NULL"),
    )
    op.create_index(
        "uq_rule_set_builtin_name",
        "rule_sets",
        ["name"],
        unique=True,
        postgresql_where=sa.text("team_id IS NULL"),
        sqlite_where=sa.text("team_id IS NULL"),
    )

    op.create_table(
        "rule_set_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "rule_set_id",
            sa.Integer(),
            sa.ForeignKey("rule_sets.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("version_no", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("rule_ids", JSONB, nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("security", JSONB, nullable=True),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("rule_set_id", "version_no", name="uq_rsv_set_version"),
    )

    op.create_table(
        "analysis_rule_sets",
        sa.Column(
            "analysis_id",
            sa.Integer(),
            sa.ForeignKey("analyses.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "rule_set_version_id",
            sa.Integer(),
            # RESTRICT: a version that produced findings can never be deleted.
            sa.ForeignKey("rule_set_versions.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
    )

    op.add_column("system_settings", sa.Column("default_rule_set_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_system_settings_default_rule_set",
        "system_settings",
        "rule_sets",
        ["default_rule_set_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.add_column("vr_findings", sa.Column("rule_set_version_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_vr_findings_rule_set_version",
        "vr_findings",
        "rule_set_versions",
        ["rule_set_version_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_vr_findings_rule_set_version", "vr_findings", type_="foreignkey")
    op.drop_column("vr_findings", "rule_set_version_id")
    op.drop_constraint("fk_system_settings_default_rule_set", "system_settings", type_="foreignkey")
    op.drop_column("system_settings", "default_rule_set_id")
    op.drop_table("analysis_rule_sets")
    op.drop_table("rule_set_versions")
    op.drop_index("uq_rule_set_builtin_name", table_name="rule_sets")
    op.drop_index("uq_rule_set_team_name", table_name="rule_sets")
    op.drop_table("rule_sets")
