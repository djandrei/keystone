"""Keystone data model (see docs/design.md §7).

Two orthogonal axes: `User.role` is the system capability tier; team membership
(via `team_members`) is the data-visibility boundary. Binaries and analyses carry
a `team_id`; a principal sees a row iff they're a member of that team (admins
transcend teams).
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    func,
    text,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship
from sqlalchemy.types import JSON

from .db import Base

# JSONB on Postgres, plain JSON on SQLite (tests) — one portable column type.
JsonB = JSON().with_variant(JSONB(), "postgresql")


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Role(str, enum.Enum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class TeamRole(str, enum.Enum):
    lead = "lead"
    member = "member"


class AnalysisMode(str, enum.Enum):
    re = "re"
    vr = "vr"


class AnalysisStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    canceled = "canceled"


class Classification(str, enum.Enum):
    true_positive = "true_positive"
    false_positive = "false_positive"
    needs_review = "needs_review"


class RiskLevel(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"


def _ts() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


# --------------------------------------------------------------------------- #
# Identity: users, teams, membership
# --------------------------------------------------------------------------- #
class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(SAEnum(Role), default=Role.analyst, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = _ts()
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    memberships: Mapped[list[TeamMember]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Team(Base):
    __tablename__ = "teams"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    created_at: Mapped[datetime] = _ts()
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))

    members: Mapped[list[TeamMember]] = relationship(
        back_populates="team", cascade="all, delete-orphan"
    )


class TeamMember(Base):
    __tablename__ = "team_members"

    team_id: Mapped[int] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    team_role: Mapped[TeamRole] = mapped_column(SAEnum(TeamRole), default=TeamRole.member)
    added_at: Mapped[datetime] = _ts()

    team: Mapped[Team] = relationship(back_populates="members")
    user: Mapped[User] = relationship(back_populates="memberships")


# --------------------------------------------------------------------------- #
# Work: projects, binaries, analyses, results
# --------------------------------------------------------------------------- #
DEFAULT_PROJECT_NAME = "Unassigned"


class Project(Base):
    """A named bucket that groups binaries within a team. Every team has exactly
    one `is_default` project ("Unassigned"); binaries with no explicit project land
    there. Project names are unique within a team."""

    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("team_id", "name", name="uq_project_team_name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    team_id: Mapped[int] = mapped_column(ForeignKey("teams.id", ondelete="RESTRICT"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    is_default: Mapped[bool] = mapped_column(Boolean, default=False)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = _ts()


class Binary(Base):
    __tablename__ = "binaries"
    __table_args__ = (UniqueConstraint("team_id", "sha256", name="uq_binary_team_sha"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    team_id: Mapped[int] = mapped_column(ForeignKey("teams.id"), index=True)
    # NOT NULL; auto-filled to the team's default project by the before_flush hook
    # below when not set explicitly. Same-team consistency is enforced in the API.
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="RESTRICT"), index=True
    )
    project: Mapped[Project] = relationship()
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    filename: Mapped[str] = mapped_column(String(255), index=True)
    size: Mapped[int] = mapped_column(Integer)
    format: Mapped[str | None] = mapped_column(String(64))
    arch: Mapped[str | None] = mapped_column(String(64))
    platform: Mapped[str | None] = mapped_column(String(32))
    ghidra_program_name: Mapped[str | None] = mapped_column(String(255))
    storage_key: Mapped[str] = mapped_column(String(255))
    uploaded_by: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = _ts()


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(primary_key=True)
    team_id: Mapped[int] = mapped_column(ForeignKey("teams.id"), index=True)
    binary_id: Mapped[int] = mapped_column(ForeignKey("binaries.id"), index=True)
    mode: Mapped[AnalysisMode] = mapped_column(SAEnum(AnalysisMode))
    status: Mapped[AnalysisStatus] = mapped_column(
        SAEnum(AnalysisStatus), default=AnalysisStatus.queued, index=True
    )
    model: Mapped[str | None] = mapped_column(String(120))
    params: Mapped[dict | None] = mapped_column(JsonB)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    progress: Mapped[dict | None] = mapped_column(JsonB)
    security: Mapped[dict | None] = mapped_column(JsonB)  # injection report (SEC.4)

    re_result: Mapped[REResult | None] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", uselist=False
    )
    findings: Mapped[list[VRFinding]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    report: Mapped[Report | None] = relationship(
        back_populates="analysis", cascade="all, delete-orphan", uselist=False
    )


class REResult(Base):
    __tablename__ = "re_results"

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), primary_key=True
    )
    binary_type: Mapped[str | None] = mapped_column(String(64))
    purpose: Mapped[str | None] = mapped_column(Text)
    key_functions: Mapped[str | None] = mapped_column(Text)
    attack_surface: Mapped[str | None] = mapped_column(Text)
    language_runtime: Mapped[str | None] = mapped_column(Text)
    tool_calls: Mapped[int | None] = mapped_column(Integer)
    raw: Mapped[dict | None] = mapped_column(JsonB)

    analysis: Mapped[Analysis] = relationship(back_populates="re_result")


class VRFinding(Base):
    __tablename__ = "vr_findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True
    )
    rule: Mapped[str | None] = mapped_column(String(255))
    file: Mapped[str | None] = mapped_column(String(255))
    line: Mapped[int | None] = mapped_column(Integer)
    semgrep_message: Mapped[str | None] = mapped_column(Text)
    classification: Mapped[Classification | None] = mapped_column(SAEnum(Classification))
    risk_level: Mapped[RiskLevel | None] = mapped_column(SAEnum(RiskLevel))
    cwe_id: Mapped[str | None] = mapped_column(String(32))
    reasoning: Mapped[str | None] = mapped_column(Text)
    reachable: Mapped[str | None] = mapped_column(String(16))
    entry_path: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[str | None] = mapped_column(String(16))
    # Which ruleset version produced this finding (parsed from the namespaced
    # check_id); NULL for findings from the legacy single-config path.
    rule_set_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("rule_set_versions.id", ondelete="SET NULL")
    )

    analysis: Mapped[Analysis] = relationship(back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), primary_key=True
    )
    format: Mapped[str] = mapped_column(String(16), default="md")
    storage_key: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = _ts()

    analysis: Mapped[Analysis] = relationship(back_populates="report")


# --------------------------------------------------------------------------- #
# Semgrep rule sets: the team-scoped pattern library
# --------------------------------------------------------------------------- #
BUILTIN_RULESET_NAME = "Decompiled C — VR defaults"


class RuleSet(Base):
    """A named Semgrep ruleset. `team_id IS NULL` marks a system built-in: readable
    by every team, writable only by admins, and forked into a team with `clone`.
    Content never lives here — it lives in immutable `RuleSetVersion` rows, so an
    analysis can pin the exact text it ran (see docs/rule-sets-plan.md §4).

    There is deliberately no `current_version_id` pointer: it would make a circular
    FK with `rule_set_versions`. The latest version is `max(version_no)`, and a
    revert is a new version carrying an old version's content.
    """

    __tablename__ = "rule_sets"
    # Two partial indexes rather than one UniqueConstraint: NULLs compare distinct,
    # so a plain (team_id, name) constraint would not stop two built-ins sharing
    # a name. Both dialects we run on support partial indexes.
    __table_args__ = (
        Index(
            "uq_rule_set_team_name",
            "team_id",
            "name",
            unique=True,
            postgresql_where=text("team_id IS NOT NULL"),
            sqlite_where=text("team_id IS NOT NULL"),
        ),
        Index(
            "uq_rule_set_builtin_name",
            "name",
            unique=True,
            postgresql_where=text("team_id IS NULL"),
            sqlite_where=text("team_id IS NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    team_id: Mapped[int | None] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(120))
    description: Mapped[str | None] = mapped_column(Text)
    languages: Mapped[list | None] = mapped_column(JsonB)  # ["c"] — picker filter
    is_builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    # Archived rulesets stay pinnable by history but drop out of the pickers.
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = _ts()

    versions: Mapped[list[RuleSetVersion]] = relationship(
        back_populates="rule_set",
        cascade="all, delete-orphan",
        order_by="RuleSetVersion.version_no",
    )

    @property
    def latest(self) -> RuleSetVersion | None:
        return self.versions[-1] if self.versions else None


class RuleSetVersion(Base):
    """One immutable revision of a ruleset. Never UPDATEd after insert — editing a
    ruleset appends a new row."""

    __tablename__ = "rule_set_versions"
    __table_args__ = (UniqueConstraint("rule_set_id", "version_no", name="uq_rsv_set_version"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_set_id: Mapped[int] = mapped_column(
        ForeignKey("rule_sets.id", ondelete="CASCADE"), index=True
    )
    version_no: Mapped[int] = mapped_column(Integer)
    content: Mapped[str] = mapped_column(Text)  # the Semgrep YAML document
    content_sha256: Mapped[str] = mapped_column(String(64))  # no-op saves are skipped
    rule_ids: Mapped[list | None] = mapped_column(JsonB)  # extracted at save time
    notes: Mapped[str | None] = mapped_column(Text)
    # Injection screen over the authored rule text (SEC: rule messages reach the
    # triage prompt). Shape matches Analysis.security.
    security: Mapped[dict | None] = mapped_column(JsonB)
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[datetime] = _ts()

    rule_set: Mapped[RuleSet] = relationship(back_populates="versions")


class AnalysisRuleSet(Base):
    """The pin: exactly which ruleset versions an analysis ran, in --config order.

    RESTRICT on the version FK is the point — a version that produced findings can
    never be deleted, so an old report stays explainable."""

    __tablename__ = "analysis_rule_sets"

    analysis_id: Mapped[int] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), primary_key=True
    )
    rule_set_version_id: Mapped[int] = mapped_column(
        ForeignKey("rule_set_versions.id", ondelete="RESTRICT"), primary_key=True
    )
    position: Mapped[int] = mapped_column(Integer, default=0)


# --------------------------------------------------------------------------- #
# System: settings, tokens, audit
# --------------------------------------------------------------------------- #
class SystemSettings(Base):
    __tablename__ = "system_settings"

    id: Mapped[int] = mapped_column(primary_key=True)  # singleton row id=1
    llm_endpoint_url: Mapped[str | None] = mapped_column(String(255))
    default_model: Mapped[str | None] = mapped_column(String(120))
    # Optional separate model for the high-volume VR triage step (two-model cascade).
    triage_model: Mapped[str | None] = mapped_column(String(120))
    triage_endpoint_url: Mapped[str | None] = mapped_column(String(255))
    # Deprecated (never read by the worker) — superseded by default_rule_set_id.
    # Retained for one release so an upgrade can roll back; do not surface it.
    semgrep_config: Mapped[dict | None] = mapped_column(JsonB)
    # The ruleset a VR analysis falls back to when the request pins none.
    default_rule_set_id: Mapped[int | None] = mapped_column(
        ForeignKey("rule_sets.id", ondelete="SET NULL")
    )
    updated_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    scopes: Mapped[dict | None] = mapped_column(JsonB)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _ts()
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    issued_at: Mapped[datetime] = _ts()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    user_agent: Mapped[str | None] = mapped_column(String(255))


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    action: Mapped[str] = mapped_column(String(120), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[dict | None] = mapped_column(JsonB)
    created_at: Mapped[datetime] = _ts()


@event.listens_for(Session, "before_flush")
def _assign_default_project(session: Session, flush_context, instances) -> None:  # type: ignore[no-untyped-def]
    """Any new Binary without an explicit project lands in its team's default
    ("Unassigned") project — created on demand. Keeps binaries.project_id NOT NULL
    without every caller having to pick a project."""
    pending = [
        o
        for o in session.new
        if isinstance(o, Binary) and o.project_id is None and o.project is None
    ]
    if not pending:
        return
    with session.no_autoflush:
        by_team: dict[int, Project] = {}
        for b in pending:
            proj = by_team.get(b.team_id)
            if proj is None:
                proj = session.query(Project).filter_by(team_id=b.team_id, is_default=True).first()
                if proj is None:
                    proj = Project(team_id=b.team_id, name=DEFAULT_PROJECT_NAME, is_default=True)
                    session.add(proj)
                by_team[b.team_id] = proj
            b.project = proj
