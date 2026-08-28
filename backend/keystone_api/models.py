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
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
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
# Work: binaries, analyses, results
# --------------------------------------------------------------------------- #
class Binary(Base):
    __tablename__ = "binaries"
    __table_args__ = (UniqueConstraint("team_id", "sha256", name="uq_binary_team_sha"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    team_id: Mapped[int] = mapped_column(ForeignKey("teams.id"), index=True)
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
    semgrep_config: Mapped[dict | None] = mapped_column(JsonB)
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
