"""Domain services: system settings + first-run bootstrap (idempotent)."""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy.orm import Session

from .config import get_settings
from .models import (
    BUILTIN_RULESET_NAME,
    DEFAULT_PROJECT_NAME,
    AnalysisRuleSet,
    Project,
    Role,
    RuleSet,
    RuleSetVersion,
    SystemSettings,
    Team,
    TeamMember,
    TeamRole,
    User,
)
from .rulesets import RulesetError, content_sha256, validate_ruleset
from .security import hash_password

log = logging.getLogger("keystone.services")

# The ruleset shipped in the image (backend/semgrep-rules/), seeded as the
# system built-in. Resolved relative to this file so it works in the container
# (/app/keystone_api/services.py) and from a source checkout alike.
BUILTIN_RULESET_PATH = (
    Path(__file__).resolve().parent.parent / "semgrep-rules" / "decompiled-c.yaml"
)


def get_or_create_settings(session: Session) -> SystemSettings:
    row = session.get(SystemSettings, 1)
    if row is None:
        row = SystemSettings(id=1)
        session.add(row)
        session.flush()
    return row


def update_settings(session: Session, **fields: object) -> SystemSettings:
    row = get_or_create_settings(session)
    for key, value in fields.items():
        if hasattr(row, key):
            setattr(row, key, value)
    session.flush()
    return row


def get_or_create_default_project(
    session: Session, team_id: int, created_by: int | None = None
) -> Project:
    """The team's non-deletable 'Unassigned' bucket — the home for binaries with no
    explicit project. Idempotent."""
    proj = session.query(Project).filter_by(team_id=team_id, is_default=True).first()
    if proj is None:
        proj = Project(
            team_id=team_id, name=DEFAULT_PROJECT_NAME, is_default=True, created_by=created_by
        )
        session.add(proj)
        session.flush()
    return proj


def ensure_team(session: Session, name: str, created_by: int | None = None) -> Team:
    team = session.query(Team).filter_by(name=name).first()
    if team is None:
        team = Team(name=name, created_by=created_by)
        session.add(team)
        session.flush()
    get_or_create_default_project(session, team.id, created_by)
    return team


def ensure_membership(session: Session, team: Team, user: User, role: TeamRole) -> None:
    if session.get(TeamMember, (team.id, user.id)) is None:
        session.add(TeamMember(team_id=team.id, user_id=user.id, team_role=role))
        session.flush()


def add_rule_set_version(
    session: Session,
    rule_set: RuleSet,
    content: str,
    *,
    created_by: int | None = None,
    notes: str | None = None,
    security: dict | None = None,
) -> RuleSetVersion | None:
    """Append an immutable version. Returns None when `content` matches the latest
    version byte-for-byte — a save that changes nothing should not manufacture
    history. Validates first: an invalid document never reaches the DB."""
    rule_ids, _ = validate_ruleset(content)
    digest = content_sha256(content)

    latest = (
        session.query(RuleSetVersion)
        .filter_by(rule_set_id=rule_set.id)
        .order_by(RuleSetVersion.version_no.desc())
        .first()
    )
    if latest is not None and latest.content_sha256 == digest:
        return None

    version = RuleSetVersion(
        rule_set_id=rule_set.id,
        version_no=(latest.version_no + 1) if latest else 1,
        content=content,
        content_sha256=digest,
        rule_ids=rule_ids,
        notes=notes,
        security=security,
        created_by=created_by,
    )
    session.add(version)
    session.flush()
    return version


def latest_version(session: Session, rule_set_id: int) -> RuleSetVersion | None:
    return (
        session.query(RuleSetVersion)
        .filter_by(rule_set_id=rule_set_id)
        .order_by(RuleSetVersion.version_no.desc())
        .first()
    )


class RuleSetResolutionError(ValueError):
    """A requested rule set does not exist, is empty, or belongs to another team."""


def _assert_visible(rs: RuleSet, team_id: int) -> None:
    """A built-in is visible to every team; anything else must be the team's own.
    Checked server-side because a pinned id arrives from the client."""
    if rs.team_id is not None and rs.team_id != team_id:
        raise RuleSetResolutionError(f"rule set {rs.id} does not belong to this team")


def resolve_rule_set_versions(
    session: Session, team_id: int, params: dict | None, sysset: SystemSettings
) -> list[RuleSetVersion]:
    """The versions a VR analysis should run, in `--config` order.

    Resolution order (docs/rule-sets-plan.md §5):
      1. `params["rule_set_version_ids"]` — an exact pin
      2. `params["rule_set_ids"]`         — resolved to each set's latest version
      3. `SystemSettings.default_rule_set_id`
      4. nothing — the caller falls back to the legacy env `semgrep_config`

    Resolution happens when the analysis is *created*, not when the worker picks
    it up, so a bad id is a 400 on the request rather than a failed job, and the
    pin reflects what the analyst saw in the picker.
    """
    params = params or {}

    version_ids = params.get("rule_set_version_ids") or []
    if version_ids:
        versions: list[RuleSetVersion] = []
        for vid in version_ids:
            v = session.get(RuleSetVersion, vid)
            if v is None:
                raise RuleSetResolutionError(f"rule set version {vid} not found")
            _assert_visible(v.rule_set, team_id)
            versions.append(v)
        return versions

    set_ids = params.get("rule_set_ids") or []
    if not set_ids and sysset.default_rule_set_id is not None:
        set_ids = [sysset.default_rule_set_id]

    versions = []
    for sid in set_ids:
        rs = session.get(RuleSet, sid)
        if rs is None:
            raise RuleSetResolutionError(f"rule set {sid} not found")
        _assert_visible(rs, team_id)
        v = latest_version(session, rs.id)
        if v is None:
            raise RuleSetResolutionError(f"rule set {rs.name!r} has no versions")
        versions.append(v)
    return versions


def pin_rule_sets(session: Session, analysis_id: int, versions: list[RuleSetVersion]) -> None:
    """Record which versions this analysis ran. Written at creation so the pin
    survives a worker that dies mid-scan."""
    for i, v in enumerate(versions):
        session.add(AnalysisRuleSet(analysis_id=analysis_id, rule_set_version_id=v.id, position=i))


def pinned_rule_set_versions(session: Session, analysis_id: int) -> list[RuleSetVersion]:
    """The pinned versions in `--config` order — the worker's read side."""
    rows = (
        session.query(RuleSetVersion, AnalysisRuleSet.position)
        .join(AnalysisRuleSet, AnalysisRuleSet.rule_set_version_id == RuleSetVersion.id)
        .filter(AnalysisRuleSet.analysis_id == analysis_id)
        .order_by(AnalysisRuleSet.position)
        .all()
    )
    return [v for v, _ in rows]


def upsert_builtin_ruleset(
    session: Session,
    name: str,
    content: str,
    *,
    description: str | None = None,
    languages: list[str] | None = None,
    notes: str | None = None,
    attribution: dict | None = None,
) -> RuleSet | None:
    """Create-or-update a system built-in (`team_id IS NULL`) from shipped content.

    Idempotent and content-aware: identical content is a no-op, changed content
    appends a new version. Returns the rule set, or None if the content will not
    validate — a bad shipped file must not abort a boot."""
    rs = session.query(RuleSet).filter_by(name=name, team_id=None).first()
    if rs is None:
        rs = RuleSet(
            team_id=None,
            name=name,
            description=description,
            languages=languages,
            is_builtin=True,
            attribution=attribution,
        )
        session.add(rs)
        session.flush()
    else:
        # Let a re-vendor correct the blurb and the credit without touching
        # version history — a new upstream commit changes the attribution too.
        if description is not None:
            rs.description = description
        if languages is not None:
            rs.languages = languages
        if attribution is not None:
            rs.attribution = attribution

    try:
        add_rule_set_version(session, rs, content, notes=notes)
    except RulesetError as e:
        log.warning("built-in ruleset %r failed validation: %s", name, e)
        return None
    return rs


def ensure_builtin_rulesets(session: Session) -> RuleSet | None:
    """Seed the shipped ruleset as the system built-in and return it (it is the
    deployment default). Idempotent, and content-aware: a shipped rule change on
    the next deploy appends v2 rather than being ignored or duplicating the set.

    Seeding lives here, not in the Alembic migration, so a missing or malformed
    rules file logs a warning instead of wedging a deployment mid-migration."""
    try:
        content = BUILTIN_RULESET_PATH.read_text(encoding="utf-8")
    except OSError as e:
        log.warning("built-in ruleset not seeded — cannot read %s: %s", BUILTIN_RULESET_PATH, e)
        return None

    rs = upsert_builtin_ruleset(
        session,
        BUILTIN_RULESET_NAME,
        content,
        description=(
            "Vulnerability-research rules for Ghidra-decompiled C, shipped with "
            "Keystone. Clone it into your team to customize."
        ),
        languages=["c"],
        notes="shipped with Keystone",
    )
    # A validation failure must not lose the deployment default: the row exists
    # either way, so look it up rather than propagating the None.
    return rs or session.query(RuleSet).filter_by(name=BUILTIN_RULESET_NAME, team_id=None).first()


def ensure_vendored_rulesets(session: Session) -> list[RuleSet]:
    """Seed the vendored third-party rule tree (0xdea) as grouped built-ins.

    The grouping lives in `rule_import.GROUPS`; this only persists it. Idempotent
    by content hash, so re-vendoring an unchanged tree costs one hash per group and
    a changed rule appends a version to just the group that carries it."""
    from .rule_import import ATTRIBUTION, build_groups

    seeded: list[RuleSet] = []
    for group, content, count in build_groups():
        rs = upsert_builtin_ruleset(
            session,
            group.name,
            content,
            description=group.description,
            notes=f"vendored from 0xdea/semgrep-rules ({count} rules)",
            attribution=ATTRIBUTION,
        )
        if rs is not None:
            seeded.append(rs)
    return seeded


def bootstrap(session: Session) -> dict:
    """Ensure the settings singleton, a default team, the admin, and the built-in
    rule set. Idempotent."""
    sysset = get_or_create_settings(session)
    cfg = get_settings()

    builtin = ensure_builtin_rulesets(session)
    ensure_vendored_rulesets(session)
    # Point the deployment default at the built-in on first boot only — never
    # overwrite an admin's later choice.
    if builtin is not None and sysset.default_rule_set_id is None:
        sysset.default_rule_set_id = builtin.id

    team = ensure_team(session, "Default")
    admin = session.query(User).filter_by(username=cfg.admin_username).first()
    created = False
    if admin is None:
        admin = User(
            username=cfg.admin_username,
            email=cfg.admin_email,
            password_hash=hash_password(cfg.admin_password),
            role=Role.admin,
        )
        session.add(admin)
        session.flush()
        created = True
    ensure_membership(session, team, admin, TeamRole.lead)
    return {"admin_created": created, "admin": admin.username, "team": team.name}


def seed_demo(session: Session) -> None:
    """Dev fixture: bootstrap + a demo analyst in a demo team."""
    bootstrap(session)
    team = ensure_team(session, "Blue Team")
    analyst = session.query(User).filter_by(username="analyst").first()
    if analyst is None:
        analyst = User(
            username="analyst",
            email="analyst@keystone.local",
            password_hash=hash_password("analyst"),
            role=Role.analyst,
        )
        session.add(analyst)
        session.flush()
    ensure_membership(session, team, analyst, TeamRole.member)
