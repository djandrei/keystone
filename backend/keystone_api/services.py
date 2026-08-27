"""Domain services: system settings + first-run bootstrap (idempotent)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from .config import get_settings
from .models import Role, SystemSettings, Team, TeamMember, TeamRole, User
from .security import hash_password


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


def ensure_team(session: Session, name: str, created_by: int | None = None) -> Team:
    team = session.query(Team).filter_by(name=name).first()
    if team is None:
        team = Team(name=name, created_by=created_by)
        session.add(team)
        session.flush()
    return team


def ensure_membership(session: Session, team: Team, user: User, role: TeamRole) -> None:
    if session.get(TeamMember, (team.id, user.id)) is None:
        session.add(TeamMember(team_id=team.id, user_id=user.id, team_role=role))
        session.flush()


def bootstrap(session: Session) -> dict:
    """Ensure the settings singleton, a default team, and the admin. Idempotent."""
    get_or_create_settings(session)
    cfg = get_settings()

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
