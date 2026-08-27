"""JWT access tokens + DB-backed, rotating, revocable refresh tokens."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

import jwt
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import RefreshToken, TeamMember, User


def _now() -> datetime:
    return datetime.now(UTC)


def _aware(dt: datetime) -> datetime:
    """SQLite returns naive datetimes; treat naive as UTC for comparisons."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def user_team_ids(session: Session, user_id: int) -> list[int]:
    return [m.team_id for m in session.query(TeamMember).filter_by(user_id=user_id).all()]


def create_access_token(user: User, team_ids: list[int]) -> str:
    cfg = get_settings()
    now = _now()
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role.value,
        "teams": team_ids,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=cfg.access_ttl_min)).timestamp()),
    }
    return jwt.encode(payload, cfg.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    """Raises jwt.PyJWTError on invalid/expired."""
    return jwt.decode(token, get_settings().jwt_secret, algorithms=["HS256"])


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def issue_refresh_token(session: Session, user: User, user_agent: str | None = None) -> str:
    cfg = get_settings()
    raw = secrets.token_urlsafe(48)
    session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=_hash(raw),
            expires_at=_now() + timedelta(days=cfg.refresh_ttl_days),
            user_agent=(user_agent or "")[:255],
        )
    )
    session.flush()
    return raw


def _find_active(session: Session, raw: str) -> RefreshToken | None:
    rt = session.query(RefreshToken).filter_by(token_hash=_hash(raw)).first()
    if rt is None or rt.revoked_at is not None or _aware(rt.expires_at) <= _now():
        return None
    return rt


def rotate_refresh(session: Session, raw: str, user_agent: str | None = None):
    rt = _find_active(session, raw)
    if rt is None:
        return None
    rt.revoked_at = _now()  # single-use: revoke on rotation
    user = session.get(User, rt.user_id)
    assert user is not None
    new_raw = issue_refresh_token(session, user, user_agent)
    return user, new_raw


def revoke_refresh(session: Session, raw: str) -> None:
    rt = session.query(RefreshToken).filter_by(token_hash=_hash(raw)).first()
    if rt is not None and rt.revoked_at is None:
        rt.revoked_at = _now()
