"""Personal API tokens for external/programmatic clients (opaque, hashed)."""
from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models import ApiToken, User
from .principal import Principal
from .tokens import _aware, user_team_ids

PREFIX = "kst_"


def _hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def create_api_token(
    session: Session,
    user: User,
    name: str,
    scopes: list[str] | None = None,
    expires_at: datetime | None = None,
) -> tuple[ApiToken, str]:
    raw = PREFIX + secrets.token_urlsafe(32)
    tok = ApiToken(
        user_id=user.id, name=name, token_hash=_hash(raw),
        scopes=scopes, expires_at=expires_at,
    )
    session.add(tok)
    session.flush()
    return tok, raw


def list_api_tokens(session: Session, user: User) -> list[ApiToken]:
    return session.query(ApiToken).filter_by(user_id=user.id).order_by(ApiToken.created_at.desc()).all()


def revoke_api_token(session: Session, user: User, token_id: int) -> bool:
    tok = session.query(ApiToken).filter_by(id=token_id, user_id=user.id).first()
    if tok is None:
        return False
    session.delete(tok)
    return True


def resolve_api_token(session: Session, raw: str) -> Principal | None:
    if not raw.startswith(PREFIX):
        return None
    tok = session.query(ApiToken).filter_by(token_hash=_hash(raw)).first()
    if tok is None:
        return None
    if tok.expires_at is not None and _aware(tok.expires_at) <= datetime.now(timezone.utc):
        return None
    user = session.get(User, tok.user_id)
    if user is None or not user.is_active:
        return None
    tok.last_used_at = datetime.now(timezone.utc)
    return Principal(user=user, role=user.role, team_ids=user_team_ids(session, user.id))
