"""Audit trail for privileged actions."""

from __future__ import annotations

from sqlalchemy.orm import Session

from .auth.principal import Principal
from .models import AuditLog


def audit(
    session: Session,
    principal: Principal | None,
    action: str,
    target_type: str | None = None,
    target_id: object | None = None,
    detail: dict | None = None,
) -> None:
    session.add(
        AuditLog(
            user_id=principal.user.id if principal else None,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            detail=detail,
        )
    )
    session.flush()
