"""Role gating (what you can do) + team scoping (what rows you can see).

`User.role` is the capability tier; team membership is the visibility boundary.
Both are enforced server-side on every route.
"""

from __future__ import annotations

from functools import wraps

from flask import g, jsonify
from sqlalchemy.orm import Query, Session

from .auth.deps import resolve_principal
from .auth.principal import Principal
from .models import Role, TeamMember, TeamRole


def require_role(*roles: Role):  # type: ignore[no-untyped-def]
    allowed = set(roles)

    def decorator(fn):  # type: ignore[no-untyped-def]
        @wraps(fn)
        def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            principal = resolve_principal()
            if principal is None:
                return jsonify(error="unauthorized"), 401
            if principal.role not in allowed:
                return jsonify(error="forbidden"), 403
            g.principal = principal
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_admin(fn):  # type: ignore[no-untyped-def]
    return require_role(Role.admin)(fn)


# --- team scoping ---------------------------------------------------------- #
def scope_to_teams(query: Query, model, principal: Principal) -> Query:  # type: ignore[no-untyped-def]
    """Restrict a query on a team-scoped model to the principal's teams (admins bypass)."""
    if principal.is_admin:
        return query
    return query.filter(model.team_id.in_(principal.team_ids or [-1]))


def can_access_team(principal: Principal, team_id: int) -> bool:
    return principal.is_admin or team_id in (principal.team_ids or [])


def is_team_lead(session: Session, principal: Principal, team_id: int) -> bool:
    if principal.is_admin:
        return True
    m = session.get(TeamMember, (team_id, principal.user.id))
    return m is not None and m.team_role is TeamRole.lead
