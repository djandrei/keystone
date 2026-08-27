"""The authenticated caller for a request."""
from __future__ import annotations

from dataclasses import dataclass

from ..models import Role, User


@dataclass
class Principal:
    user: User
    role: Role
    team_ids: list[int]

    @property
    def is_admin(self) -> bool:
        return self.role is Role.admin
