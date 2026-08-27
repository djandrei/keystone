from __future__ import annotations

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class LogoutRequest(BaseModel):
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8)
