"""SDK token models extended with the identity Ratatoskr needs on every request."""

from __future__ import annotations

from typing import Literal

from mcp.server.auth.provider import AccessToken, RefreshToken

AuthSource = Literal["local", "oidc"]


class RatatoskrAccessToken(AccessToken):
    subject: str
    display_name: str
    groups: list[str]
    auth_source: AuthSource


class RatatoskrRefreshToken(RefreshToken):
    family_id: str
    subject: str
    display_name: str
    groups: list[str]
    auth_source: AuthSource
