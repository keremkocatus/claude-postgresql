"""Shared identity-provider types. Both providers produce a :class:`Principal`."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ratatoskr.auth.principal import Principal


class IdentityError(Exception):
    """Sign-in could not be completed. The message is for logs, never shown to the user verbatim."""


class UpstreamRejectedError(IdentityError):
    """The upstream issuer definitively refused (inactive user, revoked session): revoke our tokens."""


class UpstreamUnavailableError(IdentityError):
    """The upstream issuer could not be reached or answered with a server error: try again later."""


@dataclass(frozen=True)
class ExternalLogin:
    """Result of an OIDC sign-in or upstream refresh."""

    principal: Principal
    refresh_token: str | None


class PasswordIdentityProvider(Protocol):
    async def verify_password(self, username: str, password: str) -> Principal | None: ...

    def lookup(self, subject: str) -> Principal | None:
        """Current identity for ``subject`` from configuration; ``None`` once the user is removed."""


class RedirectIdentityProvider(Protocol):
    async def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str: ...

    async def complete(self, code: str, code_verifier: str, nonce: str) -> ExternalLogin: ...

    async def refresh(self, refresh_token: str) -> ExternalLogin: ...
