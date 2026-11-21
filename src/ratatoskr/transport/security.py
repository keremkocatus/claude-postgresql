"""SDK settings derived from ``server.public_url``: OAuth metadata and DNS-rebinding protection."""

from __future__ import annotations

from urllib.parse import urlsplit

from mcp.server.auth.settings import AuthSettings as McpAuthSettings
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl

from ratatoskr.auth.oauth_server import DEFAULT_SCOPES, MCP_PATH


def mcp_auth_settings(public_url: str) -> McpAuthSettings:
    """Issuer is the public origin; tokens are bound (RFC 8707) to ``<public_url>/mcp``."""
    return McpAuthSettings(
        issuer_url=AnyHttpUrl(public_url),
        resource_server_url=AnyHttpUrl(public_url + MCP_PATH),
        client_registration_options=ClientRegistrationOptions(enabled=True, default_scopes=list(DEFAULT_SCOPES)),
        revocation_options=RevocationOptions(enabled=True),
        validate_token_resource=True,
    )


def transport_security(public_url: str) -> TransportSecuritySettings:
    """Only requests whose Host (and Origin, when present) name the public URL reach the MCP endpoint."""
    parts = urlsplit(public_url)
    hostname = parts.hostname or ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[host, f"{host}:*"],
        allowed_origins=[f"{parts.scheme}://{host}", f"{parts.scheme}://{host}:*"],
    )
