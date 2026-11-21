"""Refuse to serve streamable-http unless it is authenticated and behind https (spec §4, §5.4).

``serve`` and ``check-config`` both call :func:`check_http_preconditions`, so a config that one accepts the other
accepts too. Messages name the offending setting but never contain a secret value (key, hash, URL credentials).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from pydantic import SecretStr

from ratatoskr.auth.crypto import secret_key_problem
from ratatoskr.auth.identity.local import LocalIdentityProvider, password_hash_weakness
from ratatoskr.config.loader import ConfigError
from ratatoskr.config.models import LOOPBACK_HOSTS, AuthSettings, LocalUser, RatatoskrConfig, ServerSettings
from ratatoskr.config.notices import config_warnings
from ratatoskr.transport.client_ip import catch_all_networks

INSECURE_DEV_WARNING = (
    "INSECURE DEV MODE (--insecure-dev): https is not enforced. Use only for local development on this machine."
)


@dataclass(frozen=True)
class HttpSettings:
    """Validated values the HTTP server needs, with the optional fields narrowed."""

    public_url: str
    secret_key: str = field(repr=False)
    auth: AuthSettings
    warnings: tuple[str, ...]
    # The provider built while checking local users; ``build_http_app`` reuses it instead of building another one.
    local_provider: LocalIdentityProvider | None = field(default=None, repr=False)


def _check_local_users(users: list[LocalUser]) -> tuple[LocalIdentityProvider, list[str]]:
    """Run the identity provider's own checks (argon2id hashes, unique non-empty names, one parameter set).

    Building ``LocalIdentityProvider`` is exactly what ``serve`` does later, so ``check-config`` cannot disagree with
    it. Its messages name users but never contain a hash. Returns the provider and the OWASP weakness warnings.
    """
    provider: LocalIdentityProvider | None = None
    problem = "auth.local users could not be checked"
    try:
        provider = LocalIdentityProvider(users)
    except ValueError as exc:
        problem = str(exc)
    if provider is None:
        raise ConfigError(problem)
    return provider, [weakness for user in users if (weakness := password_hash_weakness(user)) is not None]


def _check_auth(
    auth: AuthSettings | None, *, insecure_dev: bool
) -> tuple[AuthSettings, LocalIdentityProvider | None, list[str]]:
    if auth is None:
        raise ConfigError("transport 'streamable-http' requires an 'auth' section; HTTP never runs unauthenticated")
    if auth.mode == "local":
        if auth.local is None or not auth.local.users:
            raise ConfigError("auth.mode 'local' requires at least one entry in auth.local.users")
        provider, warnings = _check_local_users(auth.local.users)
        return auth, provider, warnings
    if auth.mode == "oidc":
        if auth.oidc is None:
            raise ConfigError("auth.mode 'oidc' requires the auth.oidc section")
        if auth.oidc.issuer.scheme != "https" and not insecure_dev:
            raise ConfigError("auth.oidc.issuer must use https (plain http is only possible with --insecure-dev)")
    return auth, None, []


def _check_secret_key(secret_key: SecretStr | None) -> str:
    if secret_key is None:
        raise ConfigError("server.secret_key is required for transport 'streamable-http'")
    secret = secret_key.get_secret_value()
    problem = secret_key_problem(secret)
    if problem is not None:
        raise ConfigError(problem)
    return secret


def _check_public_url(server: ServerSettings, *, insecure_dev: bool) -> str:
    url = server.public_url
    if url is None:
        raise ConfigError("server.public_url is required for transport 'streamable-http'")
    if url.username or url.password:
        raise ConfigError("server.public_url must not contain credentials")
    if url.path not in (None, "", "/") or url.query or url.fragment:
        raise ConfigError("server.public_url must be an origin such as https://mcp.example.com (no path or query)")
    if url.scheme != "https":
        if not insecure_dev:
            raise ConfigError("server.public_url must use https (plain http is only possible with --insecure-dev)")
        if (url.host or "").strip("[]") not in LOOPBACK_HOSTS:
            raise ConfigError("--insecure-dev requires a public_url on 127.0.0.1, localhost or [::1]")
    return str(url).rstrip("/")


def _user() -> str:
    getuid = getattr(os, "getuid", None)
    return f"uid {getuid()}" if getuid is not None else "the current user"


def _check_state_path(path: Path) -> None:
    """The SQLite file's directory must exist or be creatable, and be writable by this process. Nothing is created:
    the store creates the directory when it opens."""
    path = path.absolute()
    if path.is_dir():
        raise ConfigError(f"server.state_path {path} is a directory; give the path of the SQLite file")
    directory = path.parent
    existing = directory
    while not existing.exists():
        if existing.parent == existing:
            break
        existing = existing.parent
    if not existing.is_dir():
        raise ConfigError(f"server.state_path: directory {directory} cannot be created ({existing} is not a directory)")
    if existing != directory and not os.access(existing, os.W_OK | os.X_OK):
        # Typically a container config checked on a host (no /data there): the advice is to check in the right place.
        raise ConfigError(
            f"server.state_path: directory {directory} does not exist and {_user()} cannot create it in {existing};"
            " the path is checked on this machine, so run check-config where `serve` runs"
            " (for the image: docker run ... ratatoskr check-config)"
        )
    if not os.access(existing, os.W_OK | os.X_OK) or (path.exists() and not os.access(path, os.R_OK | os.W_OK)):
        where = path if path.exists() and existing == directory else existing
        raise ConfigError(
            f"server.state_path: {where} is not writable by {_user()}; in the container a bind-mounted /data must be"
            " owned by uid 10001 (`chown 10001:10001` on the host directory)"
        )


def check_http_preconditions(config: RatatoskrConfig, *, insecure_dev: bool) -> HttpSettings:
    """Validated HTTP settings plus warnings to print and log at every start; ``ConfigError`` on any problem."""
    server = config.server
    if server.transport != "streamable-http":
        raise ConfigError("server.transport must be 'streamable-http' to serve HTTP")
    if insecure_dev and server.host not in LOOPBACK_HOSTS:
        raise ConfigError("--insecure-dev is only allowed when server.host is 127.0.0.1, localhost or ::1")
    auth, local_provider, auth_warnings = _check_auth(config.auth, insecure_dev=insecure_dev)
    secret = _check_secret_key(server.secret_key)
    public_url = _check_public_url(server, insecure_dev=insecure_dev)
    _check_state_path(server.state_path)

    warnings: list[str] = [INSECURE_DEV_WARNING] if insecure_dev else []
    warnings.extend(auth_warnings)
    warnings.extend(config_warnings(config))
    for entry in catch_all_networks(server.trusted_proxies):
        warnings.append(
            f"server.trusted_proxies contains {entry}: every peer is trusted, so any client can choose its own IP"
            " with X-Forwarded-For and evade per-IP rate limits; list only your reverse proxies"
        )
    return HttpSettings(
        public_url=public_url,
        secret_key=secret,
        auth=auth,
        warnings=tuple(warnings),
        local_provider=local_provider,
    )
