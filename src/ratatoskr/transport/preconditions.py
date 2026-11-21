"""Refuse to serve streamable-http unless it is authenticated and behind https (spec §4, §5.4).

``serve`` and ``check-config`` both call :func:`check_http_preconditions`, so a config that one accepts the other
accepts too. Messages name the offending setting but never contain a secret value (key, hash, URL credentials).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pydantic import SecretStr

from ratatoskr.auth.crypto import secret_key_problem
from ratatoskr.auth.identity.local import LocalIdentityProvider, password_hash_weakness
from ratatoskr.config.loader import ConfigError
from ratatoskr.config.models import AuthSettings, LocalUser, RatatoskrConfig, ServerSettings
from ratatoskr.transport.client_ip import catch_all_networks

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
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


def _check_local_users(users: list[LocalUser]) -> list[str]:
    """Run the identity provider's own checks (argon2id hashes, unique non-empty names, one parameter set).

    Building ``LocalIdentityProvider`` is exactly what ``serve`` does later, so ``check-config`` cannot disagree with
    it. Its messages name users but never contain a hash. Returns the OWASP weakness warnings.
    """
    problem: str | None = None
    try:
        LocalIdentityProvider(users)
    except ValueError as exc:
        problem = str(exc)
    if problem is not None:
        raise ConfigError(problem)
    return [weakness for user in users if (weakness := password_hash_weakness(user)) is not None]


def _check_auth(auth: AuthSettings | None, *, insecure_dev: bool) -> tuple[AuthSettings, list[str]]:
    if auth is None:
        raise ConfigError("transport 'streamable-http' requires an 'auth' section; HTTP never runs unauthenticated")
    if auth.mode == "local":
        if auth.local is None or not auth.local.users:
            raise ConfigError("auth.mode 'local' requires at least one entry in auth.local.users")
        return auth, _check_local_users(auth.local.users)
    if auth.mode == "oidc":
        if auth.oidc is None:
            raise ConfigError("auth.mode 'oidc' requires the auth.oidc section")
        if auth.oidc.issuer.scheme != "https" and not insecure_dev:
            raise ConfigError("auth.oidc.issuer must use https (plain http is only possible with --insecure-dev)")
    return auth, []


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


def check_http_preconditions(config: RatatoskrConfig, *, insecure_dev: bool) -> HttpSettings:
    """Validated HTTP settings plus warnings to print and log at every start; ``ConfigError`` on any problem."""
    server = config.server
    if server.transport != "streamable-http":
        raise ConfigError("server.transport must be 'streamable-http' to serve HTTP")
    if insecure_dev and server.host not in LOOPBACK_HOSTS:
        raise ConfigError("--insecure-dev is only allowed when server.host is 127.0.0.1, localhost or ::1")
    auth, auth_warnings = _check_auth(config.auth, insecure_dev=insecure_dev)
    secret = _check_secret_key(server.secret_key)
    public_url = _check_public_url(server, insecure_dev=insecure_dev)

    warnings: list[str] = [INSECURE_DEV_WARNING] if insecure_dev else []
    warnings.extend(auth_warnings)
    for entry in catch_all_networks(server.trusted_proxies):
        warnings.append(
            f"server.trusted_proxies contains {entry}: every peer is trusted, so any client can choose its own IP"
            " with X-Forwarded-For and evade per-IP rate limits; list only your reverse proxies"
        )
    return HttpSettings(public_url=public_url, secret_key=secret, auth=auth, warnings=tuple(warnings))
