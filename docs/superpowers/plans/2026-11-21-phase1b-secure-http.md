# Plan 1b — Secure streamable-HTTP (OAuth AS, local + OIDC identity, state store) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `ratatoskr serve` with `transport: streamable-http` is a secure claude.ai custom connector: OAuth 2.1
authorization server (DCR, code + PKCE, rotating refresh tokens with reuse detection, revocation) backed by a SQLite
state store, people signing in either with local argon2id users or through an OIDC issuer (Authentik), login pages
with CSRF/clickjacking protection and rate limiting, a persistent audit trail, health endpoints and a hardened
container image.

**Architecture:** Plan 1a's `build_app()` stays the single place where tools are registered. A new composition root,
`ratatoskr.transport.app.build_http_app()`, builds the `SqliteStore`, the `RatatoskrOAuthProvider` and the identity
provider, passes provider + MCP `AuthSettings` into `build_app()`, adds the browser routes (`/login`,
`/oauth/callback`) and `/healthz`, `/readyz` as FastMCP custom routes, enables DNS-rebinding protection for the
`public_url` host, and wraps the Starlette lifespan so the store, audit writer and cleanup task run **once per
process**. It also creates the `BackendRegistry` and injects it into `build_app(registry=...)`: by 1a's ownership
rule (whoever creates the registry closes it) the FastMCP lifespan — which the SDK enters once per MCP session —
then never closes it, and the process-level Starlette lifespan closes it exactly once at shutdown.
`TokenPrincipalResolver` turns the bearer token of the *current HTTP request* into a `Principal`, so 1a's
`ToolRuntime` and `Policy` work unchanged.

**Tech Stack:** Python 3.12, mcp 1.30 (FastMCP, `mcp.server.auth`), Starlette 1.10, uvicorn, aiosqlite 0.22 (WAL),
argon2-cffi 25.1, cryptography (AES-GCM, HKDF), joserfc 1.8 (JWT/JWKS; typed, replaces the deprecated
`authlib.jose`), httpx 0.28; tests with pytest-asyncio (auto mode), respx 0.23 and an in-process
`httpx.ASGITransport` against the real Starlette app.

**Spec:** `docs/superpowers/specs/2026-11-21-multi-backend-redesign-design.md` (§5, §7, §8 health, §9 Dockerfile).
**Contract:** `docs/superpowers/plans/2026-11-21-phase1-interfaces.md`. Plan 1a is implemented before this plan.

---

## SDK facts this plan relies on (verified in `.venv/Lib/site-packages/mcp`, 1.30.0)

These were checked by reading the installed source and by running probes; do not "fix" code that depends on them.

1. **The SDK already validates** in `/authorize`: `code_challenge` present and `code_challenge_method == "S256"`
   (missing or `plain` → **302 to the client's redirect_uri with `error=invalid_request`**, not a 400), redirect_uri
   registered for the client, scope ⊆ client scope. In `/token`: client authentication, code expiry, code belongs
   to the client, redirect_uri equality, **PKCE verifier**, refresh-token expiry, refresh scope narrowing. The
   provider therefore does *not* re-verify PKCE; it adds the redirect-host allowlist, the S256 challenge shape,
   RFC 8707 resource binding, single-use codes, hashing, rotation/reuse detection and revocation.
2. The token and revocation handlers compare `client_secret` **in plaintext** against `get_client()`. Client
   secrets therefore cannot be stored as hashes; they are sealed with AES-GCM under a key derived from
   `server.secret_key`.
3. `load_refresh_token` is called before `exchange_refresh_token`, and `/revoke` calls `load_access_token` then
   `load_refresh_token`. Reuse detection lives in `load_refresh_token` (an already-used refresh token revokes the
   family) and again in the atomic `rotate_refresh` (two concurrent refreshes with the same token).
4. `RevocationRequest.client_secret` is a required field (`str | None` without default): `/revoke` must always send
   a `client_secret` form field.
5. **Streamable-HTTP enters the FastMCP lifespan once per MCP session** (`Server.run` →
   `AsyncExitStack.enter_async_context(self.lifespan(self))`). The Starlette app's own lifespan is only
   `session_manager.run()`. Process-wide resources therefore live in the Starlette lifespan that
   `build_http_app` installs (through the public `app.router.lifespan_context` attribute), and the backend registry
   is injected into `build_app` so that the per-session FastMCP lifespan never closes it.
6. **`get_access_token()` is stale inside a session.** Its context variable is captured when the session task
   starts; after a refresh it still returns the session's *first* token (probe: request token `vAlqrr…`,
   `get_access_token()` → `t1MNeL…`). The current token is on the request the SDK attaches to every message:
   `request_ctx.get().request.scope["user"].access_token`. `TokenPrincipalResolver` uses that.
7. DNS-rebinding protection (`TransportSecuritySettings`) is applied **only to the `/mcp` endpoint**, after the
   bearer check: a wrong `Host` without a token gets 401, with a valid token 421; a foreign `Origin` gets 403.
   FastMCP auto-enables it only when constructed with a loopback host, so it is set explicitly.
8. With `resource_server_url` set and `validate_token_resource` unset the SDK emits a `DeprecationWarning`; this
   plan sets it to `True` and stores `resource = <public_url>/mcp` on every token.
9. Streamable-HTTP session ownership is `(client_id, iss claim, subject)`: `AccessToken.subject` is set so a
   refreshed token keeps using the same session.
10. `uvicorn` defaults to `proxy_headers=True` with `forwarded_allow_ips=127.0.0.1`; Ratatoskr disables it and
    applies `server.trusted_proxies` itself. `aiosqlite` logs every statement *with parameters* at DEBUG.

## Contract additions made by this plan

- `ServerSettings.trusted_proxies: list[str] = []` — IPs/CIDRs whose `X-Forwarded-For` is honoured.
- `ServerSettings.audit_retention: timedelta = 90 days` — parsed with `parse_duration`.
- HTTP preconditions (in `transport/preconditions.py`, enforced at `serve` time): `server.secret_key` ≥ 32
  characters; `server.public_url` must be an origin without path (the MCP endpoint is `<public_url>/mcp`).
- `ratatoskr.auth.tokens.RatatoskrAccessToken(AccessToken)` with `subject: str`, `display_name: str`,
  `groups: list[str]`, `auth_source: Literal["local", "oidc"]`; plus `RatatoskrRefreshToken(RefreshToken)` that also
  carries `family_id`.
- `ratatoskr.auth.resolver.TokenPrincipalResolver()` — no constructor arguments.
- Auth audit events reuse `AuditEvent` with `tool` = event name (`login_succeeded`, `login_failed`,
  `login_rate_limited`, `token_reuse_detected`, `token_revoked`, `upstream_refresh_failed`) and `connection=None`.
- Fixed paths: `/login`, `/oauth/callback`, `/healthz`, `/readyz`; OAuth scope `mcp` (default).
- `build_app()` is called with 1a's `registry: BackendRegistry | None = None` keyword (1a Task 17): the HTTP app
  passes its own registry and closes it in the process-level lifespan; 1a's `app.py` is not modified by this plan.
- `build_http_app(config, *, insecure_dev=False, clock=time.time, registry=None) -> HttpApp(asgi, store, provider,
  registry)`; `registry` exists for tests. No private SDK attribute is used anywhere in this plan.
- Uses 1a's `load_config(path, env=None, *, insecure_dev=False)` (a 1a addition) only through the CLI.

---

## File Structure

**Created — source (`src/ratatoskr/`)**

| File | Responsibility |
|---|---|
| `state/__init__.py` | package marker |
| `state/records.py` | frozen dataclasses exchanged with the store; `Clock` alias |
| `state/store.py` | `Store` protocol (clock-free; hashes only) |
| `state/migrations.py` | ordered schema migrations (v1 = spec §7 tables) |
| `state/sqlite.py` | `SqliteStore`: aiosqlite, WAL, `synchronous=NORMAL`, one connection + lock, migrations |
| `state/audit.py` | `SqliteAuditSink`: non-blocking queue, batches of 100 / every 1 s, drained on close |
| `state/maintenance.py` | `CleanupTask`: hourly purge of expired rows and old audit events |
| `auth/crypto.py` | opaque tokens, SHA-256 hashing, PKCE S256, HKDF keys, AES-GCM `Sealer`, HMAC `Signer`, `Keyring` |
| `auth/tokens.py` | `RatatoskrAccessToken`, `RatatoskrRefreshToken` |
| `auth/redirects.py` | DCR redirect-URI allowlist check |
| `auth/events.py` | helper that records auth events as `AuditEvent`s |
| `auth/ratelimit.py` | sliding window + exponential lockout persisted in the store; login and DCR rules |
| `auth/identity/__init__.py` | package marker |
| `auth/identity/base.py` | identity errors, `ExternalLogin`, provider protocols |
| `auth/identity/local.py` | argon2id local users; constant-cost unknown-user path; `hash_password` |
| `auth/identity/oidc.py` | OIDC RP: discovery, PKCE/state/nonce, JWKS ID-token validation, upstream refresh |
| `auth/oauth_server.py` | `RatatoskrOAuthProvider` (`OAuthAuthorizationServerProvider` on the store) |
| `auth/csrf.py` | signed double-submit CSRF token bound to the pending request |
| `auth/pages.py` | login / message HTML and security headers (CSP with style hash, nosniff, no-referrer) |
| `auth/web.py` | `/login` (GET form or OIDC redirect, POST verify) and `/oauth/callback` routes |
| `auth/password_cli.py` | `ratatoskr hash-password` implementation |
| `observability/health.py` | `/healthz`, `/readyz` |
| `transport/__init__.py` | package marker |
| `transport/client_ip.py` | client IP with trusted-proxy `X-Forwarded-For` handling |
| `transport/preconditions.py` | refuse HTTP without auth / https / secret; `--insecure-dev` rules |
| `transport/security.py` | MCP `AuthSettings` and `TransportSecuritySettings` from `public_url` |
| `transport/register_limit.py` | per-IP rate limit middleware for `POST /register` |
| `transport/app.py` | `build_http_app()` composition root → `HttpApp(asgi, store, provider)` |
| `transport/serve.py` | `serve_http()` under uvicorn |

**Created — tests (`tests/unit/secure_http/` and `e2e/`, each with an empty `__init__.py` like 1a's test packages)**

| File | Covers |
|---|---|
| `conftest.py` | clock, audit recorder, store, config factory, password hash, fake OIDC issuer (RSA + JWKS via respx) |
| `test_config_http_settings.py` | new `ServerSettings` fields |
| `test_auth_crypto.py` | hashing, PKCE, HKDF, AES-GCM, HMAC |
| `test_state_sqlite.py` | migrations, WAL, every store method, rotation/reuse, cleanup |
| `test_state_audit_sink.py` | batching, interval flush, drain on close, never raises; cleanup task |
| `test_auth_redirects.py` | redirect allowlist |
| `test_auth_ratelimit.py` | window, lockout growth and cap, persistence |
| `test_token_resolver.py` | current-request token wins over stale context |
| `test_identity_local.py` | argon2id, unknown user path, `hash-password` |
| `test_identity_oidc.py` | fake issuer: discovery, claims, signatures, key rotation, refresh, outages |
| `test_oauth_provider.py` | DCR, authorize, single-use codes, token lifecycle, reuse, revoke, upstream re-validation |
| `test_auth_csrf.py` | CSRF token/cookie |
| `test_auth_pages.py` | escaping, CSP/headers |
| `test_transport_settings.py` | client IP, preconditions, SDK settings |
| `e2e/conftest.py` | `OAuthDriver` (plays claude.ai) and `run_app` |
| `e2e/test_http_registry_lifecycle.py` | injected registry survives ended sessions, closed once at shutdown |
| `e2e/test_http_local_flow.py` | DCR → authorize → login → token → `list_connections` → refresh → revoke; audit; logs |
| `e2e/test_http_security.py` | redirect allowlist, PKCE, CSRF, 401, DNS rebinding, rate limits |
| `e2e/test_http_oidc_flow.py` | OIDC login, group refresh, offboarding, callback attacks |
| `test_cli_http.py` | `hash-password` and `serve` dispatch |

**Created — other:** `Dockerfile` (rewritten), `.dockerignore`, `docs/authentik.md`.

**Modified (Plan 1a files):** `pyproject.toml` (dependencies), `src/ratatoskr/config/models.py` (`ServerSettings`
fields), `src/ratatoskr/auth/resolver.py` (adds `TokenPrincipalResolver`), `src/ratatoskr/cli.py` (`serve` HTTP
branch, `hash-password`), `tests/unit/test_cli.py` (drops `test_serve_refuses_http_transport_for_now`).

**Repo rules for every task:** ruff (line length 120), `mypy --strict` clean for `src`, Python 3.12 typing, small
single-purpose modules, no secrets in logs, never commit with failing tests. Do not touch files of other plans
beyond the modifications listed above; do not connect to any real identity provider or database.

---

### Task 0: Preflight — confirm Plan 1a is in place

**Files:** none (read-only checks).

- [ ] **Step 1: Suite is green before starting**

Run: `.venv/Scripts/python -m pytest tests/unit -q && .venv/Scripts/python -m ruff check src tests && .venv/Scripts/python -m mypy src`
Expected: all pass.

- [ ] **Step 2: Contract objects exist with the shapes this plan uses**

Run:

```bash
.venv/Scripts/python - <<'PY'
import inspect
from ratatoskr.app import build_app
from ratatoskr.cli import EXIT_CONFIG_ERROR, build_parser, main
from ratatoskr.config.loader import load_config
from ratatoskr.observability.audit import CompositeAuditSink, LogAuditSink
print(inspect.signature(build_app))
print(inspect.signature(load_config))
LogAuditSink()
CompositeAuditSink([LogAuditSink()])
src = inspect.getsource(build_app)
assert "auth_server_provider=auth_server_provider" in src and "auth=auth_settings" in src
assert "registry" in inspect.signature(build_app).parameters, "1a Task 17 adds build_app(registry=...)"
assert "owns_registry" in src, "an injected registry must not be closed by build_app's lifespan"
PY
grep -n 'asyncio_mode' pyproject.toml
ls tests/unit/__init__.py tests/unit/test_cli.py
```

Expected: `build_app(config, *, resolver, audit, auth_server_provider=None, auth_settings=None, registry=None)`;
`load_config(path, env=None, *, insecure_dev=False)`; both sink constructors succeed; the assertions hold;
`asyncio_mode = "auto"`; both test files exist (1a's tests are a package, so the new test directories get
`__init__.py` too). If a shape differs, adapt the single call site named in the failing task and record it in that
task's commit message.

---

### Task 1: Dependencies, new server settings, test fixtures

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/ratatoskr/config/models.py` (class `ServerSettings`)
- Create: `tests/unit/secure_http/__init__.py` (empty), `tests/unit/secure_http/conftest.py`
- Test: `tests/unit/secure_http/test_config_http_settings.py`

- [ ] **Step 1: Add dependencies to `pyproject.toml`**

Append to `[project] dependencies` (keep the entries 1a already has):

```toml
    "aiosqlite>=0.22",
    "argon2-cffi>=25.1",
    "cryptography>=45",
    "httpx>=0.28",
    "joserfc>=1.8",
    "python-multipart>=0.0.20",
    "starlette>=1.0",
    "uvicorn>=0.30",
```

Append to the `dev` extra under `[project.optional-dependencies]`:

```toml
    "respx>=0.23",
```

- [ ] **Step 2: Install**

Run: `.venv/Scripts/python -m pip install --index-url https://pypi.org/simple -e ".[dev]"`
Expected: `Successfully installed ratatoskr-mcp-…` (the libraries are already present; this records them).

- [ ] **Step 3: Write the fixtures**

Create the empty package marker `tests/unit/secure_http/__init__.py`, then `tests/unit/secure_http/conftest.py` (project modules are imported lazily so the file can exist before them):

```python
"""Fixtures for the Plan 1b (secure HTTP) unit tests.

Project modules are imported inside the fixtures so that this file can exist before the modules it serves.
"""

from __future__ import annotations

import ssl
import time
from collections.abc import AsyncIterator, Callable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from joserfc import jwt
from joserfc.jwk import KeySet, RSAKey

from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import AuditEvent

if TYPE_CHECKING:
    from ratatoskr.state.sqlite import SqliteStore

PASSWORD = "correct horse battery staple"
SECRET_KEY = "k" * 48
ISSUER = "https://idp.example.com/application/o/mcp/"
IDP_BASE = "https://idp.example.com/application/o/"
OIDC_CLIENT_ID = "ratatoskr"


class FakeClock:
    def __init__(self, start: float | None = None) -> None:
        self.now = time.time() if start is None else start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class RecordingAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)

    def names(self) -> list[str]:
        return [e.tool for e in self.events]


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def audit() -> RecordingAudit:
    return RecordingAudit()


@pytest.fixture(scope="session")
def password_hash() -> str:
    from ratatoskr.auth.identity.local import hash_password

    return hash_password(PASSWORD)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[SqliteStore]:
    from ratatoskr.state.sqlite import SqliteStore

    s = SqliteStore(tmp_path / "state.db")
    await s.open()
    yield s
    await s.close()


@pytest.fixture
def make_config(tmp_path: Path, password_hash: str) -> Callable[..., RatatoskrConfig]:
    """Valid streamable-http config. Invalid variants are made with ``model_copy`` so that they bypass
    whatever model-level validation Plan 1a added and reach the code under test."""

    def factory(
        *,
        mode: str = "local",
        public_url: str = "https://mcp.example.com",
        host: str = "0.0.0.0",
        server_extra: dict[str, Any] | None = None,
        auth_extra: dict[str, Any] | None = None,
    ) -> RatatoskrConfig:
        auth: dict[str, Any] = {"mode": mode, **(auth_extra or {})}
        if mode == "local":
            auth["local"] = {
                "users": [
                    {"username": "kerem", "password_hash": password_hash, "groups": ["admins"]},
                    {"username": "ayse", "password_hash": password_hash, "groups": ["analyst"]},
                ]
            }
        else:
            auth["oidc"] = {"issuer": ISSUER, "client_id": OIDC_CLIENT_ID, "client_secret": "upstream-secret"}
        server: dict[str, Any] = {
            "transport": "streamable-http",
            "public_url": public_url,
            "host": host,
            "state_path": str(tmp_path / "state.db"),
            "secret_key": SECRET_KEY,
            **(server_extra or {}),
        }
        return RatatoskrConfig.model_validate(
            {
                "server": server,
                "auth": auth,
                "roles": {"admins": {"*": "write"}, "analyst": {"prod-pg": "read"}},
                "connections": {
                    "prod-pg": {"kind": "postgres", "dsn": "postgresql://u:p@127.0.0.1:1/db", "mode": "read"},
                    "staging-pg": {"kind": "postgres", "dsn": "postgresql://u:p@127.0.0.1:1/db", "mode": "write"},
                },
            }
        )

    return factory


# ── fake OIDC issuer: local RSA key, discovery/JWKS/token/userinfo served through respx ──


class FakeIssuer:
    issuer = ISSUER
    authorization_endpoint = IDP_BASE + "authorize/"
    token_endpoint = IDP_BASE + "token/"
    userinfo_endpoint = IDP_BASE + "userinfo/"
    jwks_uri = ISSUER + "jwks/"

    def __init__(self, key: RSAKey, clock: FakeClock) -> None:
        self.key = key
        self.clock = clock
        self.jwks: dict[str, Any] = dict(KeySet([key]).as_dict(private=False))
        self.discovery: dict[str, Any] = {
            "issuer": self.issuer,
            "authorization_endpoint": self.authorization_endpoint,
            "token_endpoint": self.token_endpoint,
            "userinfo_endpoint": self.userinfo_endpoint,
            "jwks_uri": self.jwks_uri,
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        self.token_responses: list[httpx.Response] = []
        self.token_requests: list[httpx.Request] = []
        self.userinfo: dict[str, Any] = {}
        self.jwks_fetches = 0

    def id_token(self, *, key: RSAKey | None = None, header: dict[str, Any] | None = None, **overrides: Any) -> str:
        now = int(self.clock())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": OIDC_CLIENT_ID,
            "sub": "a1b2c3",
            "email": "alice@example.com",
            "name": "Alice Example",
            "groups": ["devops"],
            "iat": now,
            "exp": now + 300,
        }
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        signing_key = key or self.key
        return jwt.encode(header or {"alg": "RS256", "kid": signing_key.kid}, claims, signing_key)

    def queue_token_response(self, status: int = 200, **body: Any) -> None:
        self.token_responses.append(httpx.Response(status, json=body))

    def form(self, index: int = -1) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(self.token_requests[index].content.decode()).items()}

    def _token(self, request: httpx.Request) -> httpx.Response:
        self.token_requests.append(request)
        if not self.token_responses:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return self.token_responses.pop(0)

    def _jwks(self, request: httpx.Request) -> httpx.Response:
        self.jwks_fetches += 1
        return httpx.Response(200, json=self.jwks)

    def install(self, router: respx.Router) -> None:
        self.router = router
        router.get(self.issuer + ".well-known/openid-configuration").mock(
            side_effect=lambda request: httpx.Response(200, json=self.discovery)
        )
        router.get(self.jwks_uri).mock(side_effect=self._jwks)
        router.post(self.token_endpoint).mock(side_effect=self._token)
        router.get(self.userinfo_endpoint).mock(side_effect=lambda request: httpx.Response(200, json=self.userinfo))


@pytest.fixture(scope="session")
def tls_context() -> ssl.SSLContext:
    """Shared TLS context: httpx would otherwise load the CA bundle (~0.5 s) for every client."""
    return ssl.create_default_context()


@pytest.fixture(scope="session")
def rsa_key() -> RSAKey:
    return RSAKey.generate_key(2048, parameters={"kid": "key-1", "alg": "RS256", "use": "sig"})


@pytest.fixture(scope="session")
def other_rsa_key() -> RSAKey:
    return RSAKey.generate_key(2048, parameters={"kid": "key-2", "alg": "RS256", "use": "sig"})


@pytest.fixture
def fake_issuer(rsa_key: RSAKey, clock: FakeClock) -> Iterator[FakeIssuer]:
    """Every outbound httpx request is mocked; an unmatched one fails the test instead of reaching the network."""
    issuer = FakeIssuer(rsa_key, clock)
    with respx.mock(assert_all_called=False) as router:
        issuer.install(router)
        yield issuer
```

- [ ] **Step 4: Write the failing test**

```python
from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError

from ratatoskr.config.models import ServerSettings


def test_defaults() -> None:
    settings = ServerSettings()
    assert settings.trusted_proxies == []
    assert settings.audit_retention == timedelta(days=90)


def test_audit_retention_accepts_duration_strings() -> None:
    assert ServerSettings.model_validate({"audit_retention": "30d"}).audit_retention == timedelta(days=30)
    assert ServerSettings.model_validate({"audit_retention": 3600}).audit_retention == timedelta(hours=1)


def test_trusted_proxies_accept_addresses_and_networks() -> None:
    settings = ServerSettings.model_validate({"trusted_proxies": ["10.0.0.0/8", "172.18.0.2", "fd00::/8"]})
    assert settings.trusted_proxies == ["10.0.0.0/8", "172.18.0.2", "fd00::/8"]


def test_invalid_trusted_proxy_is_a_config_error() -> None:
    with pytest.raises(ValidationError, match="trusted_proxies"):
        ServerSettings.model_validate({"trusted_proxies": ["caddy"]})
```

- [ ] **Step 5: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_config_http_settings.py -q`
Expected: FAIL — `AttributeError: 'ServerSettings' object has no attribute 'trusted_proxies'` (or a pydantic
`extra_forbidden` error for the new keys).

- [ ] **Step 6: Add the fields**

In `src/ratatoskr/config/models.py` add `import ipaddress` to the imports and replace `ServerSettings` with the
class below: 1a's fields and `_check_log_level` unchanged, two fields and two validators added. `_duration` is 1a's
module-level helper in the same file (it wraps `parse_duration`).

```python
class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transport: Literal["stdio", "streamable-http"] = "stdio"
    public_url: AnyHttpUrl | None = None
    host: str = "127.0.0.1"
    port: int = 8000
    metrics_port: int | None = None
    state_path: Path = Path("/data/state.db")
    secret_key: SecretStr | None = None
    allowed_redirect_hosts: list[str] = ["claude.ai", "claude.com", "localhost", "127.0.0.1"]
    stdio_role: str | None = None
    log_level: str = "INFO"
    trusted_proxies: list[str] = []
    """Proxy IPs/CIDRs whose X-Forwarded-For is trusted for client IPs (rate limiting). Empty: never trusted."""
    audit_retention: timedelta = timedelta(days=90)

    @field_validator("log_level")
    @classmethod
    def _check_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in _LOG_LEVELS:
            raise ValueError(f"log_level must be one of {sorted(_LOG_LEVELS)}")
        return level

    @field_validator("audit_retention", mode="before")
    @classmethod
    def _parse_audit_retention(cls, value: Any) -> timedelta:
        return _duration(value)

    @field_validator("trusted_proxies")
    @classmethod
    def _check_trusted_proxies(cls, value: list[str]) -> list[str]:
        for entry in value:
            ipaddress.ip_network(entry, strict=False)
        return value
```

- [ ] **Step 7: Run tests, lint, types**

Run: `.venv/Scripts/python -m pytest tests/unit -q && .venv/Scripts/python -m ruff check --fix src tests && .venv/Scripts/python -m mypy src`
Expected: PASS (whole unit suite, including 1a's config tests).

- [ ] **Step 8: Commit**

```bash
git add pyproject.toml src/ratatoskr/config/models.py tests/unit/secure_http/__init__.py tests/unit/secure_http/conftest.py tests/unit/secure_http/test_config_http_settings.py
git commit -m "Add secure-HTTP dependencies, trusted_proxies and audit_retention settings" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: Token hashing and keys derived from `server.secret_key`

**Files:**
- Create: `src/ratatoskr/auth/crypto.py`
- Test: `tests/unit/secure_http/test_auth_crypto.py`

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import base64
import hashlib

import pytest

from ratatoskr.auth.crypto import (
    DecryptionError,
    Keyring,
    Sealer,
    Signer,
    derive_key,
    hash_token,
    new_token,
    pkce_challenge,
)


def test_new_token_is_32_random_bytes() -> None:
    tokens = {new_token() for _ in range(50)}
    assert len(tokens) == 50
    assert all(len(base64.urlsafe_b64decode(t + "=")) == 32 for t in tokens)


def test_hash_token_is_sha256_hex() -> None:
    assert hash_token("abc") == hashlib.sha256(b"abc").hexdigest()


def test_pkce_challenge_matches_rfc7636_example() -> None:
    assert (
        pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_derived_keys_differ_per_purpose_and_secret() -> None:
    assert derive_key("s" * 32, "a") != derive_key("s" * 32, "b")
    assert derive_key("s" * 32, "a") != derive_key("t" * 32, "a")
    assert len(derive_key("s" * 32, "a")) == 32


def test_sealer_roundtrip_uses_fresh_nonce() -> None:
    sealer = Sealer(derive_key("s" * 32, "x"))
    one, two = sealer.seal("upstream-refresh", aad="alice"), sealer.seal("upstream-refresh", aad="alice")
    assert one != two
    assert b"upstream-refresh" not in one
    assert sealer.open(one, aad="alice") == "upstream-refresh"


def test_sealer_rejects_wrong_aad_wrong_key_and_tampering() -> None:
    sealer = Sealer(derive_key("s" * 32, "x"))
    blob = sealer.seal("secret", aad="alice")
    with pytest.raises(DecryptionError):
        sealer.open(blob, aad="bob")
    with pytest.raises(DecryptionError):
        Sealer(derive_key("other-secret" * 3, "x")).open(blob, aad="alice")
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])
    with pytest.raises(DecryptionError):
        sealer.open(tampered, aad="alice")
    with pytest.raises(DecryptionError):
        sealer.open(b"short", aad="alice")


def test_signer_verifies_only_its_own_signatures() -> None:
    signer = Signer(derive_key("s" * 32, "csrf"))
    sig = signer.sign("message")
    assert signer.verify("message", sig)
    assert not signer.verify("other", sig)
    assert not Signer(derive_key("s" * 32, "flow")).verify("message", sig)


def test_keyring_keys_are_independent() -> None:
    ring = Keyring("s" * 32)
    blob = ring.upstream.seal("x", aad="a")
    with pytest.raises(DecryptionError):
        ring.client_secrets.open(blob, aad="a")
    assert not ring.oidc_flow.verify("m", ring.csrf.sign("m"))
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_auth_crypto.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.auth.crypto'`.

- [ ] **Step 3: Implement**

```python
"""Token hashing, opaque token generation and keys derived from ``server.secret_key``."""

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_BYTES = 12


class DecryptionError(Exception):
    """Ciphertext was tampered with or sealed under a different key."""


def new_token() -> str:
    """Opaque 32-byte random token, URL-safe base64 (43 characters)."""
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    """SHA-256 hex digest; the only form in which tokens and codes are stored."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def pkce_challenge(verifier: str) -> str:
    """RFC 7636 S256 code challenge for ``verifier``."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def derive_key(secret_key: str, purpose: str) -> bytes:
    """32-byte key for ``purpose``, derived with HKDF-SHA256 so every use gets an independent key."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=f"ratatoskr/{purpose}/v1".encode())
    return hkdf.derive(secret_key.encode("utf-8"))


class Sealer:
    """AES-256-GCM with a random 96-bit nonce; output is ``nonce || ciphertext+tag``."""

    def __init__(self, key: bytes) -> None:
        self._aead = AESGCM(key)

    def seal(self, plaintext: str, aad: str) -> bytes:
        nonce = os.urandom(_NONCE_BYTES)
        return nonce + self._aead.encrypt(nonce, plaintext.encode("utf-8"), aad.encode("utf-8"))

    def open(self, blob: bytes, aad: str) -> str:
        if len(blob) <= _NONCE_BYTES:
            raise DecryptionError("ciphertext too short")
        try:
            plain = self._aead.decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], aad.encode("utf-8"))
        except InvalidTag as exc:
            raise DecryptionError("ciphertext failed authentication") from exc
        return plain.decode("utf-8")


class Signer:
    """HMAC-SHA256 signatures, URL-safe base64 without padding."""

    def __init__(self, key: bytes) -> None:
        self._key = key

    def sign(self, message: str) -> str:
        mac = hmac.new(self._key, message.encode("utf-8"), hashlib.sha256).digest()
        return base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")

    def verify(self, message: str, signature: str) -> bool:
        return hmac.compare_digest(self.sign(message), signature)


class Keyring:
    """All keys the server derives from ``server.secret_key``."""

    def __init__(self, secret_key: str) -> None:
        self.upstream = Sealer(derive_key(secret_key, "upstream-refresh-token"))
        self.client_secrets = Sealer(derive_key(secret_key, "client-secret"))
        self.csrf = Signer(derive_key(secret_key, "csrf"))
        self.oidc_flow = Signer(derive_key(secret_key, "oidc-flow"))
```

- [ ] **Step 4: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_auth_crypto.py -q && .venv/Scripts/python -m mypy src`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/auth/crypto.py tests/unit/secure_http/test_auth_crypto.py
git commit -m "Add token hashing, PKCE and secret-key derived AES-GCM/HMAC keys" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: SQLite state store

**Files:**
- Create: `src/ratatoskr/state/__init__.py`, `src/ratatoskr/state/records.py`, `src/ratatoskr/state/store.py`,
  `src/ratatoskr/state/migrations.py`, `src/ratatoskr/state/sqlite.py`
- Test: `tests/unit/secure_http/test_state_sqlite.py`

Design notes: one aiosqlite connection (`isolation_level=None`, explicit `BEGIN IMMEDIATE`) guarded by an
`asyncio.Lock`, so multi-statement transactions never interleave; WAL + `synchronous=NORMAL`; `schema_version` plus
ordered migrations, each applied in its own transaction; a database newer than the code is refused. The store is
clock-free (callers pass `now`) and only ever sees SHA-256 hashes of tokens and codes. Refresh rotation marks the
old token used, revokes the family's older access tokens and inserts the new pair atomically; presenting a used
refresh token again revokes the whole family. Used refresh tokens are kept until they expire so reuse stays
detectable.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from ratatoskr.auth.principal import Principal
from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.migrations import MIGRATIONS
from ratatoskr.state.records import (
    AuthCodeRecord,
    PendingAuthorization,
    RateLimitState,
    StoredClient,
    TokenRecord,
)
from ratatoskr.state.sqlite import SqliteStore, StateStoreError

ALICE = Principal(subject="alice", display_name="Alice", groups=frozenset({"devops", "admins"}), auth_source="oidc")


def token(token_hash: str, kind: str = "refresh", family: str = "fam", expires_at: float = 2000.0) -> TokenRecord:
    return TokenRecord(
        token_hash=token_hash,
        kind="refresh" if kind == "refresh" else "access",
        family_id=family,
        client_id="client-1",
        scopes=("mcp",),
        resource="https://mcp.example.com/mcp",
        principal=ALICE,
        created_at=1000.0,
        expires_at=expires_at,
    )


async def test_open_applies_migrations_and_enables_wal(tmp_path: Path) -> None:
    store = SqliteStore(tmp_path / "nested" / "state.db")
    await store.open()
    try:
        assert await store.schema_version() == len(MIGRATIONS)
    finally:
        await store.close()
    with sqlite3.connect(tmp_path / "nested" / "state.db") as raw:
        assert raw.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        tables = {r[0] for r in raw.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {
        "clients",
        "pending_authorizations",
        "auth_codes",
        "tokens",
        "upstream_sessions",
        "rate_limits",
        "audit_events",
        "schema_version",
    } <= tables


async def test_reopen_is_idempotent(tmp_path: Path) -> None:
    for _ in range(2):
        store = SqliteStore(tmp_path / "state.db")
        await store.open()
        assert await store.schema_version() == len(MIGRATIONS)
        await store.close()


async def test_newer_schema_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "state.db"
    with sqlite3.connect(path) as raw:
        raw.execute("CREATE TABLE schema_version (version INTEGER NOT NULL)")
        raw.execute("INSERT INTO schema_version (version) VALUES (999)")
    store = SqliteStore(path)
    with pytest.raises(StateStoreError, match="newer"):
        await store.open()


async def test_use_before_open_fails(tmp_path: Path) -> None:
    with pytest.raises(StateStoreError, match="not open"):
        await SqliteStore(tmp_path / "x.db").get_client("c")


async def test_clients_roundtrip(store: SqliteStore) -> None:
    await store.save_client(StoredClient("c1", '{"redirect_uris": []}', b"sealed", 1.0))
    loaded = await store.get_client("c1")
    assert loaded == StoredClient("c1", '{"redirect_uris": []}', b"sealed", 1.0)
    assert await store.get_client("missing") is None


async def test_pending_take_is_single_use_and_respects_expiry(store: SqliteStore) -> None:
    await store.save_pending(PendingAuthorization("p1", "c1", "{}", expires_at=100.0, nonce="n", upstream_verifier="v"))
    assert (await store.get_pending("p1", now=50.0)) is not None
    assert await store.get_pending("p1", now=100.0) is None
    taken = await store.take_pending("p1", now=50.0)
    assert taken is not None and taken.nonce == "n" and taken.upstream_verifier == "v"
    assert await store.take_pending("p1", now=50.0) is None


async def test_expired_pending_cannot_be_taken(store: SqliteStore) -> None:
    await store.save_pending(PendingAuthorization("p2", "c1", "{}", expires_at=100.0))
    assert await store.take_pending("p2", now=101.0) is None


async def test_code_take_is_single_use(store: SqliteStore) -> None:
    await store.save_code(AuthCodeRecord("h1", "c1", "{}", ALICE, b"up", expires_at=300.0))
    got = await store.get_code("h1", now=10.0)
    assert got is not None and got.principal == ALICE and got.upstream_blob == b"up"
    assert await store.take_code("h1", now=10.0) is not None
    assert await store.take_code("h1", now=10.0) is None
    assert await store.get_code("h1", now=10.0) is None


async def test_expired_code_is_invisible(store: SqliteStore) -> None:
    await store.save_code(AuthCodeRecord("h2", "c1", "{}", ALICE, None, expires_at=300.0))
    assert await store.get_code("h2", now=300.0) is None
    assert await store.take_code("h2", now=301.0) is None


async def test_create_family_and_get_token(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=b"enc")
    access = await store.get_token("a1")
    assert access is not None and access.kind == "access" and access.principal == ALICE
    assert access.scopes == ("mcp",)
    assert await store.get_upstream("fam") == b"enc"


async def test_rotate_marks_old_used_and_revokes_old_access(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=None)
    outcome = await store.rotate_refresh("r1", token("a2", "access"), token("r2"), b"new-up", now=1500.0)
    assert outcome == "rotated"
    old = await store.get_token("r1")
    assert old is not None and old.used_at == 1500.0 and old.revoked_at is None
    old_access = await store.get_token("a1")
    assert old_access is not None and old_access.revoked_at == 1500.0
    assert (await store.get_token("r2")) is not None
    assert await store.get_upstream("fam") == b"new-up"


async def test_rotating_a_used_token_revokes_the_family(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=b"up")
    assert await store.rotate_refresh("r1", token("a2", "access"), token("r2"), None, now=1500.0) == "rotated"
    outcome = await store.rotate_refresh("r1", token("a3", "access"), token("r3"), None, now=1600.0)
    assert outcome == "reused"
    for h in ("r1", "r2", "a2"):
        rec = await store.get_token(h)
        assert rec is not None and rec.revoked_at == 1600.0
    assert await store.get_token("r3") is None


async def test_rotate_invalid_cases(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access", expires_at=1100.0), token("r1", expires_at=1100.0), None)
    assert await store.rotate_refresh("missing", token("x", "access"), token("y"), None, now=1050.0) == "invalid"
    assert await store.rotate_refresh("a1", token("x", "access"), token("y"), None, now=1050.0) == "invalid"
    assert await store.rotate_refresh("r1", token("x", "access"), token("y"), None, now=1100.0) == "invalid"
    await store.revoke_family("fam", now=1050.0)
    assert await store.rotate_refresh("r1", token("x", "access"), token("y"), None, now=1060.0) == "invalid"


async def test_revoke_family_counts_and_drops_upstream(store: SqliteStore) -> None:
    await store.create_family(token("a1", "access"), token("r1"), upstream_blob=b"up")
    assert await store.revoke_family("fam", now=1200.0) == 2
    assert await store.revoke_family("fam", now=1300.0) == 0
    assert await store.get_upstream("fam") is None


async def test_rate_limit_roundtrip(store: SqliteStore) -> None:
    state = RateLimitState(hits=(1.0, 2.5), strikes=1, blocked_until=99.0)
    await store.save_rate_limit("login:ip:1.2.3.4", state, now=3.0)
    assert await store.get_rate_limit("login:ip:1.2.3.4") == state
    await store.delete_rate_limit("login:ip:1.2.3.4")
    assert await store.get_rate_limit("login:ip:1.2.3.4") is None


def audit_event(ts: datetime) -> AuditEvent:
    return AuditEvent(
        ts=ts,
        subject="alice",
        auth_source="oidc",
        connection="prod-pg",
        tool="pg_query",
        query_text="select 1",
        query_sha256="ab",
        duration_ms=1.5,
        rows=1,
        result="ok",
        error_class=None,
    )


async def test_insert_audit_events(store: SqliteStore) -> None:
    await store.insert_audit_events([audit_event(datetime.now(UTC)) for _ in range(3)])
    await store.insert_audit_events([])
    assert await store.count_audit_events() == 3


async def test_cleanup_removes_only_expired_rows(store: SqliteStore) -> None:
    await store.save_pending(PendingAuthorization("old", "c", "{}", expires_at=10.0))
    await store.save_pending(PendingAuthorization("new", "c", "{}", expires_at=5000.0))
    await store.save_code(AuthCodeRecord("oldc", "c", "{}", ALICE, None, expires_at=10.0))
    await store.create_family(token("a1", "access", expires_at=10.0), token("r1", expires_at=5000.0), b"up")
    await store.create_family(
        token("a9", "access", family="dead", expires_at=10.0), token("r9", family="dead", expires_at=10.0), b"up"
    )
    await store.save_rate_limit("idle", RateLimitState((), 0, 0.0), now=0.0)
    await store.insert_audit_events([audit_event(datetime.fromtimestamp(5.0, UTC))])
    await store.insert_audit_events([audit_event(datetime.fromtimestamp(4000.0, UTC))])

    stats = await store.cleanup(now=1000.0, audit_cutoff=1000.0)

    assert stats.pending == 1 and stats.codes == 1
    assert stats.tokens == 3
    assert stats.upstream_sessions == 1
    assert stats.audit_events == 1
    assert await store.get_pending("new", now=0.0) is not None
    assert await store.get_token("r1") is not None
    assert await store.get_upstream("fam") == b"up"
    assert await store.get_upstream("dead") is None
    assert await store.count_audit_events() == 1


async def test_cleanup_drops_idle_rate_limits(store: SqliteStore) -> None:
    await store.save_rate_limit("idle", RateLimitState((), 0, 0.0), now=0.0)
    await store.save_rate_limit("busy", RateLimitState((), 1, 0.0), now=90_000.0)
    stats = await store.cleanup(now=90_001.0, audit_cutoff=0.0)
    assert stats.rate_limits == 1
    assert await store.get_rate_limit("busy") is not None


async def test_check_writable(store: SqliteStore) -> None:
    await store.check_writable()
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_state_sqlite.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.state'`.

- [ ] **Step 3: Implement the package marker and records**

`src/ratatoskr/state/__init__.py`:

```python
"""Persistent server state: OAuth clients, codes, tokens, rate limits and audit events."""
```

`src/ratatoskr/state/records.py`:

```python
"""Plain records exchanged between the auth layer and the state store."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from ratatoskr.auth.principal import Principal

Clock = Callable[[], float]
"""Returns the current time as epoch seconds (``time.time``); injectable for tests."""

TokenKind = Literal["access", "refresh"]
RotateOutcome = Literal["rotated", "reused", "invalid"]


@dataclass(frozen=True)
class StoredClient:
    client_id: str
    metadata_json: str
    secret_blob: bytes | None
    created_at: float


@dataclass(frozen=True)
class PendingAuthorization:
    id: str
    client_id: str
    params_json: str
    expires_at: float
    nonce: str | None = None
    upstream_verifier: str | None = None


@dataclass(frozen=True)
class AuthCodeRecord:
    code_hash: str
    client_id: str
    params_json: str
    principal: Principal
    upstream_blob: bytes | None
    expires_at: float


@dataclass(frozen=True)
class TokenRecord:
    token_hash: str
    kind: TokenKind
    family_id: str
    client_id: str
    scopes: tuple[str, ...]
    resource: str | None
    principal: Principal
    created_at: float
    expires_at: float
    used_at: float | None = None
    revoked_at: float | None = None


@dataclass(frozen=True)
class RateLimitState:
    hits: tuple[float, ...]
    strikes: int
    blocked_until: float


@dataclass(frozen=True)
class CleanupStats:
    pending: int
    codes: int
    tokens: int
    upstream_sessions: int
    rate_limits: int
    audit_events: int
```

- [ ] **Step 4: Implement the protocol**

`src/ratatoskr/state/store.py`:

```python
"""Store protocol: the only persistence boundary of the auth layer.

Every method takes ``now`` explicitly where time matters, so implementations stay clock-free.
Raw tokens and codes never reach the store; callers pass SHA-256 hashes (``auth.crypto.hash_token``).
"""

from collections.abc import Sequence
from typing import Protocol

from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.records import (
    AuthCodeRecord,
    CleanupStats,
    PendingAuthorization,
    RateLimitState,
    RotateOutcome,
    StoredClient,
    TokenRecord,
)


class Store(Protocol):
    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def check_writable(self) -> None:
        """Raise if the store cannot persist a write (used by ``/readyz``)."""

    async def save_client(self, client: StoredClient) -> None: ...

    async def get_client(self, client_id: str) -> StoredClient | None: ...

    async def save_pending(self, pending: PendingAuthorization) -> None: ...

    async def get_pending(self, pending_id: str, now: float) -> PendingAuthorization | None: ...

    async def take_pending(self, pending_id: str, now: float) -> PendingAuthorization | None:
        """Delete and return the pending authorization; ``None`` if missing or expired."""

    async def save_code(self, code: AuthCodeRecord) -> None: ...

    async def get_code(self, code_hash: str, now: float) -> AuthCodeRecord | None: ...

    async def take_code(self, code_hash: str, now: float) -> AuthCodeRecord | None:
        """Atomically delete and return the code (single use); ``None`` if missing or expired."""

    async def create_family(self, access: TokenRecord, refresh: TokenRecord, upstream_blob: bytes | None) -> None: ...

    async def get_token(self, token_hash: str) -> TokenRecord | None: ...

    async def rotate_refresh(
        self,
        old_hash: str,
        access: TokenRecord,
        refresh: TokenRecord,
        upstream_blob: bytes | None,
        now: float,
    ) -> RotateOutcome:
        """Mark ``old_hash`` used and insert the new pair in one transaction.

        ``reused`` means the old refresh token had already been used: the whole family is revoked.
        ``invalid`` means it is missing, revoked, expired or not a refresh token: nothing changes.
        """

    async def revoke_family(self, family_id: str, now: float) -> int: ...

    async def get_upstream(self, family_id: str) -> bytes | None: ...

    async def get_rate_limit(self, key: str) -> RateLimitState | None: ...

    async def save_rate_limit(self, key: str, state: RateLimitState, now: float) -> None: ...

    async def delete_rate_limit(self, key: str) -> None: ...

    async def insert_audit_events(self, events: Sequence[AuditEvent]) -> None: ...

    async def cleanup(self, now: float, audit_cutoff: float) -> CleanupStats: ...
```

- [ ] **Step 5: Implement the migrations**

`src/ratatoskr/state/migrations.py`:

```python
"""Ordered SQLite schema migrations. Append new entries; never edit an applied one."""

MIGRATIONS: tuple[str, ...] = (
    # 1 — initial schema (spec §7)
    """
    CREATE TABLE clients (
        client_id     TEXT PRIMARY KEY,
        metadata_json TEXT NOT NULL,
        secret_blob   BLOB,
        created_at    REAL NOT NULL
    );
    CREATE TABLE pending_authorizations (
        id                TEXT PRIMARY KEY,
        client_id         TEXT NOT NULL,
        params_json       TEXT NOT NULL,
        nonce             TEXT,
        upstream_verifier TEXT,
        expires_at        REAL NOT NULL
    );
    CREATE TABLE auth_codes (
        code_hash     TEXT PRIMARY KEY,
        client_id     TEXT NOT NULL,
        params_json   TEXT NOT NULL,
        subject       TEXT NOT NULL,
        display_name  TEXT NOT NULL,
        groups_json   TEXT NOT NULL,
        auth_source   TEXT NOT NULL,
        upstream_blob BLOB,
        expires_at    REAL NOT NULL
    );
    CREATE TABLE tokens (
        token_hash   TEXT PRIMARY KEY,
        kind         TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
        family_id    TEXT NOT NULL,
        client_id    TEXT NOT NULL,
        scopes_json  TEXT NOT NULL,
        resource     TEXT,
        subject      TEXT NOT NULL,
        display_name TEXT NOT NULL,
        groups_json  TEXT NOT NULL,
        auth_source  TEXT NOT NULL,
        created_at   REAL NOT NULL,
        expires_at   REAL NOT NULL,
        used_at      REAL,
        revoked_at   REAL
    );
    CREATE INDEX tokens_family ON tokens (family_id);
    CREATE INDEX tokens_expires ON tokens (expires_at);
    CREATE TABLE upstream_sessions (
        family_id    TEXT PRIMARY KEY,
        refresh_blob BLOB NOT NULL,
        updated_at   REAL NOT NULL
    );
    CREATE TABLE rate_limits (
        key           TEXT PRIMARY KEY,
        hits_json     TEXT NOT NULL,
        strikes       INTEGER NOT NULL,
        blocked_until REAL NOT NULL,
        updated_at    REAL NOT NULL
    );
    CREATE TABLE audit_events (
        id           INTEGER PRIMARY KEY,
        ts           REAL NOT NULL,
        subject      TEXT NOT NULL,
        auth_source  TEXT NOT NULL,
        connection   TEXT,
        tool         TEXT NOT NULL,
        query_text   TEXT,
        query_sha256 TEXT,
        duration_ms  REAL NOT NULL,
        rows         INTEGER,
        result       TEXT NOT NULL,
        error_class  TEXT
    );
    CREATE INDEX audit_events_ts ON audit_events (ts);
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """,
)
```

- [ ] **Step 6: Implement `SqliteStore`**

`src/ratatoskr/state/sqlite.py`:

```python
"""SQLite implementation of :class:`ratatoskr.state.store.Store`.

One aiosqlite connection (one writer thread) in WAL mode with ``synchronous=NORMAL``. An asyncio lock serialises
statements so that multi-statement transactions from concurrent coroutines never interleave.
"""

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import aiosqlite

from ratatoskr.auth.principal import Principal
from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.migrations import MIGRATIONS
from ratatoskr.state.records import (
    AuthCodeRecord,
    CleanupStats,
    PendingAuthorization,
    RateLimitState,
    RotateOutcome,
    StoredClient,
    TokenRecord,
)

_RATE_LIMIT_IDLE_SECONDS = 86400.0
_SOURCES: dict[str, Literal["stdio", "local", "oidc"]] = {"stdio": "stdio", "local": "local", "oidc": "oidc"}


class StateStoreError(Exception):
    """The state database is unusable (not open, or newer than this server)."""


def _principal(row: sqlite3.Row) -> Principal:
    source = _SOURCES.get(str(row["auth_source"]))
    if source is None:
        raise StateStoreError(f"unknown auth_source in state database: {row['auth_source']!r}")
    return Principal(
        subject=str(row["subject"]),
        display_name=str(row["display_name"]),
        groups=frozenset(json.loads(row["groups_json"])),
        auth_source=source,
    )


def _groups_json(principal: Principal) -> str:
    return json.dumps(sorted(principal.groups))


def _token(row: sqlite3.Row) -> TokenRecord:
    kind: Literal["access", "refresh"] = "access" if row["kind"] == "access" else "refresh"
    return TokenRecord(
        token_hash=str(row["token_hash"]),
        kind=kind,
        family_id=str(row["family_id"]),
        client_id=str(row["client_id"]),
        scopes=tuple(json.loads(row["scopes_json"])),
        resource=row["resource"],
        principal=_principal(row),
        created_at=float(row["created_at"]),
        expires_at=float(row["expires_at"]),
        used_at=row["used_at"],
        revoked_at=row["revoked_at"],
    )


def _token_params(token: TokenRecord) -> tuple[Any, ...]:
    p = token.principal
    return (
        token.token_hash,
        token.kind,
        token.family_id,
        token.client_id,
        json.dumps(list(token.scopes)),
        token.resource,
        p.subject,
        p.display_name,
        _groups_json(p),
        p.auth_source,
        token.created_at,
        token.expires_at,
        token.used_at,
        token.revoked_at,
    )


_INSERT_TOKEN = (
    "INSERT INTO tokens (token_hash, kind, family_id, client_id, scopes_json, resource, subject, display_name,"
    " groups_json, auth_source, created_at, expires_at, used_at, revoked_at)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
)
_UPSERT_UPSTREAM = (
    "INSERT INTO upstream_sessions (family_id, refresh_blob, updated_at) VALUES (?, ?, ?)"
    " ON CONFLICT (family_id) DO UPDATE SET refresh_blob = excluded.refresh_blob, updated_at = excluded.updated_at"
)


class SqliteStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._db: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    # ── lifecycle ────────────────────────────────────────────────────────

    async def open(self) -> None:
        if self._db is not None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        db = await aiosqlite.connect(self._path, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            mode_rows = list(await db.execute_fetchall("PRAGMA journal_mode=WAL"))
            if str(mode_rows[0][0]).lower() != "wal":
                raise StateStoreError(f"could not enable WAL mode on {self._path}")
            await db.execute("PRAGMA synchronous=NORMAL")
            await db.execute("PRAGMA busy_timeout=5000")
            self._db = db
            await self._migrate()
        except BaseException:
            self._db = None
            await db.close()
            raise

    async def close(self) -> None:
        if self._db is None:
            return
        async with self._lock:
            db, self._db = self._db, None
            await db.close()

    @property
    def _conn(self) -> aiosqlite.Connection:
        if self._db is None:
            raise StateStoreError("state store is not open")
        return self._db

    async def schema_version(self) -> int:
        async with self._lock:
            rows = list(await self._conn.execute_fetchall("SELECT version FROM schema_version"))
        return int(rows[0]["version"]) if rows else 0

    async def _migrate(self) -> None:
        async with self._lock:
            db = self._conn
            await db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            rows = list(await db.execute_fetchall("SELECT version FROM schema_version"))
            current = int(rows[0]["version"]) if rows else 0
            if current > len(MIGRATIONS):
                raise StateStoreError(
                    f"state database schema version {current} is newer than this server supports ({len(MIGRATIONS)})"
                )
            for version in range(current + 1, len(MIGRATIONS) + 1):
                script = (
                    "BEGIN IMMEDIATE;\n"
                    f"{MIGRATIONS[version - 1]}\n"
                    "DELETE FROM schema_version;\n"
                    f"INSERT INTO schema_version (version) VALUES ({version});\n"
                    "COMMIT;"
                )
                try:
                    await db.executescript(script)
                except sqlite3.Error:
                    if db.in_transaction:
                        await db.execute("ROLLBACK")
                    raise

    @asynccontextmanager
    async def _tx(self) -> AsyncIterator[aiosqlite.Connection]:
        async with self._lock:
            db = self._conn
            await db.execute("BEGIN IMMEDIATE")
            try:
                yield db
            except BaseException:
                await db.execute("ROLLBACK")
                raise
            await db.execute("COMMIT")

    async def _fetchone(self, sql: str, params: tuple[Any, ...]) -> sqlite3.Row | None:
        async with self._lock:
            rows = list(await self._conn.execute_fetchall(sql, params))
        return rows[0] if rows else None

    async def check_writable(self) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO meta (key, value) VALUES ('ready_check', ?)"
                " ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                (datetime.now(UTC).isoformat(),),
            )

    # ── clients ──────────────────────────────────────────────────────────

    async def save_client(self, client: StoredClient) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO clients (client_id, metadata_json, secret_blob, created_at) VALUES (?, ?, ?, ?)",
                (client.client_id, client.metadata_json, client.secret_blob, client.created_at),
            )

    async def get_client(self, client_id: str) -> StoredClient | None:
        row = await self._fetchone("SELECT * FROM clients WHERE client_id = ?", (client_id,))
        if row is None:
            return None
        return StoredClient(
            client_id=str(row["client_id"]),
            metadata_json=str(row["metadata_json"]),
            secret_blob=row["secret_blob"],
            created_at=float(row["created_at"]),
        )

    # ── pending authorizations ──────────────────────────────────────────

    async def save_pending(self, pending: PendingAuthorization) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO pending_authorizations (id, client_id, params_json, nonce, upstream_verifier, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    pending.id,
                    pending.client_id,
                    pending.params_json,
                    pending.nonce,
                    pending.upstream_verifier,
                    pending.expires_at,
                ),
            )

    @staticmethod
    def _pending(row: sqlite3.Row) -> PendingAuthorization:
        return PendingAuthorization(
            id=str(row["id"]),
            client_id=str(row["client_id"]),
            params_json=str(row["params_json"]),
            expires_at=float(row["expires_at"]),
            nonce=row["nonce"],
            upstream_verifier=row["upstream_verifier"],
        )

    async def get_pending(self, pending_id: str, now: float) -> PendingAuthorization | None:
        row = await self._fetchone(
            "SELECT * FROM pending_authorizations WHERE id = ? AND expires_at > ?", (pending_id, now)
        )
        return None if row is None else self._pending(row)

    async def take_pending(self, pending_id: str, now: float) -> PendingAuthorization | None:
        async with self._tx() as db:
            rows = list(
                await db.execute_fetchall("DELETE FROM pending_authorizations WHERE id = ? RETURNING *", (pending_id,))
            )
        if not rows or float(rows[0]["expires_at"]) <= now:
            return None
        return self._pending(rows[0])

    # ── authorization codes ─────────────────────────────────────────────

    async def save_code(self, code: AuthCodeRecord) -> None:
        p = code.principal
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO auth_codes (code_hash, client_id, params_json, subject, display_name, groups_json,"
                " auth_source, upstream_blob, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    code.code_hash,
                    code.client_id,
                    code.params_json,
                    p.subject,
                    p.display_name,
                    _groups_json(p),
                    p.auth_source,
                    code.upstream_blob,
                    code.expires_at,
                ),
            )

    @staticmethod
    def _code(row: sqlite3.Row) -> AuthCodeRecord:
        return AuthCodeRecord(
            code_hash=str(row["code_hash"]),
            client_id=str(row["client_id"]),
            params_json=str(row["params_json"]),
            principal=_principal(row),
            upstream_blob=row["upstream_blob"],
            expires_at=float(row["expires_at"]),
        )

    async def get_code(self, code_hash: str, now: float) -> AuthCodeRecord | None:
        row = await self._fetchone("SELECT * FROM auth_codes WHERE code_hash = ? AND expires_at > ?", (code_hash, now))
        return None if row is None else self._code(row)

    async def take_code(self, code_hash: str, now: float) -> AuthCodeRecord | None:
        async with self._tx() as db:
            rows = list(
                await db.execute_fetchall("DELETE FROM auth_codes WHERE code_hash = ? RETURNING *", (code_hash,))
            )
        if not rows or float(rows[0]["expires_at"]) <= now:
            return None
        return self._code(rows[0])

    # ── tokens ───────────────────────────────────────────────────────────

    async def create_family(self, access: TokenRecord, refresh: TokenRecord, upstream_blob: bytes | None) -> None:
        async with self._tx() as db:
            await db.execute(_INSERT_TOKEN, _token_params(access))
            await db.execute(_INSERT_TOKEN, _token_params(refresh))
            if upstream_blob is not None:
                await db.execute(_UPSERT_UPSTREAM, (refresh.family_id, upstream_blob, refresh.created_at))

    async def get_token(self, token_hash: str) -> TokenRecord | None:
        row = await self._fetchone("SELECT * FROM tokens WHERE token_hash = ?", (token_hash,))
        return None if row is None else _token(row)

    async def rotate_refresh(
        self,
        old_hash: str,
        access: TokenRecord,
        refresh: TokenRecord,
        upstream_blob: bytes | None,
        now: float,
    ) -> RotateOutcome:
        async with self._tx() as db:
            rows = list(await db.execute_fetchall("SELECT * FROM tokens WHERE token_hash = ?", (old_hash,)))
            if not rows:
                return "invalid"
            old = _token(rows[0])
            if old.kind != "refresh" or old.revoked_at is not None or old.expires_at <= now:
                return "invalid"
            if old.used_at is not None:
                await db.execute(
                    "UPDATE tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL", (now, old.family_id)
                )
                return "reused"
            await db.execute("UPDATE tokens SET used_at = ? WHERE token_hash = ?", (now, old_hash))
            await db.execute(
                "UPDATE tokens SET revoked_at = ? WHERE family_id = ? AND kind = 'access' AND revoked_at IS NULL",
                (now, old.family_id),
            )
            await db.execute(_INSERT_TOKEN, _token_params(access))
            await db.execute(_INSERT_TOKEN, _token_params(refresh))
            if upstream_blob is not None:
                await db.execute(_UPSERT_UPSTREAM, (old.family_id, upstream_blob, now))
            return "rotated"

    async def revoke_family(self, family_id: str, now: float) -> int:
        async with self._tx() as db:
            cursor = await db.execute(
                "UPDATE tokens SET revoked_at = ? WHERE family_id = ? AND revoked_at IS NULL", (now, family_id)
            )
            await db.execute("DELETE FROM upstream_sessions WHERE family_id = ?", (family_id,))
            return cursor.rowcount

    async def get_upstream(self, family_id: str) -> bytes | None:
        row = await self._fetchone("SELECT refresh_blob FROM upstream_sessions WHERE family_id = ?", (family_id,))
        return None if row is None else bytes(row["refresh_blob"])

    # ── rate limits ─────────────────────────────────────────────────────

    async def get_rate_limit(self, key: str) -> RateLimitState | None:
        row = await self._fetchone("SELECT * FROM rate_limits WHERE key = ?", (key,))
        if row is None:
            return None
        return RateLimitState(
            hits=tuple(float(h) for h in json.loads(row["hits_json"])),
            strikes=int(row["strikes"]),
            blocked_until=float(row["blocked_until"]),
        )

    async def save_rate_limit(self, key: str, state: RateLimitState, now: float) -> None:
        async with self._tx() as db:
            await db.execute(
                "INSERT INTO rate_limits (key, hits_json, strikes, blocked_until, updated_at) VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT (key) DO UPDATE SET hits_json = excluded.hits_json, strikes = excluded.strikes,"
                " blocked_until = excluded.blocked_until, updated_at = excluded.updated_at",
                (key, json.dumps(list(state.hits)), state.strikes, state.blocked_until, now),
            )

    async def delete_rate_limit(self, key: str) -> None:
        async with self._tx() as db:
            await db.execute("DELETE FROM rate_limits WHERE key = ?", (key,))

    # ── audit ───────────────────────────────────────────────────────────

    async def insert_audit_events(self, events: Sequence[AuditEvent]) -> None:
        if not events:
            return
        rows = [
            (
                e.ts.timestamp(),
                e.subject,
                e.auth_source,
                e.connection,
                e.tool,
                e.query_text,
                e.query_sha256,
                e.duration_ms,
                e.rows,
                e.result,
                e.error_class,
            )
            for e in events
        ]
        async with self._tx() as db:
            await db.executemany(
                "INSERT INTO audit_events (ts, subject, auth_source, connection, tool, query_text, query_sha256,"
                " duration_ms, rows, result, error_class) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )

    async def count_audit_events(self) -> int:
        row = await self._fetchone("SELECT COUNT(*) AS n FROM audit_events", ())
        return 0 if row is None else int(row["n"])

    # ── maintenance ─────────────────────────────────────────────────────

    async def cleanup(self, now: float, audit_cutoff: float) -> CleanupStats:
        async with self._tx() as db:
            pending = await db.execute("DELETE FROM pending_authorizations WHERE expires_at <= ?", (now,))
            codes = await db.execute("DELETE FROM auth_codes WHERE expires_at <= ?", (now,))
            tokens = await db.execute("DELETE FROM tokens WHERE expires_at <= ?", (now,))
            upstream = await db.execute(
                "DELETE FROM upstream_sessions WHERE family_id NOT IN"
                " (SELECT family_id FROM tokens WHERE revoked_at IS NULL)"
            )
            limits = await db.execute(
                "DELETE FROM rate_limits WHERE updated_at <= ? AND blocked_until <= ?",
                (now - _RATE_LIMIT_IDLE_SECONDS, now),
            )
            audit = await db.execute("DELETE FROM audit_events WHERE ts < ?", (audit_cutoff,))
            return CleanupStats(
                pending=pending.rowcount,
                codes=codes.rowcount,
                tokens=tokens.rowcount,
                upstream_sessions=upstream.rowcount,
                rate_limits=limits.rowcount,
                audit_events=audit.rowcount,
            )
```

- [ ] **Step 7: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_state_sqlite.py -q && .venv/Scripts/python -m mypy src && .venv/Scripts/python -m ruff check src tests`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/ratatoskr/state tests/unit/secure_http/test_state_sqlite.py
git commit -m "Add SQLite state store with migrations, hashed tokens and refresh rotation" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Persistent audit sink and hourly cleanup

**Files:**
- Create: `src/ratatoskr/state/audit.py`, `src/ratatoskr/state/maintenance.py`
- Test: `tests/unit/secure_http/test_state_audit_sink.py`

`SqliteAuditSink.record` only enqueues (never blocks, never raises — the `AuditSink` contract); a background task
writes a batch when 100 events are queued or 1 s after the first one; `aclose()` enqueues a stop marker and waits,
so everything recorded before shutdown is written. A full queue (10 000) drops events with a rate-limited warning.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.audit import SqliteAuditSink
from ratatoskr.state.maintenance import CleanupTask
from ratatoskr.state.records import PendingAuthorization
from ratatoskr.state.sqlite import SqliteStore


def event(i: int = 0, ts: datetime | None = None) -> AuditEvent:
    return AuditEvent(
        ts=ts or datetime.now(UTC),
        subject="alice",
        auth_source="local",
        connection="prod-pg",
        tool=f"tool-{i}",
        query_text=None,
        query_sha256=None,
        duration_ms=1.0,
        rows=None,
        result="ok",
        error_class=None,
    )


async def wait_for_count(store: SqliteStore, expected: int, timeout: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while await store.count_audit_events() < expected:
        assert asyncio.get_running_loop().time() < deadline, "audit events were not flushed in time"
        await asyncio.sleep(0.01)


async def test_flushes_after_the_interval(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store, flush_interval=0.05)
    sink.start()
    sink.record(event())
    assert await store.count_audit_events() == 0
    await wait_for_count(store, 1)
    await sink.aclose()


async def test_flushes_a_full_batch_without_waiting(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store, batch_size=10, flush_interval=60.0)
    sink.start()
    for i in range(10):
        sink.record(event(i))
    await wait_for_count(store, 10, timeout=1.0)
    await sink.aclose()


async def test_close_writes_everything_queued(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store, flush_interval=60.0)
    sink.start()
    for i in range(250):
        sink.record(event(i))
    await sink.aclose()
    assert await store.count_audit_events() == 250


async def test_close_without_start_still_writes(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store)
    sink.record(event())
    await sink.aclose()
    assert await store.count_audit_events() == 1


async def test_record_never_raises_when_full_or_closed(store: SqliteStore) -> None:
    sink = SqliteAuditSink(store, max_queue=2)
    for i in range(5):
        sink.record(event(i))
    assert sink.dropped == 3
    await sink.aclose()
    sink.record(event())
    assert sink.dropped == 4
    assert await store.count_audit_events() == 2


async def test_write_failure_is_logged_not_raised(store: SqliteStore, caplog) -> None:
    sink = SqliteAuditSink(store, flush_interval=0.01)
    sink.start()
    await store.close()
    sink.record(event())
    await asyncio.sleep(0.1)
    await sink.aclose()
    assert "failed to persist 1 audit events" in caplog.text


async def test_cleanup_task_applies_retention(store: SqliteStore, clock) -> None:
    old = datetime.fromtimestamp(clock() - 91 * 86400, UTC)
    await store.insert_audit_events([event(1, old), event(2)])
    await store.save_pending(PendingAuthorization("p", "c", "{}", expires_at=clock() - 1))
    stats = await CleanupTask(store, audit_retention=timedelta(days=90), clock=clock).run_once()
    assert stats.audit_events == 1 and stats.pending == 1
    assert await store.count_audit_events() == 1


async def test_cleanup_task_runs_in_background_until_stopped(store: SqliteStore, clock) -> None:
    await store.save_pending(PendingAuthorization("p", "c", "{}", expires_at=clock() - 1))
    task = CleanupTask(store, audit_retention=timedelta(days=90), clock=clock, interval=3600)
    task.start()
    for _ in range(100):
        if await store.get_pending("p", now=0.0) is None:
            break
        await asyncio.sleep(0.01)
    await task.stop()
    assert await store.get_pending("p", now=0.0) is None
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_state_audit_sink.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.state.audit'`.

- [ ] **Step 3: Implement the sink**

`src/ratatoskr/state/audit.py`:

```python
"""Audit sink that persists events to the state store in batches (spec §7).

``record`` never blocks and never raises: events go to an in-memory queue that a background task writes every
``flush_interval`` seconds or every ``batch_size`` events. ``aclose`` writes everything still queued.
"""

import asyncio
import logging

from ratatoskr.observability.audit import AuditEvent
from ratatoskr.state.store import Store

logger = logging.getLogger("ratatoskr.state.audit")


class SqliteAuditSink:
    def __init__(
        self,
        store: Store,
        *,
        batch_size: int = 100,
        flush_interval: float = 1.0,
        max_queue: int = 10_000,
    ) -> None:
        self._store = store
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._max_queue = max_queue
        self._queue: asyncio.Queue[AuditEvent | None] = asyncio.Queue()
        self._task: asyncio.Task[None] | None = None
        self._closed = False
        self.dropped = 0

    def record(self, event: AuditEvent) -> None:
        if self._closed or self._queue.qsize() >= self._max_queue:
            self.dropped += 1
            if self.dropped == 1 or self.dropped % 1000 == 0:
                logger.warning("audit queue unavailable; %d audit events dropped so far", self.dropped)
            return
        self._queue.put_nowait(event)

    def start(self) -> None:
        if self._task is None and not self._closed:
            self._task = asyncio.create_task(self._run(), name="ratatoskr-audit-writer")

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._task is not None:
            self._queue.put_nowait(None)
            await self._task
            return
        leftovers: list[AuditEvent] = []
        while not self._queue.empty():
            item = self._queue.get_nowait()
            if item is not None:
                leftovers.append(item)
        await self._write(leftovers)

    async def _run(self) -> None:
        loop = asyncio.get_running_loop()
        stopping = False
        while not stopping:
            first = await self._queue.get()
            if first is None:
                return
            batch = [first]
            deadline = loop.time() + self._flush_interval
            while len(batch) < self._batch_size:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                try:
                    item = await asyncio.wait_for(self._queue.get(), remaining)
                except TimeoutError:
                    break
                if item is None:
                    stopping = True
                    break
                batch.append(item)
            await self._write(batch)

    async def _write(self, batch: list[AuditEvent]) -> None:
        if not batch:
            return
        try:
            await self._store.insert_audit_events(batch)
        except Exception:
            logger.exception("failed to persist %d audit events", len(batch))
```

- [ ] **Step 4: Implement the cleanup task**

`src/ratatoskr/state/maintenance.py`:

```python
"""Hourly removal of expired codes, tokens, pending authorizations, idle rate limits and old audit rows."""

import asyncio
import contextlib
import logging
from dataclasses import asdict
from datetime import timedelta

from ratatoskr.state.records import CleanupStats, Clock
from ratatoskr.state.store import Store

logger = logging.getLogger("ratatoskr.state.maintenance")

CLEANUP_INTERVAL_SECONDS = 3600.0


class CleanupTask:
    def __init__(
        self,
        store: Store,
        *,
        audit_retention: timedelta,
        clock: Clock,
        interval: float = CLEANUP_INTERVAL_SECONDS,
    ) -> None:
        self._store = store
        self._retention = audit_retention.total_seconds()
        self._clock = clock
        self._interval = interval
        self._task: asyncio.Task[None] | None = None

    async def run_once(self) -> CleanupStats:
        now = self._clock()
        stats = await self._store.cleanup(now, audit_cutoff=now - self._retention)
        logger.info("state cleanup finished", extra={"cleanup": asdict(stats)})
        return stats

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._loop(), name="ratatoskr-state-cleanup")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def _loop(self) -> None:
        while True:
            try:
                await self.run_once()
            except Exception:
                logger.exception("state cleanup failed")
            await asyncio.sleep(self._interval)
```

- [ ] **Step 5: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_state_audit_sink.py -q && .venv/Scripts/python -m mypy src`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ratatoskr/state/audit.py src/ratatoskr/state/maintenance.py tests/unit/secure_http/test_state_audit_sink.py
git commit -m "Add batched SQLite audit sink and hourly state cleanup" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Redirect URI allowlist

**Files:**
- Create: `src/ratatoskr/auth/redirects.py`
- Test: `tests/unit/secure_http/test_auth_redirects.py`

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import pytest

from ratatoskr.auth.redirects import redirect_uri_problem

ALLOWED = ["claude.ai", "claude.com", "localhost", "127.0.0.1"]


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.ai/api/mcp/auth_callback",
        "https://CLAUDE.com/api/mcp/auth_callback",
        "http://localhost:6274/oauth/callback",
        "http://127.0.0.1:33418/callback",
        "https://localhost/callback",
    ],
)
def test_allowed_redirects(uri: str) -> None:
    assert redirect_uri_problem(uri, ALLOWED) is None


@pytest.mark.parametrize(
    ("uri", "reason"),
    [
        ("https://evil.example/callback", "allowed_redirect_hosts"),
        ("https://claude.ai.evil.example/cb", "allowed_redirect_hosts"),
        ("http://claude.ai/api/mcp/auth_callback", "https"),
        ("https://claude.ai/cb#frag", "fragment"),
        ("https://user:pw@claude.ai/cb", "credentials"),
        ("myapp://callback", "host"),
        ("https://claude.ai:99999/cb", "valid URL"),
        ("javascript:alert(1)", "host"),
    ],
)
def test_rejected_redirects(uri: str, reason: str) -> None:
    problem = redirect_uri_problem(uri, ALLOWED)
    assert problem is not None and reason in problem
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_auth_redirects.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.auth.redirects'`.

- [ ] **Step 3: Implement**

```python
"""Redirect URI allowlist for dynamic client registration (spec §5.2 step 1)."""

from urllib.parse import urlsplit

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1"})


def redirect_uri_problem(uri: str, allowed_hosts: list[str]) -> str | None:
    """Return why ``uri`` is not an acceptable redirect URI, or ``None`` when it is."""
    try:
        parts = urlsplit(uri)
        host = (parts.hostname or "").lower()
        _ = parts.port  # raises ValueError on a malformed port
    except ValueError:
        return f"redirect_uri {uri!r} is not a valid URL"
    if parts.fragment:
        return f"redirect_uri {uri!r} must not contain a fragment"
    if parts.username is not None or parts.password is not None:
        return f"redirect_uri {uri!r} must not contain credentials"
    if not host:
        return f"redirect_uri {uri!r} has no host"
    if host not in {h.lower() for h in allowed_hosts}:
        return f"redirect_uri host {host!r} is not in server.allowed_redirect_hosts"
    if parts.scheme == "https":
        return None
    if parts.scheme == "http" and host in _LOOPBACK_HOSTS:
        return None
    return f"redirect_uri {uri!r} must use https (http is allowed only for localhost and 127.0.0.1)"
```

- [ ] **Step 4: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_auth_redirects.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/auth/redirects.py tests/unit/secure_http/test_auth_redirects.py
git commit -m "Add redirect URI allowlist for dynamic client registration" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Rate limiter

**Files:**
- Create: `src/ratatoskr/auth/ratelimit.py`
- Test: `tests/unit/secure_http/test_auth_ratelimit.py`

Semantics: `hit(key)` records an attempt; the attempt that brings the sliding window to `limit` starts a lockout of
`base_lockout · 2^(n-1)` (n = lockouts so far), capped at `max_lockout`, and clears the window. `retry_after(key)`
is checked before an attempt. Login: 5 failures/60 s per IP and per username, lockout 1 min doubling to 1 h. DCR:
20 registrations/hour per IP, lockout 10 min doubling to 24 h. State lives in the store, so it survives restarts.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

from ratatoskr.auth.ratelimit import RateLimiter, RateRule
from ratatoskr.state.sqlite import SqliteStore

RULE = RateRule(limit=3, window=60.0, base_lockout=10.0, max_lockout=35.0)


async def test_allows_attempts_below_the_limit(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    assert await limiter.hit("k") == 0.0
    assert await limiter.hit("k") == 0.0
    assert await limiter.retry_after("k") == 0.0


async def test_reaching_the_limit_locks_out(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(2):
        await limiter.hit("k")
    assert await limiter.hit("k") == 10.0
    assert await limiter.retry_after("k") == 10.0
    clock.advance(4.0)
    assert await limiter.retry_after("k") == 6.0
    clock.advance(6.0)
    assert await limiter.retry_after("k") == 0.0


async def test_window_slides(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    await limiter.hit("k")
    await limiter.hit("k")
    clock.advance(61.0)
    assert await limiter.hit("k") == 0.0
    assert await limiter.retry_after("k") == 0.0


async def test_lockout_grows_exponentially_and_is_capped(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    lockouts = []
    for _ in range(4):
        for _ in range(2):
            await limiter.hit("k")
        lockouts.append(await limiter.hit("k"))
        clock.advance(lockouts[-1])
    assert lockouts == [10.0, 20.0, 35.0, 35.0]


async def test_keys_are_independent_and_reset_clears(store: SqliteStore, clock) -> None:
    limiter = RateLimiter(store, RULE, clock)
    for _ in range(3):
        await limiter.hit("a")
    assert await limiter.retry_after("a") > 0
    assert await limiter.retry_after("b") == 0.0
    await limiter.reset("a")
    assert await limiter.retry_after("a") == 0.0


async def test_state_survives_a_new_limiter_instance(store: SqliteStore, clock) -> None:
    for _ in range(3):
        await RateLimiter(store, RULE, clock).hit("k")
    assert await RateLimiter(store, RULE, clock).retry_after("k") == 10.0
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_auth_ratelimit.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.auth.ratelimit'`.

- [ ] **Step 3: Implement**

```python
"""Sliding-window rate limiting with exponential lockout, persisted in the state store (spec §5.4)."""

import asyncio
from dataclasses import dataclass

from ratatoskr.state.records import Clock, RateLimitState
from ratatoskr.state.store import Store


@dataclass(frozen=True)
class RateRule:
    limit: int
    """Attempts allowed inside ``window`` seconds; reaching it starts a lockout."""
    window: float
    base_lockout: float
    """First lockout in seconds; each further lockout doubles it."""
    max_lockout: float


LOGIN_RULE = RateRule(limit=5, window=60.0, base_lockout=60.0, max_lockout=3600.0)
REGISTER_RULE = RateRule(limit=20, window=3600.0, base_lockout=600.0, max_lockout=86400.0)


class RateLimiter:
    def __init__(self, store: Store, rule: RateRule, clock: Clock) -> None:
        self._store = store
        self._rule = rule
        self._clock = clock
        self._lock = asyncio.Lock()

    async def retry_after(self, key: str) -> float:
        """Seconds until ``key`` may try again; ``0.0`` when it is not locked out."""
        state = await self._store.get_rate_limit(key)
        if state is None:
            return 0.0
        return max(0.0, state.blocked_until - self._clock())

    async def hit(self, key: str) -> float:
        """Record one attempt for ``key``; returns the lockout it triggered (``0.0`` when none)."""
        async with self._lock:
            now = self._clock()
            state = await self._store.get_rate_limit(key) or RateLimitState(hits=(), strikes=0, blocked_until=0.0)
            hits = tuple(t for t in state.hits if t > now - self._rule.window) + (now,)
            if len(hits) < self._rule.limit:
                await self._store.save_rate_limit(key, RateLimitState(hits, state.strikes, state.blocked_until), now)
                return 0.0
            strikes = state.strikes + 1
            lockout = min(self._rule.max_lockout, self._rule.base_lockout * 2.0 ** (strikes - 1))
            await self._store.save_rate_limit(key, RateLimitState((), strikes, now + lockout), now)
            return lockout

    async def reset(self, key: str) -> None:
        await self._store.delete_rate_limit(key)
```

- [ ] **Step 4: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_auth_ratelimit.py -q && .venv/Scripts/python -m mypy src`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/auth/ratelimit.py tests/unit/secure_http/test_auth_ratelimit.py
git commit -m "Add persistent sliding-window rate limiter with exponential lockout" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Token models and `TokenPrincipalResolver`

**Files:**
- Create: `src/ratatoskr/auth/tokens.py`
- Modify: `src/ratatoskr/auth/resolver.py` (complete replacement below; `PrincipalResolver` and
  `StdioPrincipalResolver` keep the contract behaviour exactly)
- Test: `tests/unit/secure_http/test_token_resolver.py`

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

from types import SimpleNamespace

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel.server import request_ctx
from starlette.requests import Request

from ratatoskr.auth.resolver import StdioPrincipalResolver, TokenPrincipalResolver
from ratatoskr.auth.tokens import RatatoskrAccessToken


def ratatoskr_token(subject: str, groups: list[str]) -> RatatoskrAccessToken:
    return RatatoskrAccessToken(
        token="t-" + subject,
        client_id="c",
        scopes=["mcp"],
        subject=subject,
        display_name=subject.title(),
        groups=groups,
        auth_source="oidc",
    )


def request_with(token: AccessToken | None) -> Request:
    scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": []}
    if token is not None:
        scope["user"] = AuthenticatedUser(token)
    return Request(scope)


def test_stdio_resolver_is_unchanged() -> None:
    principal = StdioPrincipalResolver("admins").resolve()
    assert (principal.subject, principal.groups, principal.auth_source) == ("stdio", frozenset({"admins"}), "stdio")
    assert StdioPrincipalResolver(None).resolve().groups == frozenset()


def test_resolves_from_the_current_request_not_the_session_context() -> None:
    stale = auth_context_var.set(AuthenticatedUser(ratatoskr_token("alice", ["old-group"])))
    ctx = request_ctx.set(SimpleNamespace(request=request_with(ratatoskr_token("alice", ["new-group"]))))  # type: ignore[arg-type]
    try:
        principal = TokenPrincipalResolver().resolve()
    finally:
        request_ctx.reset(ctx)
        auth_context_var.reset(stale)
    assert principal.groups == frozenset({"new-group"})
    assert principal.display_name == "Alice" and principal.auth_source == "oidc"


def test_falls_back_to_auth_context_without_a_request() -> None:
    stale = auth_context_var.set(AuthenticatedUser(ratatoskr_token("bob", ["g"])))
    try:
        assert TokenPrincipalResolver().resolve().subject == "bob"
    finally:
        auth_context_var.reset(stale)


def test_request_without_user_is_refused_even_if_context_has_one() -> None:
    stale = auth_context_var.set(AuthenticatedUser(ratatoskr_token("bob", ["g"])))
    ctx = request_ctx.set(SimpleNamespace(request=request_with(None)))  # type: ignore[arg-type]
    try:
        with pytest.raises(PermissionError):
            TokenPrincipalResolver().resolve()
    finally:
        request_ctx.reset(ctx)
        auth_context_var.reset(stale)


def test_foreign_token_type_is_refused() -> None:
    plain = AccessToken(token="t", client_id="c", scopes=[])
    ctx = request_ctx.set(SimpleNamespace(request=request_with(plain)))  # type: ignore[arg-type]
    try:
        with pytest.raises(PermissionError, match="Authentication required"):
            TokenPrincipalResolver().resolve()
    finally:
        request_ctx.reset(ctx)


def test_no_context_at_all_is_refused() -> None:
    with pytest.raises(PermissionError):
        TokenPrincipalResolver().resolve()
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_token_resolver.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.auth.tokens'`.

- [ ] **Step 3: Implement the token models**

`src/ratatoskr/auth/tokens.py`:

```python
"""SDK token models extended with the identity Ratatoskr needs on every request."""

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
```

- [ ] **Step 4: Replace `src/ratatoskr/auth/resolver.py`**

If 1a's file has extra docstrings or helpers, keep them; the classes must read:

```python
"""Resolve the :class:`Principal` of the current tool call (stdio process user or OAuth bearer token)."""

from typing import Protocol

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel.server import request_ctx
from starlette.requests import HTTPConnection

from ratatoskr.auth.principal import Principal
from ratatoskr.auth.tokens import RatatoskrAccessToken


class PrincipalResolver(Protocol):
    def resolve(self) -> Principal: ...


class StdioPrincipalResolver:
    def __init__(self, role: str | None) -> None:
        self._role = role

    def resolve(self) -> Principal:
        groups = frozenset({self._role}) if self._role else frozenset()
        return Principal(subject="stdio", display_name="local stdio user", groups=groups, auth_source="stdio")


def _current_access_token() -> AccessToken | None:
    """Token of the HTTP request that carried this JSON-RPC message.

    ``get_access_token()`` alone is not enough: its context variable is captured when the MCP session task starts,
    so after a refresh it still returns the session's first token. The request object the SDK attaches to every
    message always holds the token that was just verified.
    """
    try:
        context = request_ctx.get()
    except LookupError:
        return get_access_token()
    request = context.request
    if not isinstance(request, HTTPConnection):
        return get_access_token()
    user = request.scope.get("user")
    return user.access_token if isinstance(user, AuthenticatedUser) else None


class TokenPrincipalResolver:
    def resolve(self) -> Principal:
        token = _current_access_token()
        if not isinstance(token, RatatoskrAccessToken):
            raise PermissionError("Authentication required.")
        return Principal(
            subject=token.subject,
            display_name=token.display_name,
            groups=frozenset(token.groups),
            auth_source=token.auth_source,
        )
```

- [ ] **Step 5: Run it (plus 1a's resolver tests)**

Run: `.venv/Scripts/python -m pytest tests/unit -q && .venv/Scripts/python -m mypy src`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ratatoskr/auth/tokens.py src/ratatoskr/auth/resolver.py tests/unit/secure_http/test_token_resolver.py
git commit -m "Add Ratatoskr token models and request-scoped TokenPrincipalResolver" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Local identity (argon2id) and `hash-password` logic

**Files:**
- Create: `src/ratatoskr/auth/identity/__init__.py`, `src/ratatoskr/auth/identity/base.py`,
  `src/ratatoskr/auth/identity/local.py`, `src/ratatoskr/auth/password_cli.py`
- Test: `tests/unit/secure_http/test_identity_local.py`

argon2 verification runs in a worker thread (`asyncio.to_thread`) so a login never stalls the event loop. An unknown
username is verified against a dummy hash created at start-up, so it costs the same as a wrong password.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import io

import pytest
from pydantic import SecretStr

from ratatoskr.auth.identity.local import LocalIdentityProvider, hash_password
from ratatoskr.auth.password_cli import run_hash_password
from ratatoskr.config.models import LocalUser

PASSWORD = "correct horse battery staple"


def provider(password_hash: str) -> LocalIdentityProvider:
    return LocalIdentityProvider(
        [LocalUser(username="kerem", password_hash=SecretStr(password_hash), groups=["admins", "devops"])]
    )


def test_hash_password_produces_argon2id() -> None:
    assert hash_password("pw").startswith("$argon2id$")


async def test_correct_password_returns_principal(password_hash: str) -> None:
    principal = await provider(password_hash).verify_password("kerem", PASSWORD)
    assert principal is not None
    assert principal.subject == "kerem"
    assert principal.groups == frozenset({"admins", "devops"})
    assert principal.auth_source == "local"


async def test_wrong_password_and_unknown_user_return_none(password_hash: str) -> None:
    local = provider(password_hash)
    assert await local.verify_password("kerem", "wrong") is None
    assert await local.verify_password("nobody", PASSWORD) is None


async def test_unknown_user_still_runs_argon2(password_hash: str, monkeypatch: pytest.MonkeyPatch) -> None:
    import ratatoskr.auth.identity.local as local_module

    calls: list[str] = []
    real = local_module._verify

    def spy(stored: str, password: str) -> bool:
        calls.append(stored)
        return real(stored, password)

    monkeypatch.setattr(local_module, "_verify", spy)
    await provider(password_hash).verify_password("nobody", "x")
    assert len(calls) == 1 and calls[0].startswith("$argon2id$")


def test_non_argon2id_hash_is_rejected() -> None:
    with pytest.raises(ValueError, match="argon2id"):
        provider("plaintext-password")


def test_lookup_reflects_configuration(password_hash: str) -> None:
    local = provider(password_hash)
    found = local.lookup("kerem")
    assert found is not None and found.groups == frozenset({"admins", "devops"})
    assert local.lookup("removed-user") is None


class FakeTty(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_hash_password_command_reads_stdin() -> None:
    out, err = io.StringIO(), io.StringIO()
    assert run_hash_password(io.StringIO("s3cret\n"), out, err) == 0
    printed = out.getvalue().strip()
    assert printed.startswith("$argon2id$") and "s3cret" not in printed
    assert err.getvalue() == ""


def test_hash_password_command_prompts_twice_on_tty() -> None:
    answers = iter(["pw-one", "pw-one"])
    out, err = io.StringIO(), io.StringIO()
    assert run_hash_password(FakeTty(), out, err, prompt=lambda _: next(answers)) == 0
    assert out.getvalue().startswith("$argon2id$")


def test_hash_password_command_rejects_mismatch_and_empty() -> None:
    answers = iter(["a", "b"])
    err = io.StringIO()
    assert run_hash_password(FakeTty(), io.StringIO(), err, prompt=lambda _: next(answers)) == 1
    assert "do not match" in err.getvalue()
    err = io.StringIO()
    assert run_hash_password(io.StringIO("\n"), io.StringIO(), err) == 1
    assert "empty" in err.getvalue()
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_identity_local.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.auth.identity'`.

- [ ] **Step 3: Implement the identity package**

`src/ratatoskr/auth/identity/__init__.py`:

```python
"""Identity providers: who the person in the browser is (local users or an OIDC issuer)."""
```

`src/ratatoskr/auth/identity/base.py`:

```python
"""Shared identity-provider types. Both providers produce a :class:`Principal`."""

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
```

`src/ratatoskr/auth/identity/local.py`:

```python
"""Local users from configuration, verified with argon2id (spec §5.1 ``local``)."""

import asyncio
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import LocalUser

_HASHER = PasswordHasher()


def hash_password(password: str) -> str:
    """argon2id hash in PHC string format, as stored in ``auth.local.users[].password_hash``."""
    return _HASHER.hash(password)


def _verify(password_hash: str, password: str) -> bool:
    try:
        return _HASHER.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


class LocalIdentityProvider:
    def __init__(self, users: list[LocalUser]) -> None:
        self._users: dict[str, LocalUser] = {}
        for user in users:
            if not user.password_hash.get_secret_value().startswith("$argon2id$"):
                raise ValueError(
                    f"auth.local user {user.username!r}: password_hash must be an argon2id hash"
                    " (generate one with `ratatoskr hash-password`)"
                )
            self._users[user.username] = user
        # Unknown usernames are checked against this hash so they cost the same time as a wrong password.
        self._dummy_hash = _HASHER.hash(secrets.token_urlsafe(32))

    @staticmethod
    def _principal(user: LocalUser) -> Principal:
        return Principal(
            subject=user.username,
            display_name=user.username,
            groups=frozenset(user.groups),
            auth_source="local",
        )

    def lookup(self, subject: str) -> Principal | None:
        user = self._users.get(subject)
        return None if user is None else self._principal(user)

    async def verify_password(self, username: str, password: str) -> Principal | None:
        user = self._users.get(username)
        stored = user.password_hash.get_secret_value() if user is not None else self._dummy_hash
        ok = await asyncio.to_thread(_verify, stored, password)
        if user is None or not ok:
            return None
        return self._principal(user)
```

- [ ] **Step 4: Implement the command logic**

`src/ratatoskr/auth/password_cli.py`:

```python
"""``ratatoskr hash-password``: read a password without echo (or from stdin) and print its argon2id hash."""

import getpass
from collections.abc import Callable
from typing import TextIO

from ratatoskr.auth.identity.local import hash_password


def run_hash_password(
    stdin: TextIO,
    stdout: TextIO,
    stderr: TextIO,
    prompt: Callable[[str], str] = getpass.getpass,
) -> int:
    if stdin.isatty():
        password = prompt("Password: ")
        if prompt("Repeat password: ") != password:
            print("Passwords do not match.", file=stderr)
            return 1
    else:
        password = stdin.readline().rstrip("\r\n")
    if not password:
        print("Password must not be empty.", file=stderr)
        return 1
    print(hash_password(password), file=stdout)
    return 0
```

- [ ] **Step 5: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_identity_local.py -q && .venv/Scripts/python -m mypy src`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ratatoskr/auth/identity src/ratatoskr/auth/password_cli.py tests/unit/secure_http/test_identity_local.py
git commit -m "Add argon2id local identity provider and hash-password logic" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: OIDC relying party

**Files:**
- Create: `src/ratatoskr/auth/identity/oidc.py`
- Test: `tests/unit/secure_http/test_identity_oidc.py`

The fake issuer (conftest) signs ID tokens with a local RSA key and serves discovery, JWKS, token and userinfo
through respx; unmatched outbound requests fail the test, so nothing reaches the network. Upstream token requests use
`client_secret_basic`. Errors are split: `UpstreamUnavailableError` (network, 5xx — retry later, keep our tokens)
versus every other `IdentityError` (refused or unverifiable — revoke our tokens).

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import base64
import ssl
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, OctKey

from ratatoskr.auth.crypto import pkce_challenge
from ratatoskr.auth.identity.base import IdentityError, UpstreamRejectedError, UpstreamUnavailableError
from ratatoskr.auth.identity.oidc import OidcIdentityProvider
from ratatoskr.config.models import OidcSettings

REDIRECT = "https://mcp.example.com/oauth/callback"
VERIFIER = "v" * 64


@pytest.fixture
async def http(tls_context: ssl.SSLContext) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(verify=tls_context) as client:
        yield client


def settings(**overrides: object) -> OidcSettings:
    values: dict[str, object] = {
        "issuer": "https://idp.example.com/application/o/mcp/",
        "client_id": "ratatoskr",
        "client_secret": "upstream-secret",
        **overrides,
    }
    return OidcSettings.model_validate(values)


@pytest.fixture
def oidc(http: httpx.AsyncClient, clock) -> OidcIdentityProvider:
    return OidcIdentityProvider(settings(), REDIRECT, http, clock)


async def test_authorization_url_carries_pkce_state_and_nonce(oidc, fake_issuer) -> None:
    url = await oidc.authorization_url(state="st", nonce="nn", code_verifier=VERIFIER)
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == fake_issuer.authorization_endpoint
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert query == {
        "response_type": "code",
        "client_id": "ratatoskr",
        "redirect_uri": REDIRECT,
        "scope": "openid email profile groups offline_access",
        "state": "st",
        "nonce": "nn",
        "code_challenge": pkce_challenge(VERIFIER),
        "code_challenge_method": "S256",
    }


async def test_discovery_issuer_mismatch_is_rejected(oidc, fake_issuer) -> None:
    fake_issuer.discovery["issuer"] = "https://attacker.example.com/"
    with pytest.raises(IdentityError, match="does not match"):
        await oidc.metadata()


async def test_complete_returns_principal_and_upstream_refresh(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(
        id_token=fake_issuer.id_token(nonce="nn", groups=["devops", "analyst"]),
        access_token="up-access",
        refresh_token="up-refresh",
        token_type="Bearer",
    )
    login = await oidc.complete("the-code", VERIFIER, "nn")
    assert login.principal.subject == "alice@example.com"
    assert login.principal.display_name == "Alice Example"
    assert login.principal.groups == frozenset({"devops", "analyst"})
    assert login.principal.auth_source == "oidc"
    assert login.refresh_token == "up-refresh"
    form = fake_issuer.form()
    assert form == {
        "grant_type": "authorization_code",
        "code": "the-code",
        "redirect_uri": REDIRECT,
        "code_verifier": VERIFIER,
    }
    basic = base64.b64encode(b"ratatoskr:upstream-secret").decode()
    assert fake_issuer.token_requests[-1].headers["authorization"] == f"Basic {basic}"


async def test_subject_and_groups_claims_are_configurable(http, clock, fake_issuer) -> None:
    provider = OidcIdentityProvider(settings(subject_claim="sub", groups_claim="roles"), REDIRECT, http, clock)
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn", roles=["dba"]))
    login = await provider.complete("c", VERIFIER, "nn")
    assert login.principal.subject == "a1b2c3"
    assert login.principal.groups == frozenset({"dba"})
    assert login.refresh_token is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"nonce": "other"}, "claims rejected"),
        ({"nonce": None}, "claims rejected"),
        ({"aud": "someone-else"}, "claims rejected"),
        ({"iss": "https://attacker.example.com/"}, "claims rejected"),
        ({"email": None}, "missing"),
    ],
)
async def test_invalid_id_token_claims_are_rejected(oidc, fake_issuer, overrides, message) -> None:
    claims = {"nonce": "nn", **overrides}
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(**claims))
    with pytest.raises(IdentityError, match=message):
        await oidc.complete("c", VERIFIER, "nn")


async def test_expired_id_token_is_rejected(oidc, fake_issuer, clock) -> None:
    token = fake_issuer.id_token(nonce="nn")
    clock.advance(300 + 61)
    fake_issuer.queue_token_response(id_token=token)
    with pytest.raises(IdentityError, match="claims rejected"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_several_audiences_require_azp(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn", aud=["ratatoskr", "other"]))
    with pytest.raises(IdentityError, match="azp"):
        await oidc.complete("c", VERIFIER, "nn")
    fake_issuer.queue_token_response(
        id_token=fake_issuer.id_token(nonce="nn", aud=["ratatoskr", "other"], azp="ratatoskr")
    )
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.subject == "alice@example.com"


async def test_signature_from_unknown_key_is_rejected(oidc, fake_issuer, other_rsa_key) -> None:
    forged = fake_issuer.id_token(key=other_rsa_key, header={"alg": "RS256", "kid": "key-1"}, nonce="nn")
    fake_issuer.queue_token_response(id_token=forged)
    with pytest.raises(IdentityError, match="signature"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_hmac_signed_token_is_rejected(oidc, fake_issuer) -> None:
    secret = OctKey.import_key("upstream-secret-upstream-secret-32")
    token = jwt.encode(
        {"alg": "HS256"},
        {"iss": fake_issuer.issuer, "aud": "ratatoskr", "email": "alice@example.com", "nonce": "nn"},
        secret,
    )
    fake_issuer.queue_token_response(id_token=token)
    with pytest.raises(IdentityError):
        await oidc.complete("c", VERIFIER, "nn")


async def test_key_rotation_refetches_jwks(oidc, fake_issuer, other_rsa_key) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    await oidc.complete("c", VERIFIER, "nn")
    assert fake_issuer.jwks_fetches == 1
    fake_issuer.jwks = dict(KeySet([other_rsa_key]).as_dict(private=False))
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(key=other_rsa_key, nonce="nn"))
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.subject == "alice@example.com"
    assert fake_issuer.jwks_fetches == 2


async def test_missing_id_token_is_rejected(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(access_token="only-access")
    with pytest.raises(IdentityError, match="id_token"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_refresh_rereads_groups_from_new_id_token(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(groups=["analyst"]), refresh_token="up-2")
    login = await oidc.refresh("up-1")
    assert login.principal.groups == frozenset({"analyst"})
    assert login.refresh_token == "up-2"
    assert fake_issuer.form() == {"grant_type": "refresh_token", "refresh_token": "up-1"}


async def test_refresh_without_id_token_uses_userinfo(oidc, fake_issuer) -> None:
    fake_issuer.userinfo = {"sub": "a1b2c3", "email": "alice@example.com", "groups": ["ops"]}
    fake_issuer.queue_token_response(access_token="up-access")
    login = await oidc.refresh("up-1")
    assert login.principal.groups == frozenset({"ops"})
    assert login.refresh_token == "up-1"


async def test_refresh_rejected_by_issuer(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(400, error="invalid_grant")
    with pytest.raises(UpstreamRejectedError, match="invalid_grant"):
        await oidc.refresh("up-1")


async def test_issuer_outage_is_reported_as_unavailable(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(503, error="unavailable")
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")


async def test_network_error_is_reported_as_unavailable(oidc, fake_issuer) -> None:
    fake_issuer.discovery["token_endpoint"] = "https://idp-down.example.com/token/"
    fake_issuer.router.post("https://idp-down.example.com/token/").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_identity_oidc.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.auth.identity.oidc'`.

- [ ] **Step 3: Implement**

```python
"""OIDC relying party for an upstream issuer such as Authentik (spec §5.2 ``oidc``, §5.3).

Authorization code flow with PKCE (S256), ``state`` and ``nonce``. ID tokens are verified against the issuer's
JWKS (signature, ``iss``, ``aud``/``azp``, ``exp``, ``iat``, ``nonce``); only asymmetric algorithms are accepted.
"""

import asyncio
from dataclasses import dataclass
from typing import Any, cast
from urllib.parse import urlencode

import httpx
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet, KeySetSerialization

from ratatoskr.auth.crypto import pkce_challenge
from ratatoskr.auth.identity.base import (
    ExternalLogin,
    IdentityError,
    UpstreamRejectedError,
    UpstreamUnavailableError,
)
from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import OidcSettings
from ratatoskr.state.records import Clock

ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
CLOCK_LEEWAY_SECONDS = 60


@dataclass(frozen=True)
class OidcMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None
    algorithms: tuple[str, ...]


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise IdentityError(f"OIDC discovery document has no {key!r}")
    return value


class OidcIdentityProvider:
    def __init__(self, settings: OidcSettings, redirect_uri: str, http: httpx.AsyncClient, clock: Clock) -> None:
        self._settings = settings
        self._issuer = str(settings.issuer)
        self._redirect_uri = redirect_uri
        self._http = http
        self._clock = clock
        self._metadata: OidcMetadata | None = None
        self._keys: KeySet | None = None
        self._lock = asyncio.Lock()

    # ── upstream HTTP ───────────────────────────────────────────────────

    async def _get_json(self, url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        try:
            response = await self._http.get(url, headers={"Accept": "application/json", **(headers or {})})
        except httpx.HTTPError as exc:
            raise UpstreamUnavailableError(f"GET {url} failed: {type(exc).__name__}") from exc
        if response.status_code >= 500:
            raise UpstreamUnavailableError(f"GET {url} returned HTTP {response.status_code}")
        if response.status_code != 200:
            raise UpstreamRejectedError(f"GET {url} returned HTTP {response.status_code}")
        return self._json_object(response, url)

    @staticmethod
    def _json_object(response: httpx.Response, url: str) -> dict[str, Any]:
        try:
            data = response.json()
        except ValueError as exc:
            raise IdentityError(f"{url} did not return JSON") from exc
        if not isinstance(data, dict):
            raise IdentityError(f"{url} did not return a JSON object")
        return data

    async def _token_request(self, form: dict[str, str]) -> dict[str, Any]:
        meta = await self.metadata()
        try:
            response = await self._http.post(
                meta.token_endpoint,
                data=form,
                auth=(self._settings.client_id, self._settings.client_secret.get_secret_value()),
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise UpstreamUnavailableError(f"token endpoint request failed: {type(exc).__name__}") from exc
        if response.status_code >= 500:
            raise UpstreamUnavailableError(f"token endpoint returned HTTP {response.status_code}")
        if response.status_code != 200:
            error = "unknown"
            try:
                body = response.json()
                if isinstance(body, dict) and isinstance(body.get("error"), str):
                    error = body["error"]
            except ValueError:
                pass
            raise UpstreamRejectedError(f"token endpoint returned HTTP {response.status_code} ({error})")
        return self._json_object(response, meta.token_endpoint)

    # ── discovery and keys ──────────────────────────────────────────────

    async def metadata(self) -> OidcMetadata:
        async with self._lock:
            if self._metadata is None:
                data = await self._get_json(self._issuer.rstrip("/") + "/.well-known/openid-configuration")
                issuer = _require_str(data, "issuer")
                if issuer.rstrip("/") != self._issuer.rstrip("/"):
                    raise IdentityError(f"OIDC discovery issuer {issuer!r} does not match configured issuer")
                advertised = data.get("id_token_signing_alg_values_supported")
                algorithms = (
                    tuple(a for a in advertised if a in ALLOWED_ALGORITHMS) if isinstance(advertised, list) else ()
                )
                userinfo = data.get("userinfo_endpoint")
                self._metadata = OidcMetadata(
                    issuer=issuer,
                    authorization_endpoint=_require_str(data, "authorization_endpoint"),
                    token_endpoint=_require_str(data, "token_endpoint"),
                    jwks_uri=_require_str(data, "jwks_uri"),
                    userinfo_endpoint=userinfo if isinstance(userinfo, str) else None,
                    algorithms=algorithms or ("RS256",),
                )
            return self._metadata

    async def _key_set(self, *, refresh: bool) -> KeySet:
        if self._keys is None or refresh:
            meta = await self.metadata()
            data = await self._get_json(meta.jwks_uri)
            try:
                self._keys = KeySet.import_key_set(cast(KeySetSerialization, data))
            except (JoseError, KeyError, TypeError, ValueError) as exc:
                raise IdentityError("issuer JWKS could not be imported") from exc
        return self._keys

    # ── ID token validation ─────────────────────────────────────────────

    async def _verify_id_token(self, id_token: str, nonce: str | None) -> dict[str, Any]:
        meta = await self.metadata()
        claims: dict[str, Any] | None = None
        for refresh in (False, True):
            keys = await self._key_set(refresh=refresh)
            try:
                claims = jwt.decode(id_token, keys, algorithms=list(meta.algorithms)).claims
                break
            except InvalidKeyIdError as exc:
                if refresh:
                    raise IdentityError("ID token is signed with a key the issuer does not publish") from exc
            except (JoseError, KeyError, ValueError) as exc:
                raise IdentityError(f"ID token signature rejected: {exc}") from exc
        if claims is None:
            raise IdentityError("ID token could not be verified")
        options: dict[str, jwt.ClaimsOption] = {
            "iss": {"essential": True, "value": meta.issuer},
            "aud": {"essential": True, "value": self._settings.client_id},
            "exp": {"essential": True},
            "iat": {"essential": True},
        }
        if nonce is not None:
            options["nonce"] = {"essential": True, "value": nonce}
        registry = jwt.JWTClaimsRegistry(now=int(self._clock()), leeway=CLOCK_LEEWAY_SECONDS, **options)
        try:
            registry.validate(claims)
        except JoseError as exc:
            raise IdentityError(f"ID token claims rejected: {exc}") from exc
        audience = claims["aud"]
        if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != self._settings.client_id:
            raise IdentityError("ID token has several audiences but azp is not this client")
        return claims

    def _principal(self, claims: dict[str, Any]) -> Principal:
        subject = claims.get(self._settings.subject_claim)
        if not isinstance(subject, str) or not subject:
            raise IdentityError(f"claim {self._settings.subject_claim!r} is missing from the identity")
        raw_groups = claims.get(self._settings.groups_claim, [])
        groups = frozenset(g for g in raw_groups if isinstance(g, str)) if isinstance(raw_groups, list) else frozenset()
        display = claims.get("name") or claims.get("preferred_username") or subject
        return Principal(
            subject=subject,
            display_name=display if isinstance(display, str) else subject,
            groups=groups,
            auth_source="oidc",
        )

    # ── public API ──────────────────────────────────────────────────────

    async def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        meta = await self.metadata()
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._settings.client_id,
                "redirect_uri": self._redirect_uri,
                "scope": " ".join(self._settings.scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": pkce_challenge(code_verifier),
                "code_challenge_method": "S256",
            }
        )
        separator = "&" if "?" in meta.authorization_endpoint else "?"
        return f"{meta.authorization_endpoint}{separator}{query}"

    async def complete(self, code: str, code_verifier: str, nonce: str) -> ExternalLogin:
        data = await self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._redirect_uri,
                "code_verifier": code_verifier,
            }
        )
        id_token = data.get("id_token")
        if not isinstance(id_token, str):
            raise IdentityError("token response has no id_token")
        claims = await self._verify_id_token(id_token, nonce)
        refresh = data.get("refresh_token")
        return ExternalLogin(self._principal(claims), refresh if isinstance(refresh, str) else None)

    async def refresh(self, refresh_token: str) -> ExternalLogin:
        data = await self._token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})
        id_token = data.get("id_token")
        if isinstance(id_token, str):
            claims = await self._verify_id_token(id_token, None)
        else:
            claims = await self._userinfo(data.get("access_token"))
        new_refresh = data.get("refresh_token")
        return ExternalLogin(self._principal(claims), new_refresh if isinstance(new_refresh, str) else refresh_token)

    async def _userinfo(self, access_token: object) -> dict[str, Any]:
        meta = await self.metadata()
        if not isinstance(access_token, str) or meta.userinfo_endpoint is None:
            raise IdentityError("refresh response has neither id_token nor a usable access token for userinfo")
        return await self._get_json(meta.userinfo_endpoint, {"Authorization": f"Bearer {access_token}"})
```

- [ ] **Step 4: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_identity_oidc.py -q && .venv/Scripts/python -m mypy src`
Expected: PASS (about 20 tests, under 2 s).

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/auth/identity/oidc.py tests/unit/secure_http/test_identity_oidc.py
git commit -m "Add OIDC relying party with JWKS ID-token validation and upstream refresh" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: OAuth authorization server provider

**Files:**
- Create: `src/ratatoskr/auth/events.py`, `src/ratatoskr/auth/oauth_server.py`
- Test: `tests/unit/secure_http/test_oauth_provider.py`

Behaviour beyond the SDK (see "SDK facts"): redirect hosts checked against `server.allowed_redirect_hosts` at DCR
(https required except localhost/127.0.0.1); client secrets sealed; `authorize` refuses a `resource` other than
`<public_url>` / `<public_url>/mcp` and a challenge that is not 43 base64url characters, then stores a pending
authorization (10 min) and redirects to `/login?request=…` — with a nonce and an upstream PKCE verifier already
generated in OIDC mode; codes are single-use (`take_code`), 5 min, bound to client + redirect_uri; tokens carry
`resource=<public_url>/mcp`; local users' groups are re-read from configuration on every request; OIDC refresh
re-validates at the issuer, re-reads groups, and revokes the family when the issuer refuses or the subject changes.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import sqlite3
from urllib.parse import parse_qs, urlsplit

import pytest
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl, SecretStr

from ratatoskr.auth.crypto import Keyring, hash_token, pkce_challenge
from ratatoskr.auth.identity.base import ExternalLogin, UpstreamRejectedError, UpstreamUnavailableError
from ratatoskr.auth.identity.local import LocalIdentityProvider
from ratatoskr.auth.oauth_server import RatatoskrOAuthProvider
from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import LocalUser

REDIRECT = "https://claude.ai/api/mcp/auth_callback"
VERIFIER = "x" * 64
KEREM = Principal(subject="kerem", display_name="kerem", groups=frozenset({"admins"}), auth_source="local")
ALICE = Principal(subject="alice@example.com", display_name="Alice", groups=frozenset({"devops"}), auth_source="oidc")


class FakeUpstream:
    def __init__(self) -> None:
        self.result: ExternalLogin | Exception = ExternalLogin(ALICE, "up-2")
        self.refreshed_with: list[str] = []

    async def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        return f"https://idp.example.com/authorize?state={state}"

    async def complete(self, code: str, code_verifier: str, nonce: str) -> ExternalLogin:
        return ExternalLogin(ALICE, "up-1")

    async def refresh(self, refresh_token: str) -> ExternalLogin:
        self.refreshed_with.append(refresh_token)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def local_users(password_hash: str, groups: list[str]) -> LocalIdentityProvider:
    return LocalIdentityProvider([LocalUser(username="kerem", password_hash=SecretStr(password_hash), groups=groups)])


@pytest.fixture
def build(make_config, store, audit, clock, password_hash):
    def factory(*, mode: str = "local", local=None, oidc=None) -> RatatoskrOAuthProvider:
        config = make_config(mode=mode, auth_extra={"access_token_ttl": "1h", "refresh_token_ttl": "30d"})
        return RatatoskrOAuthProvider(
            config,
            store=store,
            keyring=Keyring("k" * 48),
            audit=audit,
            clock=clock,
            local=local if local is not None else (local_users(password_hash, ["admins"]) if mode == "local" else None),
            oidc=oidc,
        )

    return factory


async def register(provider: RatatoskrOAuthProvider, client_id: str = "client-1") -> OAuthClientInformationFull:
    client = OAuthClientInformationFull(
        client_id=client_id,
        client_secret="client-secret-value",
        redirect_uris=[AnyUrl(REDIRECT)],
        token_endpoint_auth_method="client_secret_post",
        client_name="Claude",
        scope="mcp",
    )
    await provider.register_client(client)
    loaded = await provider.get_client(client_id)
    assert loaded is not None
    return loaded


def params(**overrides: object) -> AuthorizationParams:
    values: dict[str, object] = {
        "state": "client-state",
        "scopes": ["mcp"],
        "code_challenge": pkce_challenge(VERIFIER),
        "redirect_uri": AnyUrl(REDIRECT),
        "redirect_uri_provided_explicitly": True,
        "resource": "https://mcp.example.com/mcp",
        **overrides,
    }
    return AuthorizationParams.model_validate(values)


async def issue_code(
    provider: RatatoskrOAuthProvider, client: OAuthClientInformationFull, principal: Principal, upstream: str | None
) -> str:
    login_url = await provider.authorize(client, params())
    request_id = parse_qs(urlsplit(login_url).query)["request"][0]
    pending = await provider.take_pending(request_id)
    assert pending is not None
    redirect = await provider.complete_authorization(pending, principal, upstream)
    query = parse_qs(urlsplit(redirect).query)
    assert query["state"] == ["client-state"]
    return query["code"][0]


async def tokens_for(provider, client, principal=KEREM, upstream=None):
    code = await issue_code(provider, client, principal, upstream)
    loaded = await provider.load_authorization_code(client, code)
    assert loaded is not None
    return await provider.exchange_authorization_code(client, loaded)


# ── registration ────────────────────────────────────────────────────────────


async def test_registration_seals_client_secret(build, store, tmp_path) -> None:
    provider = build()
    client = await register(provider)
    assert client.client_secret == "client-secret-value"
    with sqlite3.connect(tmp_path / "state.db") as raw:
        row = raw.execute("SELECT metadata_json, secret_blob FROM clients").fetchone()
    assert "client-secret-value" not in row[0]
    assert b"client-secret-value" not in row[1]


@pytest.mark.parametrize(
    "uri", ["https://evil.example/cb", "http://claude.ai/api/mcp/auth_callback", "https://claude.ai.evil.example/cb"]
)
async def test_registration_rejects_disallowed_redirects(build, uri) -> None:
    client = OAuthClientInformationFull(client_id="c", redirect_uris=[AnyUrl(uri)], token_endpoint_auth_method="none")
    with pytest.raises(RegistrationError) as info:
        await build().register_client(client)
    assert info.value.error == "invalid_redirect_uri"


async def test_registration_rejects_unsupported_client_auth(build) -> None:
    client = OAuthClientInformationFull(
        client_id="c", redirect_uris=[AnyUrl(REDIRECT)], token_endpoint_auth_method="private_key_jwt"
    )
    with pytest.raises(RegistrationError) as info:
        await build().register_client(client)
    assert info.value.error == "invalid_client_metadata"


async def test_secret_sealed_under_other_key_hides_client(build, make_config, store, audit, clock) -> None:
    await register(build())
    other = RatatoskrOAuthProvider(make_config(), store=store, keyring=Keyring("z" * 48), audit=audit, clock=clock)
    assert await other.get_client("client-1") is None


# ── authorize ───────────────────────────────────────────────────────────────


async def test_authorize_returns_login_url_with_opaque_request(build) -> None:
    provider = build()
    client = await register(provider)
    url = await provider.authorize(client, params())
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://mcp.example.com/login"
    request_id = parse_qs(parts.query)["request"][0]
    pending = await provider.load_pending(request_id)
    assert pending is not None
    assert pending.client.client_name == "Claude"
    assert pending.pending.nonce is None


async def test_authorize_prepares_oidc_nonce_and_verifier(build) -> None:
    provider = build(mode="oidc", oidc=FakeUpstream())
    client = await register(provider)
    url = await provider.authorize(client, params())
    pending = await provider.load_pending(parse_qs(urlsplit(url).query)["request"][0])
    assert pending is not None
    assert pending.pending.nonce and pending.pending.upstream_verifier
    assert len(pending.pending.upstream_verifier) >= 43


@pytest.mark.parametrize(
    "overrides",
    [
        {"resource": "https://other-server.example.com/mcp"},
        {"code_challenge": "too-short"},
        {"code_challenge": "!" * 43},
    ],
)
async def test_authorize_rejects_bad_requests(build, overrides) -> None:
    provider = build()
    client = await register(provider)
    with pytest.raises(AuthorizeError) as info:
        await provider.authorize(client, params(**overrides))
    assert info.value.error == "invalid_request"


async def test_authorize_accepts_origin_as_resource_or_none(build) -> None:
    provider = build()
    client = await register(provider)
    await provider.authorize(client, params(resource="https://mcp.example.com"))
    await provider.authorize(client, params(resource=None))


# ── codes ───────────────────────────────────────────────────────────────────


async def test_code_is_single_use_and_bound_to_client(build) -> None:
    provider = build()
    client = await register(provider)
    other = await register(provider, "client-2")
    code = await issue_code(provider, client, KEREM, None)
    assert await provider.load_authorization_code(other, code) is None
    loaded = await provider.load_authorization_code(client, code)
    assert loaded is not None
    assert loaded.code_challenge == pkce_challenge(VERIFIER)
    assert str(loaded.redirect_uri) == REDIRECT
    assert loaded.subject == "kerem"
    tokens = await provider.exchange_authorization_code(client, loaded)
    assert tokens.access_token and tokens.refresh_token and tokens.expires_in == 3600
    assert await provider.load_authorization_code(client, code) is None
    with pytest.raises(TokenError) as info:
        await provider.exchange_authorization_code(client, loaded)
    assert info.value.error == "invalid_grant"


async def test_code_expires_after_five_minutes(build, clock) -> None:
    provider = build()
    client = await register(provider)
    code = await issue_code(provider, client, KEREM, None)
    clock.advance(301)
    assert await provider.load_authorization_code(client, code) is None


async def test_pending_request_expires_after_ten_minutes(build, clock) -> None:
    provider = build()
    client = await register(provider)
    url = await provider.authorize(client, params())
    clock.advance(601)
    assert await provider.load_pending(parse_qs(urlsplit(url).query)["request"][0]) is None


# ── access tokens ───────────────────────────────────────────────────────────


async def test_tokens_are_stored_only_as_hashes(build, tmp_path) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    dump = "\n".join(sqlite3.connect(tmp_path / "state.db").iterdump())
    assert tokens.access_token not in dump and tokens.refresh_token not in dump
    assert hash_token(tokens.access_token) in dump


async def test_access_token_carries_identity(build) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    access = await provider.load_access_token(tokens.access_token)
    assert access is not None
    assert (access.subject, access.display_name, access.groups, access.auth_source) == (
        "kerem",
        "kerem",
        ["admins"],
        "local",
    )
    assert access.client_id == "client-1" and access.scopes == ["mcp"]
    assert access.resource == "https://mcp.example.com/mcp"
    assert await provider.load_access_token("not-a-token") is None


async def test_access_token_expires(build, clock) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    clock.advance(3601)
    assert await provider.load_access_token(tokens.access_token) is None


async def test_local_groups_follow_configuration(build, password_hash) -> None:
    issuing = build(local=local_users(password_hash, ["admins"]))
    client = await register(issuing)
    tokens = await tokens_for(issuing, client)
    regrouped = build(local=local_users(password_hash, ["analyst"]))
    access = await regrouped.load_access_token(tokens.access_token)
    assert access is not None and access.groups == ["analyst"]


async def test_removed_local_user_loses_access(build, password_hash) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    without_user = build(local=LocalIdentityProvider([]))
    assert await without_user.load_access_token(tokens.access_token) is None


# ── refresh rotation and reuse detection ───────────────────────────────────


async def refresh(provider, client, refresh_token: str):
    loaded = await provider.load_refresh_token(client, refresh_token)
    assert loaded is not None
    return await provider.exchange_refresh_token(client, loaded, loaded.scopes)


async def test_refresh_rotates_both_tokens(build) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    second = await refresh(provider, client, first.refresh_token)
    assert second.refresh_token != first.refresh_token and second.access_token != first.access_token
    assert await provider.load_access_token(first.access_token) is None
    assert await provider.load_access_token(second.access_token) is not None


async def test_refresh_reuse_revokes_the_family(build, audit) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    second = await refresh(provider, client, first.refresh_token)
    assert await provider.load_refresh_token(client, first.refresh_token) is None
    assert "token_reuse_detected" in audit.names()
    assert await provider.load_access_token(second.access_token) is None
    assert await provider.load_refresh_token(client, second.refresh_token) is None


async def test_concurrent_refresh_is_treated_as_reuse(build, audit) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    loaded_a = await provider.load_refresh_token(client, first.refresh_token)
    loaded_b = await provider.load_refresh_token(client, first.refresh_token)
    assert loaded_a is not None and loaded_b is not None
    winner = await provider.exchange_refresh_token(client, loaded_a, ["mcp"])
    with pytest.raises(TokenError) as info:
        await provider.exchange_refresh_token(client, loaded_b, ["mcp"])
    assert info.value.error == "invalid_grant"
    assert "token_reuse_detected" in audit.names()
    assert await provider.load_access_token(winner.access_token) is None


async def test_refresh_token_belongs_to_its_client(build) -> None:
    provider = build()
    client = await register(provider)
    other = await register(provider, "client-2")
    first = await tokens_for(provider, client)
    assert await provider.load_refresh_token(other, first.refresh_token) is None
    assert await provider.load_refresh_token(client, first.access_token) is None


async def test_refresh_token_expires(build, clock) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    clock.advance(30 * 86400 + 1)
    assert await provider.load_refresh_token(client, first.refresh_token) is None


async def test_refresh_fails_for_removed_local_user(build, password_hash) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    without_user = build(local=LocalIdentityProvider([]))
    loaded = await without_user.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError):
        await without_user.exchange_refresh_token(client, loaded, ["mcp"])
    assert await provider.load_refresh_token(client, first.refresh_token) is None


# ── revoke ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("which", ["access", "refresh"])
async def test_revoke_kills_the_whole_family(build, audit, which) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    if which == "access":
        target = await provider.load_access_token(tokens.access_token)
    else:
        target = await provider.load_refresh_token(client, tokens.refresh_token)
    assert target is not None
    await provider.revoke_token(target)
    assert await provider.load_access_token(tokens.access_token) is None
    assert await provider.load_refresh_token(client, tokens.refresh_token) is None
    assert "token_revoked" in audit.names()


# ── OIDC upstream re-validation ─────────────────────────────────────────────


async def test_oidc_refresh_rereads_groups_and_reseals_upstream(build, store) -> None:
    upstream = FakeUpstream()
    upstream.result = ExternalLogin(
        Principal(ALICE.subject, ALICE.display_name, frozenset({"analyst"}), "oidc"), "up-2"
    )
    provider = build(mode="oidc", oidc=upstream)
    client = await register(provider)
    first = await tokens_for(provider, client, ALICE, upstream="up-1")
    second = await refresh(provider, client, first.refresh_token)
    assert upstream.refreshed_with == ["up-1"]
    access = await provider.load_access_token(second.access_token)
    assert access is not None and access.groups == ["analyst"] and access.auth_source == "oidc"
    third = await refresh(provider, client, second.refresh_token)
    assert upstream.refreshed_with == ["up-1", "up-2"]
    assert third.access_token


@pytest.mark.parametrize("failure", [UpstreamRejectedError("inactive"), None])
async def test_oidc_upstream_failure_revokes_family(build, audit, failure) -> None:
    upstream = FakeUpstream()
    provider = build(mode="oidc", oidc=upstream)
    client = await register(provider)
    first = await tokens_for(provider, client, ALICE, upstream=None if failure is None else "up-1")
    if failure is not None:
        upstream.result = failure
    loaded = await provider.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError) as info:
        await provider.exchange_refresh_token(client, loaded, ["mcp"])
    assert info.value.error == "invalid_grant"
    assert "upstream_refresh_failed" in audit.names()
    assert await provider.load_access_token(first.access_token) is None


async def test_oidc_subject_change_revokes_family(build) -> None:
    upstream = FakeUpstream()
    upstream.result = ExternalLogin(Principal("mallory@example.com", "M", frozenset(), "oidc"), "up-2")
    provider = build(mode="oidc", oidc=upstream)
    client = await register(provider)
    first = await tokens_for(provider, client, ALICE, upstream="up-1")
    loaded = await provider.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError):
        await provider.exchange_refresh_token(client, loaded, ["mcp"])
    assert await provider.load_access_token(first.access_token) is None


async def test_oidc_outage_keeps_the_family(build) -> None:
    upstream = FakeUpstream()
    upstream.result = UpstreamUnavailableError("timeout")
    provider = build(mode="oidc", oidc=upstream)
    client = await register(provider)
    first = await tokens_for(provider, client, ALICE, upstream="up-1")
    loaded = await provider.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError) as info:
        await provider.exchange_refresh_token(client, loaded, ["mcp"])
    assert info.value.error == "invalid_request"
    assert await provider.load_access_token(first.access_token) is not None
    upstream.result = ExternalLogin(ALICE, None)
    assert (await refresh(provider, client, first.refresh_token)).access_token
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_oauth_provider.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.auth.oauth_server'`.

- [ ] **Step 3: Implement the auth-event helper**

`src/ratatoskr/auth/events.py`:

```python
"""Audit events for authentication (login, token reuse, upstream refresh)."""

from datetime import UTC, datetime
from typing import Literal

from ratatoskr.observability.audit import AuditEvent, AuditResult, AuditSink

AuthEventName = Literal[
    "login_succeeded",
    "login_failed",
    "login_rate_limited",
    "token_reuse_detected",
    "token_revoked",
    "upstream_refresh_failed",
]


def record_auth_event(
    sink: AuditSink,
    name: AuthEventName,
    *,
    subject: str,
    auth_source: str,
    result: AuditResult,
    error_class: str | None = None,
) -> None:
    """Auth events reuse :class:`AuditEvent`: ``tool`` carries the event name, ``connection`` is ``None``."""
    sink.record(
        AuditEvent(
            ts=datetime.now(UTC),
            subject=subject,
            auth_source=auth_source,
            connection=None,
            tool=name,
            query_text=None,
            query_sha256=None,
            duration_ms=0.0,
            rows=None,
            result=result,
            error_class=error_class,
        )
    )
```

- [ ] **Step 4: Implement the provider**

`src/ratatoskr/auth/oauth_server.py`:

```python
"""MCP OAuth 2.1 authorization server backed by the state store (spec §5.2).

The SDK handlers already enforce: ``code_challenge`` present and method ``S256`` (``/authorize``), redirect_uri
registered for the client, PKCE verifier match, redirect_uri equality between ``/authorize`` and ``/token``, code
and refresh-token expiry, client authentication and refresh scope narrowing. This provider adds what the SDK leaves
to us: the redirect host allowlist, S256 challenge shape, RFC 8707 resource binding, single-use codes, hashed
storage, refresh rotation with reuse detection, family revocation and upstream (OIDC) re-validation.
"""

import logging
import re
import secrets
from dataclasses import dataclass
from typing import NoReturn
from urllib.parse import urlencode

from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from ratatoskr.auth.crypto import DecryptionError, Keyring, hash_token, new_token
from ratatoskr.auth.events import record_auth_event
from ratatoskr.auth.identity.base import (
    IdentityError,
    PasswordIdentityProvider,
    RedirectIdentityProvider,
    UpstreamUnavailableError,
)
from ratatoskr.auth.principal import Principal
from ratatoskr.auth.redirects import redirect_uri_problem
from ratatoskr.auth.tokens import AuthSource, RatatoskrAccessToken, RatatoskrRefreshToken
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import AuditSink
from ratatoskr.state.records import AuthCodeRecord, Clock, PendingAuthorization, StoredClient, TokenRecord
from ratatoskr.state.store import Store

logger = logging.getLogger("ratatoskr.auth.oauth")

PENDING_TTL_SECONDS = 600.0
CODE_TTL_SECONDS = 300.0
DEFAULT_SCOPES = ["mcp"]
MCP_PATH = "/mcp"
_S256_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_SUPPORTED_CLIENT_AUTH = frozenset({"none", "client_secret_post", "client_secret_basic"})


def _client_id(client: OAuthClientInformationFull) -> str:
    if client.client_id is None:
        raise RegistrationError("invalid_client_metadata", "client_id is missing")
    return client.client_id


def _source(principal: Principal) -> AuthSource:
    if principal.auth_source == "stdio":
        raise ValueError("stdio principals never receive OAuth tokens")
    return principal.auth_source


@dataclass(frozen=True)
class PendingRequest:
    """A pending authorization joined with its client and the original ``/authorize`` parameters."""

    pending: PendingAuthorization
    client: OAuthClientInformationFull
    params: AuthorizationParams


class RatatoskrOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RatatoskrRefreshToken, RatatoskrAccessToken]
):
    def __init__(
        self,
        config: RatatoskrConfig,
        *,
        store: Store,
        keyring: Keyring,
        audit: AuditSink,
        clock: Clock,
        local: PasswordIdentityProvider | None = None,
        oidc: RedirectIdentityProvider | None = None,
    ) -> None:
        if config.auth is None or config.server.public_url is None:
            raise ValueError("the OAuth provider needs auth settings and server.public_url")
        self._public_url = str(config.server.public_url).rstrip("/")
        self.resource_url = self._public_url + MCP_PATH
        self._resources = frozenset({self._public_url, self.resource_url})
        self._allowed_hosts = list(config.server.allowed_redirect_hosts)
        self._access_ttl = config.auth.access_token_ttl.total_seconds()
        self._refresh_ttl = config.auth.refresh_token_ttl.total_seconds()
        self._store = store
        self._keyring = keyring
        self._audit = audit
        self._clock = clock
        self._local = local
        self._oidc = oidc

    # ── clients (DCR) ───────────────────────────────────────────────────

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        stored = await self._store.get_client(client_id)
        if stored is None:
            return None
        client = OAuthClientInformationFull.model_validate_json(stored.metadata_json)
        if stored.secret_blob is not None:
            try:
                secret = self._keyring.client_secrets.open(stored.secret_blob, aad=client_id)
            except DecryptionError:
                logger.warning("client %s has a secret sealed under a different server.secret_key", client_id)
                return None
            client = client.model_copy(update={"client_secret": secret})
        return client

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        client_id = _client_id(client_info)
        if client_info.token_endpoint_auth_method not in _SUPPORTED_CLIENT_AUTH:
            raise RegistrationError(
                "invalid_client_metadata", "token_endpoint_auth_method must be none, client_secret_post or basic"
            )
        if not client_info.redirect_uris:
            raise RegistrationError("invalid_redirect_uri", "at least one redirect_uri is required")
        for uri in client_info.redirect_uris:
            problem = redirect_uri_problem(str(uri), self._allowed_hosts)
            if problem is not None:
                raise RegistrationError("invalid_redirect_uri", problem)
        secret_blob = (
            self._keyring.client_secrets.seal(client_info.client_secret, aad=client_id)
            if client_info.client_secret
            else None
        )
        metadata = client_info.model_copy(update={"client_secret": None}).model_dump_json(exclude_none=True)
        await self._store.save_client(StoredClient(client_id, metadata, secret_blob, self._clock()))
        logger.info("registered OAuth client %s (%s)", client_id, client_info.client_name or "unnamed")

    # ── authorization ───────────────────────────────────────────────────

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource is not None and params.resource.rstrip("/") not in self._resources:
            raise AuthorizeError("invalid_request", "resource does not identify this MCP server")
        if not _S256_CHALLENGE.fullmatch(params.code_challenge):
            raise AuthorizeError("invalid_request", "code_challenge must be a base64url S256 challenge")
        pending_id = new_token()
        oidc_flow = self._oidc is not None
        await self._store.save_pending(
            PendingAuthorization(
                id=pending_id,
                client_id=_client_id(client),
                params_json=params.model_dump_json(),
                expires_at=self._clock() + PENDING_TTL_SECONDS,
                nonce=new_token() if oidc_flow else None,
                upstream_verifier=secrets.token_urlsafe(64) if oidc_flow else None,
            )
        )
        return f"{self._public_url}/login?{urlencode({'request': pending_id})}"

    async def _join(self, pending: PendingAuthorization | None) -> PendingRequest | None:
        if pending is None:
            return None
        client = await self.get_client(pending.client_id)
        if client is None:
            return None
        return PendingRequest(pending, client, AuthorizationParams.model_validate_json(pending.params_json))

    async def load_pending(self, pending_id: str) -> PendingRequest | None:
        return await self._join(await self._store.get_pending(pending_id, self._clock()))

    async def take_pending(self, pending_id: str) -> PendingRequest | None:
        return await self._join(await self._store.take_pending(pending_id, self._clock()))

    async def complete_authorization(
        self, request: PendingRequest, principal: Principal, upstream_refresh_token: str | None
    ) -> str:
        """Issue a single-use code for ``principal`` and return the client redirect URL carrying it."""
        code = new_token()
        upstream_blob = (
            self._keyring.upstream.seal(upstream_refresh_token, aad=principal.subject)
            if upstream_refresh_token
            else None
        )
        await self._store.save_code(
            AuthCodeRecord(
                code_hash=hash_token(code),
                client_id=request.pending.client_id,
                params_json=request.pending.params_json,
                principal=principal,
                upstream_blob=upstream_blob,
                expires_at=self._clock() + CODE_TTL_SECONDS,
            )
        )
        return construct_redirect_uri(str(request.params.redirect_uri), code=code, state=request.params.state)

    @staticmethod
    def denied_redirect(request: PendingRequest) -> str:
        return construct_redirect_uri(
            str(request.params.redirect_uri), error="access_denied", state=request.params.state
        )

    # ── authorization codes ─────────────────────────────────────────────

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        record = await self._store.get_code(hash_token(authorization_code), self._clock())
        if record is None or record.client_id != client.client_id:
            return None
        params = AuthorizationParams.model_validate_json(record.params_json)
        return AuthorizationCode(
            code=authorization_code,
            scopes=params.scopes or list(DEFAULT_SCOPES),
            expires_at=record.expires_at,
            client_id=record.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=record.principal.subject,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        now = self._clock()
        record = await self._store.take_code(hash_token(authorization_code.code), now)
        if record is None or record.client_id != client.client_id:
            raise TokenError("invalid_grant", "authorization code is invalid or was already used")
        access, refresh, response = self._new_pair(
            family_id=new_token(),
            client_id=record.client_id,
            scopes=authorization_code.scopes,
            principal=record.principal,
            now=now,
        )
        await self._store.create_family(access, refresh, record.upstream_blob)
        return response

    # ── tokens ──────────────────────────────────────────────────────────

    def _new_pair(
        self, *, family_id: str, client_id: str, scopes: list[str], principal: Principal, now: float
    ) -> tuple[TokenRecord, TokenRecord, OAuthToken]:
        access_token = new_token()
        refresh_token = new_token()

        def record(token: str, kind: str, ttl: float) -> TokenRecord:
            return TokenRecord(
                token_hash=hash_token(token),
                kind="access" if kind == "access" else "refresh",
                family_id=family_id,
                client_id=client_id,
                scopes=tuple(scopes),
                resource=self.resource_url,
                principal=principal,
                created_at=now,
                expires_at=now + ttl,
            )

        response = OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=int(self._access_ttl),
            refresh_token=refresh_token,
            scope=" ".join(scopes),
        )
        access = record(access_token, "access", self._access_ttl)
        return access, record(refresh_token, "refresh", self._refresh_ttl), response

    async def load_access_token(self, token: str) -> RatatoskrAccessToken | None:
        record = await self._store.get_token(hash_token(token))
        if record is None or record.kind != "access" or record.revoked_at is not None:
            return None
        if record.expires_at <= self._clock():
            return None
        principal = record.principal
        if principal.auth_source == "local":
            current = self._local.lookup(principal.subject) if self._local is not None else None
            if current is None:
                return None
            principal = current
        return RatatoskrAccessToken(
            token=token,
            client_id=record.client_id,
            scopes=list(record.scopes),
            expires_at=int(record.expires_at),
            resource=record.resource,
            subject=principal.subject,
            display_name=principal.display_name,
            groups=sorted(principal.groups),
            auth_source=_source(principal),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RatatoskrRefreshToken | None:
        record = await self._store.get_token(hash_token(refresh_token))
        if record is None or record.kind != "refresh" or record.client_id != client.client_id:
            return None
        now = self._clock()
        if record.revoked_at is not None or record.expires_at <= now:
            return None
        if record.used_at is not None:
            await self._store.revoke_family(record.family_id, now)
            self._report_reuse(record.principal)
            return None
        return RatatoskrRefreshToken(
            token=refresh_token,
            client_id=record.client_id,
            scopes=list(record.scopes),
            expires_at=int(record.expires_at),
            resource=record.resource,
            family_id=record.family_id,
            subject=record.principal.subject,
            display_name=record.principal.display_name,
            groups=sorted(record.principal.groups),
            auth_source=_source(record.principal),
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RatatoskrRefreshToken, scopes: list[str]
    ) -> OAuthToken:
        now = self._clock()
        principal = Principal(
            subject=refresh_token.subject,
            display_name=refresh_token.display_name,
            groups=frozenset(refresh_token.groups),
            auth_source=refresh_token.auth_source,
        )
        upstream_blob: bytes | None = None
        if principal.auth_source == "oidc":
            principal, upstream_blob = await self._refresh_upstream(refresh_token.family_id, principal, now)
        else:
            current = self._local.lookup(principal.subject) if self._local is not None else None
            if current is None:
                await self._store.revoke_family(refresh_token.family_id, now)
                raise TokenError("invalid_grant", "the user no longer exists")
            principal = current
        access, refresh, response = self._new_pair(
            family_id=refresh_token.family_id,
            client_id=refresh_token.client_id,
            scopes=scopes,
            principal=principal,
            now=now,
        )
        outcome = await self._store.rotate_refresh(hash_token(refresh_token.token), access, refresh, upstream_blob, now)
        if outcome == "reused":
            self._report_reuse(principal)
            raise TokenError("invalid_grant", "refresh token was already used; the session has been revoked")
        if outcome == "invalid":
            raise TokenError("invalid_grant", "refresh token is no longer valid")
        return response

    async def _refresh_upstream(self, family_id: str, principal: Principal, now: float) -> tuple[Principal, bytes]:
        if self._oidc is None:
            await self._upstream_failed(family_id, principal, now, "OIDC is not configured")
        blob = await self._store.get_upstream(family_id)
        if blob is None:
            await self._upstream_failed(family_id, principal, now, "no upstream session is stored")
        try:
            upstream_token = self._keyring.upstream.open(blob, aad=principal.subject)
        except DecryptionError:
            await self._upstream_failed(family_id, principal, now, "upstream session cannot be decrypted")
        try:
            login = await self._oidc.refresh(upstream_token)
        except UpstreamUnavailableError as exc:
            logger.warning("upstream refresh for %s deferred: %s", principal.subject, exc)
            raise TokenError("invalid_request", "identity provider is temporarily unavailable; retry later") from exc
        except IdentityError as exc:
            await self._upstream_failed(family_id, principal, now, str(exc))
        if login.principal.subject != principal.subject:
            await self._upstream_failed(family_id, principal, now, "upstream subject changed")
        new_upstream = login.refresh_token or upstream_token
        return login.principal, self._keyring.upstream.seal(new_upstream, aad=principal.subject)

    async def _upstream_failed(self, family_id: str, principal: Principal, now: float, reason: str) -> NoReturn:
        await self._store.revoke_family(family_id, now)
        logger.warning("upstream refresh failed for %s; token family revoked: %s", principal.subject, reason)
        record_auth_event(
            self._audit,
            "upstream_refresh_failed",
            subject=principal.subject,
            auth_source=principal.auth_source,
            result="denied",
            error_class="upstream_refresh_failed",
        )
        raise TokenError("invalid_grant", "the identity provider no longer accepts this session")

    def _report_reuse(self, principal: Principal) -> None:
        logger.warning("refresh token reuse detected for %s; token family revoked", principal.subject)
        record_auth_event(
            self._audit,
            "token_reuse_detected",
            subject=principal.subject,
            auth_source=principal.auth_source,
            result="denied",
            error_class="token_reuse_detected",
        )

    async def revoke_token(self, token: RatatoskrAccessToken | RatatoskrRefreshToken) -> None:
        record = await self._store.get_token(hash_token(token.token))
        if record is None:
            return
        revoked = await self._store.revoke_family(record.family_id, self._clock())
        if revoked:
            record_auth_event(
                self._audit,
                "token_revoked",
                subject=record.principal.subject,
                auth_source=record.principal.auth_source,
                result="ok",
            )
```

- [ ] **Step 5: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_oauth_provider.py -q && .venv/Scripts/python -m mypy src && .venv/Scripts/python -m ruff check src tests`
Expected: PASS (33 tests).

- [ ] **Step 6: Commit**

```bash
git add src/ratatoskr/auth/events.py src/ratatoskr/auth/oauth_server.py tests/unit/secure_http/test_oauth_provider.py
git commit -m "Add store-backed OAuth provider with rotation, reuse detection and upstream re-validation" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: CSRF protection and login pages

**Files:**
- Create: `src/ratatoskr/auth/csrf.py`, `src/ratatoskr/auth/pages.py`
- Test: `tests/unit/secure_http/test_auth_csrf.py`, `tests/unit/secure_http/test_auth_pages.py`

The CSRF cookie is random, `HttpOnly`, `SameSite=Strict` and `__Host-` prefixed (`Secure`, `Path=/`) whenever
`public_url` is https; the form token is `HMAC(csrf_key, request_id:cookie)`, so it is bound to one pending
authorization. CSP allows the single inline stylesheet by SHA-256 hash only, and `form-action` lists the client's
redirect origin because browsers apply `form-action` to the redirect that follows the POST.

- [ ] **Step 1: Write the failing tests**

`tests/unit/secure_http/test_auth_csrf.py`:

```python
from __future__ import annotations

from starlette.responses import Response

from ratatoskr.auth.crypto import Keyring
from ratatoskr.auth.csrf import CsrfProtector


def protector(secure: bool = True) -> CsrfProtector:
    return CsrfProtector(Keyring("s" * 32).csrf, secure=secure)


def test_issued_pair_verifies() -> None:
    csrf = protector()
    cookie, form_token = csrf.issue("req-1")
    assert csrf.verify("req-1", cookie, form_token)


def test_missing_or_mismatched_values_fail() -> None:
    csrf = protector()
    cookie, form_token = csrf.issue("req-1")
    assert not csrf.verify("req-1", None, form_token)
    assert not csrf.verify("req-1", cookie, None)
    assert not csrf.verify("", cookie, form_token)
    assert not csrf.verify("req-2", cookie, form_token)
    other_cookie, _ = csrf.issue("req-1")
    assert not csrf.verify("req-1", other_cookie, form_token)


def test_token_from_another_secret_fails() -> None:
    cookie, form_token = CsrfProtector(Keyring("x" * 32).csrf, secure=True).issue("req-1")
    assert not protector().verify("req-1", cookie, form_token)


def test_cookie_attributes() -> None:
    response = Response()
    csrf = protector(secure=True)
    csrf.set_cookie(response, "value")
    header = response.headers["set-cookie"]
    assert header.startswith("__Host-ratatoskr-csrf=value")
    for attribute in ("HttpOnly", "Path=/", "SameSite=strict", "Secure", "Max-Age=600"):
        assert attribute in header


def test_insecure_dev_cookie_has_no_host_prefix_or_secure_flag() -> None:
    response = Response()
    csrf = protector(secure=False)
    csrf.set_cookie(response, "value")
    header = response.headers["set-cookie"]
    assert csrf.cookie_name == "ratatoskr-csrf"
    assert header.startswith("ratatoskr-csrf=value") and "Secure" not in header
```

`tests/unit/secure_http/test_auth_pages.py`:

```python
from __future__ import annotations

import base64
import hashlib
import re

from starlette.responses import RedirectResponse

from ratatoskr.auth.pages import apply_security_headers, login_page, message_page, origin_of


def render(**overrides: object):
    values: dict[str, object] = {
        "request_id": "req-1",
        "csrf_token": "tok",
        "client_name": "Claude",
        "redirect_uri": "https://claude.ai/api/mcp/auth_callback",
        **overrides,
    }
    return login_page(**values)  # type: ignore[arg-type]


def test_login_page_shows_client_and_redirect_host() -> None:
    body = render().body.decode()
    assert "<strong>Claude</strong>" in body and "<strong>claude.ai</strong>" in body
    assert 'name="request" value="req-1"' in body and 'name="csrf_token" value="tok"' in body


def test_login_page_escapes_attacker_controlled_values() -> None:
    body = render(client_name='<script>alert("x")</script>', username='"><img src=x>').body.decode()
    assert "<script>" not in body and "<img" not in body
    assert "&lt;script&gt;" in body


def test_long_client_names_are_truncated() -> None:
    assert "A" * 81 not in render(client_name="A" * 500).body.decode()


def test_security_headers_on_login_page() -> None:
    headers = render().headers
    csp = headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self' https://claude.ai" in csp
    assert "base-uri 'none'" in csp
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"] == "no-store"


def test_inline_style_is_allowed_only_by_hash() -> None:
    response = render()
    style = re.search(r"<style>(.*?)</style>", response.body.decode(), re.S)
    assert style is not None
    digest = base64.b64encode(hashlib.sha256(style.group(1).encode()).digest()).decode()
    assert f"style-src 'sha256-{digest}'" in response.headers["content-security-policy"]
    assert "unsafe-inline" not in response.headers["content-security-policy"]


def test_message_page_and_redirect_headers() -> None:
    page = message_page("Expired <b>", "Try again & again", 400)
    assert page.status_code == 400 and "Expired &lt;b&gt;" in page.body.decode()
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    redirect = apply_security_headers(RedirectResponse("https://claude.ai/cb", status_code=302))
    assert redirect.headers["referrer-policy"] == "no-referrer"


def test_origin_of() -> None:
    assert origin_of("https://claude.ai/api/mcp/auth_callback?x=1") == "https://claude.ai"
    assert origin_of("http://localhost:6274/cb") == "http://localhost:6274"
```

- [ ] **Step 2: Run them**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_auth_csrf.py tests/unit/secure_http/test_auth_pages.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.auth.csrf'` / `'ratatoskr.auth.pages'`.

- [ ] **Step 3: Implement CSRF**

`src/ratatoskr/auth/csrf.py`:

```python
"""Login-form CSRF protection: a random cookie plus a form token that signs (pending request id, cookie value).

The cookie is ``HttpOnly`` and ``SameSite=Strict``; an attacker can neither read it nor make the browser send it
cross-site, and the form token cannot be forged without ``server.secret_key``.
"""

from starlette.responses import Response

from ratatoskr.auth.crypto import Signer, new_token

CSRF_COOKIE_MAX_AGE = 600


class CsrfProtector:
    def __init__(self, signer: Signer, *, secure: bool) -> None:
        self._signer = signer
        self._secure = secure
        self.cookie_name = "__Host-ratatoskr-csrf" if secure else "ratatoskr-csrf"

    def issue(self, request_id: str) -> tuple[str, str]:
        """Return ``(cookie_value, form_token)`` for a fresh login form."""
        cookie_value = new_token()
        return cookie_value, self._signer.sign(f"{request_id}:{cookie_value}")

    def verify(self, request_id: str, cookie_value: str | None, form_token: str | None) -> bool:
        if not request_id or not cookie_value or not form_token:
            return False
        return self._signer.verify(f"{request_id}:{cookie_value}", form_token)

    def set_cookie(self, response: Response, cookie_value: str) -> None:
        response.set_cookie(
            self.cookie_name,
            cookie_value,
            max_age=CSRF_COOKIE_MAX_AGE,
            path="/",
            secure=self._secure,
            httponly=True,
            samesite="strict",
        )

    def clear_cookie(self, response: Response) -> None:
        response.delete_cookie(self.cookie_name, path="/", secure=self._secure, httponly=True, samesite="strict")
```

- [ ] **Step 4: Implement the pages**

`src/ratatoskr/auth/pages.py`:

```python
"""HTML for the sign-in pages and the security headers every auth page carries."""

import base64
import hashlib
from html import escape
from urllib.parse import urlsplit

from starlette.responses import HTMLResponse, Response

_STYLE = (
    "body{font-family:system-ui,sans-serif;max-width:380px;margin:80px auto;padding:0 20px;color:#1a1a1a}"
    "h1{font-size:1.15rem}p{line-height:1.4}.muted{color:#555;font-size:.9rem}.error{color:#b00020}"
    "input{width:100%;padding:10px;margin:0 0 12px;box-sizing:border-box;border:1px solid #bbb;border-radius:6px}"
    "button{width:100%;padding:10px;border:0;border-radius:6px;background:#1a1a1a;color:#fff;cursor:pointer}"
)
_STYLE_SOURCE = "'sha256-" + base64.b64encode(hashlib.sha256(_STYLE.encode()).digest()).decode() + "'"
_MAX_CLIENT_NAME = 80


def origin_of(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}"


def apply_security_headers[R: Response](response: R, *, form_action_origin: str | None = None) -> R:
    form_action = "'self'" if form_action_origin is None else f"'self' {form_action_origin}"
    response.headers["Content-Security-Policy"] = (
        f"default-src 'none'; style-src {_STYLE_SOURCE}; form-action {form_action}; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def _document(title: str, body: str) -> str:
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body>{body}</body></html>"
    )


def login_page(
    *,
    request_id: str,
    csrf_token: str,
    client_name: str | None,
    redirect_uri: str,
    username: str = "",
    error: str | None = None,
    status_code: int = 200,
) -> HTMLResponse:
    name = (client_name or "An unnamed application")[:_MAX_CLIENT_NAME]
    redirect_host = urlsplit(redirect_uri).hostname or redirect_uri
    error_html = f'<p class="error" role="alert">{escape(error)}</p>' if error else ""
    body = (
        "<h1>Sign in to Ratatoskr</h1>"
        f"<p><strong>{escape(name)}</strong> is asking for access to your connections.</p>"
        f'<p class="muted">After you sign in you will be sent to <strong>{escape(redirect_host)}</strong>.</p>'
        f"{error_html}"
        '<form method="post" action="/login">'
        f'<input type="hidden" name="request" value="{escape(request_id)}">'
        f'<input type="hidden" name="csrf_token" value="{escape(csrf_token)}">'
        f'<input name="username" autocomplete="username" placeholder="Username" value="{escape(username)}" required>'
        '<input type="password" name="password" autocomplete="current-password" placeholder="Password" required>'
        '<button type="submit">Sign in and authorize</button>'
        "</form>"
    )
    response = HTMLResponse(_document("Sign in — Ratatoskr", body), status_code=status_code)
    return apply_security_headers(response, form_action_origin=origin_of(redirect_uri))


def message_page(title: str, message: str, status_code: int) -> HTMLResponse:
    body = f"<h1>{escape(title)}</h1><p>{escape(message)}</p>"
    return apply_security_headers(HTMLResponse(_document(title, body), status_code=status_code))
```

- [ ] **Step 5: Run them**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_auth_csrf.py tests/unit/secure_http/test_auth_pages.py -q && .venv/Scripts/python -m mypy src`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/ratatoskr/auth/csrf.py src/ratatoskr/auth/pages.py tests/unit/secure_http/test_auth_csrf.py tests/unit/secure_http/test_auth_pages.py
git commit -m "Add CSRF protection and hardened login pages" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: Transport settings — client IP, preconditions, SDK settings

**Files:**
- Create: `src/ratatoskr/transport/__init__.py`, `src/ratatoskr/transport/client_ip.py`,
  `src/ratatoskr/transport/preconditions.py`, `src/ratatoskr/transport/security.py`
- Test: `tests/unit/secure_http/test_transport_settings.py`

Preconditions (raised as `ConfigError` before anything starts): transport is `streamable-http`; `auth` present with
users (local) or `oidc` section; `secret_key` ≥ 32 characters; `public_url` present, an origin, and https.
`--insecure-dev` is refused unless `server.host` is loopback; with it, `public_url` may be plain http but only on
127.0.0.1/localhost; whenever the flag is given, a warning is returned and logged at every start. Auth is never
optional. The tests build invalid variants with `model_copy` so they reach this code even if 1a's model validators
already reject some of them at load time.

- [ ] **Step 1: Write the failing test**

`tests/unit/secure_http/test_transport_settings.py`:

```python
from __future__ import annotations

import pytest
from pydantic import AnyHttpUrl, SecretStr

from ratatoskr.config.loader import ConfigError
from ratatoskr.transport.client_ip import client_ip, parse_trusted_proxies
from ratatoskr.transport.preconditions import check_http_preconditions
from ratatoskr.transport.security import mcp_auth_settings, transport_security


def scope(peer: str, xff: str | None = None) -> dict[str, object]:
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return {"type": "http", "client": (peer, 5000), "headers": headers}


# ── client IP ───────────────────────────────────────────────────────────────


def test_untrusted_peer_ignores_forwarded_for() -> None:
    assert client_ip(scope("203.0.113.9", "1.1.1.1"), ()) == "203.0.113.9"
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("203.0.113.9", "1.1.1.1"), trusted) == "203.0.113.9"


def test_trusted_proxy_uses_rightmost_untrusted_hop() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8", "172.16.0.5"])
    assert client_ip(scope("10.1.2.3", "6.6.6.6, 198.51.100.7, 172.16.0.5"), trusted) == "198.51.100.7"
    assert client_ip(scope("10.1.2.3", "10.0.0.9"), trusted) == "10.0.0.9"
    assert client_ip(scope("10.1.2.3"), trusted) == "10.1.2.3"


def test_malformed_forwarded_for_falls_back_to_peer() -> None:
    trusted = parse_trusted_proxies(["10.0.0.0/8"])
    assert client_ip(scope("10.1.2.3", "not-an-ip"), trusted) == "10.1.2.3"


def test_missing_client_is_unknown() -> None:
    assert client_ip({"type": "http", "headers": []}, ()) == "unknown"


# ── preconditions ───────────────────────────────────────────────────────────


def with_server(config, **updates):
    """Copy without validation, so 1a's model validators cannot pre-empt the check under test."""
    if "public_url" in updates and isinstance(updates["public_url"], str):
        updates["public_url"] = AnyHttpUrl(updates["public_url"])
    if "secret_key" in updates and isinstance(updates["secret_key"], str):
        updates["secret_key"] = SecretStr(updates["secret_key"])
    return config.model_copy(update={"server": config.server.model_copy(update=updates)})


def test_https_config_passes(make_config) -> None:
    settings = check_http_preconditions(make_config(), insecure_dev=False)
    assert settings.public_url == "https://mcp.example.com"
    assert settings.secret_key == "k" * 48
    assert settings.warnings == ()


def test_auth_is_mandatory(make_config) -> None:
    config = make_config().model_copy(update={"auth": None})
    with pytest.raises(ConfigError, match="auth"):
        check_http_preconditions(config, insecure_dev=False)


def test_secret_key_is_mandatory_and_long(make_config) -> None:
    with pytest.raises(ConfigError, match="secret_key"):
        check_http_preconditions(with_server(make_config(), secret_key=None), insecure_dev=False)
    with pytest.raises(ConfigError, match="32"):
        check_http_preconditions(with_server(make_config(), secret_key="short"), insecure_dev=False)


def test_public_url_is_mandatory_https_origin(make_config) -> None:
    with pytest.raises(ConfigError, match="public_url is required"):
        check_http_preconditions(with_server(make_config(), public_url=None), insecure_dev=False)
    with pytest.raises(ConfigError, match="https"):
        check_http_preconditions(with_server(make_config(), public_url="http://mcp.example.com"), insecure_dev=False)
    with pytest.raises(ConfigError, match="no path"):
        check_http_preconditions(
            with_server(make_config(), public_url="https://mcp.example.com/mcp"), insecure_dev=False
        )


def test_insecure_dev_allows_plain_http_only_on_loopback(make_config) -> None:
    config = with_server(make_config(), public_url="http://127.0.0.1:8000", host="127.0.0.1")
    settings = check_http_preconditions(config, insecure_dev=True)
    assert settings.public_url == "http://127.0.0.1:8000"
    assert settings.warnings and "INSECURE" in settings.warnings[0]
    with pytest.raises(ConfigError, match="server.host"):
        check_http_preconditions(with_server(config, host="0.0.0.0"), insecure_dev=True)
    with pytest.raises(ConfigError, match="public_url"):
        check_http_preconditions(with_server(config, public_url="http://mcp.example.com"), insecure_dev=True)


def test_insecure_dev_warns_even_with_https(make_config) -> None:
    settings = check_http_preconditions(with_server(make_config(), host="127.0.0.1"), insecure_dev=True)
    assert settings.warnings


def test_wrong_transport_is_refused(make_config) -> None:
    with pytest.raises(ConfigError, match="streamable-http"):
        check_http_preconditions(with_server(make_config(), transport="stdio"), insecure_dev=False)


# ── SDK settings ────────────────────────────────────────────────────────────


def test_auth_settings_bind_tokens_to_the_mcp_endpoint() -> None:
    settings = mcp_auth_settings("https://mcp.example.com")
    assert str(settings.issuer_url) == "https://mcp.example.com/"
    assert str(settings.resource_server_url) == "https://mcp.example.com/mcp"
    assert settings.validate_token_resource is True
    assert settings.client_registration_options is not None and settings.client_registration_options.enabled
    assert settings.revocation_options is not None and settings.revocation_options.enabled


def test_transport_security_allows_only_the_public_host() -> None:
    sec = transport_security("https://mcp.example.com")
    assert sec.enable_dns_rebinding_protection
    assert sec.allowed_hosts == ["mcp.example.com", "mcp.example.com:*"]
    assert sec.allowed_origins == ["https://mcp.example.com", "https://mcp.example.com:*"]
    assert transport_security("http://[::1]:8000").allowed_hosts == ["[::1]", "[::1]:*"]
```

- [ ] **Step 2: Run them**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_transport_settings.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.transport'`.

- [ ] **Step 3: Implement**

`src/ratatoskr/transport/__init__.py`:

```python
"""Streamable-HTTP serving: preconditions, transport security, app composition and uvicorn."""
```

`src/ratatoskr/transport/client_ip.py`:

```python
"""Client IP for rate limiting. ``X-Forwarded-For`` is honoured only when the peer is a configured trusted proxy."""

from collections.abc import Sequence
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network

from starlette.datastructures import Headers
from starlette.types import Scope

Network = IPv4Network | IPv6Network


def parse_trusted_proxies(entries: Sequence[str]) -> tuple[Network, ...]:
    return tuple(ip_network(entry, strict=False) for entry in entries)


def _trusted(address: str, trusted: Sequence[Network]) -> bool:
    try:
        parsed = ip_address(address)
    except ValueError:
        return False
    return any(parsed in network for network in trusted)


def client_ip(scope: Scope, trusted: Sequence[Network]) -> str:
    """Peer address, or the right-most untrusted ``X-Forwarded-For`` hop when the peer is a trusted proxy."""
    client = scope.get("client")
    peer = str(client[0]) if client else "unknown"
    if not trusted or not _trusted(peer, trusted):
        return peer
    header = Headers(scope=scope).get("x-forwarded-for")
    if not header:
        return peer
    hops = [hop.strip() for hop in header.split(",") if hop.strip()]
    for hop in reversed(hops):
        try:
            ip_address(hop)
        except ValueError:
            return peer
        if not _trusted(hop, trusted):
            return hop
    return hops[0] if hops else peer
```

`src/ratatoskr/transport/preconditions.py`:

```python
"""Refuse to serve streamable-http unless it is authenticated and behind https (spec §4, §5.4)."""

from dataclasses import dataclass

from ratatoskr.config.loader import ConfigError
from ratatoskr.config.models import AuthSettings, RatatoskrConfig

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
MIN_SECRET_KEY_LENGTH = 32


@dataclass(frozen=True)
class HttpSettings:
    """Validated values the HTTP server needs, with the optional fields narrowed."""

    public_url: str
    secret_key: str
    auth: AuthSettings
    warnings: tuple[str, ...]


def check_http_preconditions(config: RatatoskrConfig, *, insecure_dev: bool) -> HttpSettings:
    server = config.server
    if server.transport != "streamable-http":
        raise ConfigError("server.transport must be 'streamable-http' to serve HTTP")
    auth = config.auth
    if auth is None:
        raise ConfigError("transport 'streamable-http' requires an 'auth' section; HTTP never runs unauthenticated")
    if auth.mode == "local" and (auth.local is None or not auth.local.users):
        raise ConfigError("auth.mode 'local' requires at least one entry in auth.local.users")
    if auth.mode == "oidc" and auth.oidc is None:
        raise ConfigError("auth.mode 'oidc' requires the auth.oidc section")
    secret = server.secret_key.get_secret_value() if server.secret_key is not None else ""
    if len(secret) < MIN_SECRET_KEY_LENGTH:
        raise ConfigError(
            f"server.secret_key is required for HTTP and must be at least {MIN_SECRET_KEY_LENGTH} characters"
        )
    url = server.public_url
    if url is None:
        raise ConfigError("server.public_url is required for transport 'streamable-http'")
    if url.path not in (None, "", "/") or url.query or url.fragment:
        raise ConfigError("server.public_url must be an origin such as https://mcp.example.com (no path or query)")
    if insecure_dev and server.host not in LOOPBACK_HOSTS:
        raise ConfigError("--insecure-dev is only allowed when server.host is 127.0.0.1 or localhost")

    warnings: list[str] = []
    if url.scheme != "https":
        if not insecure_dev:
            raise ConfigError("server.public_url must use https (plain http is only possible with --insecure-dev)")
        if (url.host or "") not in LOOPBACK_HOSTS:
            raise ConfigError("--insecure-dev requires a public_url on 127.0.0.1 or localhost")
    if insecure_dev:
        warnings.append(
            "INSECURE DEV MODE (--insecure-dev): https is not enforced. Use only for local development on this machine."
        )
    return HttpSettings(public_url=str(url).rstrip("/"), secret_key=secret, auth=auth, warnings=tuple(warnings))
```

`src/ratatoskr/transport/security.py`:

```python
"""SDK settings derived from ``server.public_url``: OAuth metadata and DNS-rebinding protection."""

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
```

- [ ] **Step 4: Run them**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_transport_settings.py -q && .venv/Scripts/python -m mypy src`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/transport tests/unit/secure_http/test_transport_settings.py
git commit -m "Add HTTP preconditions, trusted-proxy client IP and SDK security settings" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 13: Login routes, health, DCR limit and the HTTP app (end-to-end local flow)

**Files:**
- Create: `src/ratatoskr/auth/web.py`, `src/ratatoskr/observability/health.py`,
  `src/ratatoskr/transport/register_limit.py`, `src/ratatoskr/transport/app.py`
- Create: `tests/unit/secure_http/e2e/__init__.py` (empty), `tests/unit/secure_http/e2e/conftest.py`
- Test: `tests/unit/secure_http/e2e/test_http_local_flow.py`, `tests/unit/secure_http/e2e/test_http_registry_lifecycle.py`

The e2e tests drive the real Starlette app returned by `build_http_app` through `httpx.ASGITransport` (which does
not run lifespans, so `run_app` enters `app.router.lifespan_context` itself). `OAuthDriver` plays claude.ai: DCR,
PKCE authorize, the browser form (parsing the CSRF field), `/token`, then raw MCP JSON-RPC (`initialize`,
`notifications/initialized`, `tools/call`) with SSE response parsing. The tool used is 1a's `list_connections`,
which reads configuration only (no database is contacted; the test DSNs point at `127.0.0.1:1`).

- [ ] **Step 1: Write the driver**

Create the empty package marker `tests/unit/secure_http/e2e/__init__.py`, then `tests/unit/secure_http/e2e/conftest.py`:

```python
"""End-to-end driver: plays claude.ai against the real Starlette app through an in-process ASGI transport."""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from starlette.applications import Starlette

from ratatoskr.auth.crypto import pkce_challenge
from ratatoskr.transport.app import HttpApp

PUBLIC_URL = "https://mcp.example.com"
CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PASSWORD = "correct horse battery staple"
PROTOCOL_VERSION = "2025-06-18"
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
_REQUEST_FIELD = re.compile(r'name="request" value="([^"]+)"')
_CSRF_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')


def code_from(location: str) -> str:
    query = parse_qs(urlsplit(location).query)
    assert query.get("state") == ["claude-state"], location
    return query["code"][0]


def sse_message(body: str) -> dict[str, Any]:
    for line in body.splitlines():
        if line.startswith("data: "):
            return dict(json.loads(line[len("data: ") :]))
    raise AssertionError(f"no SSE data line in {body!r}")


def tool_text(message: dict[str, Any]) -> str:
    return "\n".join(part["text"] for part in message["result"]["content"] if part["type"] == "text")


class OAuthDriver:
    PUBLIC_URL = PUBLIC_URL
    CLIENT_REDIRECT = CLIENT_REDIRECT
    PASSWORD = PASSWORD

    def __init__(self, client: httpx.AsyncClient, app: Starlette) -> None:
        self.http = client
        self.app = app
        self.client_id = ""
        self.client_secret = ""
        self.verifier = secrets.token_urlsafe(48)
        self._ids = 0

    async def register(self, redirect_uri: str = CLIENT_REDIRECT) -> httpx.Response:
        response = await self.http.post(
            "/register",
            json={
                "redirect_uris": [redirect_uri],
                "client_name": "Claude",
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
        if response.status_code == 201:
            body = response.json()
            self.client_id, self.client_secret = body["client_id"], body["client_secret"]
        return response

    def authorize_params(self, **overrides: str | None) -> dict[str, str]:
        values: dict[str, str | None] = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": CLIENT_REDIRECT,
            "code_challenge": pkce_challenge(self.verifier),
            "code_challenge_method": "S256",
            "state": "claude-state",
            "resource": PUBLIC_URL + "/mcp",
            **overrides,
        }
        return {k: v for k, v in values.items() if v is not None}

    async def authorize(self) -> str:
        response = await self.http.get("/authorize", params=self.authorize_params())
        assert response.status_code == 302, response.text
        return response.headers["location"]

    async def open_login(self, login_url: str) -> tuple[httpx.Response, str, str]:
        response = await self.http.get(login_url)
        assert response.status_code == 200, response.text
        request_id = _REQUEST_FIELD.search(response.text)
        csrf = _CSRF_FIELD.search(response.text)
        assert request_id is not None and csrf is not None
        return response, request_id.group(1), csrf.group(1)

    async def submit_login(self, request_id: str, csrf: str, username: str, password: str) -> httpx.Response:
        return await self.http.post(
            "/login",
            data={"request": request_id, "csrf_token": csrf, "username": username, "password": password},
        )

    async def login_for_code(self, username: str = "kerem", password: str = PASSWORD) -> str:
        _, request_id, csrf = await self.open_login(await self.authorize())
        response = await self.submit_login(request_id, csrf, username, password)
        assert response.status_code == 302, response.text
        return code_from(response.headers["location"])

    async def token(self, **form: str) -> httpx.Response:
        return await self.http.post(
            "/token", data={"client_id": self.client_id, "client_secret": self.client_secret, **form}
        )

    async def exchange(self, code: str) -> dict[str, Any]:
        response = await self.token(
            grant_type="authorization_code", code=code, redirect_uri=CLIENT_REDIRECT, code_verifier=self.verifier
        )
        assert response.status_code == 200, response.text
        return dict(response.json())

    async def refresh(self, refresh_token: str) -> httpx.Response:
        return await self.token(grant_type="refresh_token", refresh_token=refresh_token)

    async def revoke(self, token: str) -> httpx.Response:
        return await self.http.post(
            "/revoke", data={"token": token, "client_id": self.client_id, "client_secret": self.client_secret}
        )

    async def mcp_post(
        self,
        access_token: str | None,
        payload: dict[str, Any],
        session_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        all_headers = dict(MCP_HEADERS)
        if access_token is not None:
            all_headers["Authorization"] = f"Bearer {access_token}"
        if session_id is not None:
            all_headers["mcp-session-id"] = session_id
            all_headers["mcp-protocol-version"] = PROTOCOL_VERSION
        all_headers.update(headers or {})
        return await self.http.post("/mcp", json=payload, headers=all_headers)

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._ids += 1
        return {"jsonrpc": "2.0", "id": self._ids, "method": method, "params": params or {}}

    async def open_session(self, access_token: str) -> str:
        init = self.rpc(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}},
        )
        response = await self.mcp_post(access_token, init)
        assert response.status_code == 200, response.text
        session_id = response.headers["mcp-session-id"]
        ack = await self.mcp_post(access_token, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session_id)
        assert ack.status_code == 202, ack.text
        return session_id

    async def call_tool(self, access_token: str, session_id: str, name: str, **arguments: Any) -> httpx.Response:
        return await self.mcp_post(
            access_token, self.rpc("tools/call", {"name": name, "arguments": arguments}), session_id
        )

    async def end_session(self, access_token: str, session_id: str) -> httpx.Response:
        """DELETE /mcp: the client ends the MCP session (the SDK then exits that session's lifespan)."""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "mcp-session-id": session_id,
            "mcp-protocol-version": PROTOCOL_VERSION,
        }
        return await self.http.delete("/mcp", headers=headers)

    @staticmethod
    def code_from(location: str) -> str:
        return code_from(location)

    @asynccontextmanager
    async def spawn(self, peer: str) -> AsyncIterator[OAuthDriver]:
        """Another browser/client on a different IP against the same running app."""
        async with _client(self.app, peer) as client:
            yield OAuthDriver(client, self.app)

    async def tool_text(self, access_token: str, session_id: str, name: str, **arguments: Any) -> str:
        response = await self.call_tool(access_token, session_id, name, **arguments)
        assert response.status_code == 200, response.text
        return tool_text(sse_message(response.text))


RunApp = Callable[..., AbstractAsyncContextManager[OAuthDriver]]


def _client(app: Starlette, peer: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app, client=(peer, 50000)), base_url=PUBLIC_URL)


@pytest.fixture
def run_app() -> RunApp:
    """``async with run_app(http_app) as driver:`` runs the app lifespan and yields an :class:`OAuthDriver`."""

    @asynccontextmanager
    async def runner(http_app: HttpApp, peer: str = "203.0.113.10") -> AsyncIterator[OAuthDriver]:
        app = http_app.asgi
        async with app.router.lifespan_context(app), _client(app, peer) as client:
            yield OAuthDriver(client, app)

    return runner
```

- [ ] **Step 2: Write the failing tests**

`tests/unit/secure_http/e2e/test_http_local_flow.py`:

```python
"""DCR → authorize → login → code → token → MCP tool call → refresh → revoke, against the real app."""

from __future__ import annotations

import logging
import sqlite3

import pytest

from ratatoskr.transport.app import build_http_app

PUBLIC_URL = "https://mcp.example.com"
CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PASSWORD = "correct horse battery staple"


@pytest.fixture
def http_app(make_config):
    return build_http_app(make_config())


async def test_metadata_is_published(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        server = (await driver.http.get("/.well-known/oauth-authorization-server")).json()
        resource = (await driver.http.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert server["issuer"] == PUBLIC_URL + "/"
    assert server["registration_endpoint"] == PUBLIC_URL + "/register"
    assert server["revocation_endpoint"] == PUBLIC_URL + "/revoke"
    assert server["code_challenge_methods_supported"] == ["S256"]
    assert resource["resource"] == PUBLIC_URL + "/mcp"


async def test_full_local_flow(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        assert (await driver.register()).status_code == 201

        login_url = await driver.authorize()
        assert login_url.startswith(PUBLIC_URL + "/login?request=")
        page, request_id, csrf = await driver.open_login(login_url)
        assert "Claude" in page.text and "claude.ai" in page.text
        csp = page.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in csp and "form-action 'self' https://claude.ai" in csp
        assert page.headers["x-content-type-options"] == "nosniff"
        assert page.headers["referrer-policy"] == "no-referrer"
        assert "samesite=strict" in page.headers["set-cookie"].lower()

        redirect = await driver.submit_login(request_id, csrf, "kerem", PASSWORD)
        assert redirect.status_code == 302
        assert redirect.headers["location"].startswith(CLIENT_REDIRECT + "?")
        tokens = await driver.exchange(driver.code_from(redirect.headers["location"]))
        assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 3600

        session = await driver.open_session(tokens["access_token"])
        listing = await driver.tool_text(tokens["access_token"], session, "list_connections")
        assert "prod-pg" in listing and "staging-pg" in listing

        refreshed = await driver.refresh(tokens["refresh_token"])
        assert refreshed.status_code == 200, refreshed.text
        new = refreshed.json()
        assert new["refresh_token"] != tokens["refresh_token"]
        old_call = await driver.call_tool(tokens["access_token"], session, "list_connections")
        assert old_call.status_code == 401
        assert "prod-pg" in await driver.tool_text(new["access_token"], session, "list_connections")

        assert (await driver.revoke(new["refresh_token"])).status_code == 200
        assert (await driver.call_tool(new["access_token"], session, "list_connections")).status_code == 401
        assert (await driver.refresh(new["refresh_token"])).status_code == 400


async def test_policy_filters_connections_per_user(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        tokens = await driver.exchange(await driver.login_for_code("ayse"))
        session = await driver.open_session(tokens["access_token"])
        listing = await driver.tool_text(tokens["access_token"], session, "list_connections")
    assert "prod-pg" in listing and "staging-pg" not in listing


async def test_authorization_code_is_single_use(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        code = await driver.login_for_code()
        await driver.exchange(code)
        again = await driver.token(
            grant_type="authorization_code", code=code, redirect_uri=CLIENT_REDIRECT, code_verifier=driver.verifier
        )
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"


async def test_wrong_pkce_verifier_is_rejected(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        code = await driver.login_for_code()
        response = await driver.token(
            grant_type="authorization_code", code=code, redirect_uri=CLIENT_REDIRECT, code_verifier="w" * 64
        )
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"


async def test_refresh_token_reuse_revokes_the_session(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        tokens = await driver.exchange(await driver.login_for_code())
        new = (await driver.refresh(tokens["refresh_token"])).json()
        replay = await driver.refresh(tokens["refresh_token"])
        assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
        response = await driver.mcp_post(new["access_token"], driver.rpc("tools/list"))
    assert response.status_code == 401


async def test_health_endpoints(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        health = await driver.http.get("/healthz")
        ready = await driver.http.get("/readyz")
    assert health.status_code == 200 and health.json() == {"status": "ok"}
    assert ready.status_code == 200 and ready.json() == {"status": "ready"}


async def test_audit_events_are_persisted(make_config, run_app, tmp_path) -> None:
    async with run_app(build_http_app(make_config())) as driver:
        await driver.register()
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        await driver.submit_login(request_id, csrf, "kerem", "wrong-password")
    with sqlite3.connect(tmp_path / "state.db") as raw:
        rows = raw.execute("SELECT tool, subject, result FROM audit_events").fetchall()
    assert ("login_failed", "kerem", "denied") in rows


async def test_no_secrets_reach_the_logs(http_app, run_app, caplog) -> None:
    caplog.set_level(logging.DEBUG)
    async with run_app(http_app) as driver:
        await driver.register()
        code = await driver.login_for_code()
        tokens = await driver.exchange(code)
        session = await driver.open_session(tokens["access_token"])
        await driver.tool_text(tokens["access_token"], session, "list_connections")
        refreshed = (await driver.refresh(tokens["refresh_token"])).json()
        await driver.revoke(refreshed["access_token"])
        secrets = [
            PASSWORD,
            code,
            tokens["access_token"],
            tokens["refresh_token"],
            refreshed["access_token"],
            refreshed["refresh_token"],
            driver.client_secret,
            "k" * 48,
        ]
    leaked = [s for s in secrets if s in caplog.text]
    assert leaked == []
```

`tests/unit/secure_http/e2e/test_http_registry_lifecycle.py` — two MCP sessions, one ended with `DELETE /mcp`; the
injected registry (the real 1a `BackendRegistry` with call counters; no backend is opened) must be used by the tools,
survive the ended session and be closed exactly once, after the app's lifespan exits:

```python
"""Ownership rule: the HTTP app creates the backend registry, injects it into build_app and closes it exactly once,
at process shutdown. The SDK enters build_app's lifespan once per MCP session; ending a session must not close it."""

from __future__ import annotations

import asyncio

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.transport.app import build_http_app


class CountingRegistry(BackendRegistry):
    """The real 1a registry (no backend is ever opened here), counting the calls this test cares about."""

    def __init__(self, config: RatatoskrConfig) -> None:
        super().__init__(config)
        self.close_calls = 0
        self.describe_calls = 0

    def describe(self, name: str):  # type: ignore[no-untyped-def]
        self.describe_calls += 1
        return super().describe(name)

    async def close_all(self) -> None:
        self.close_calls += 1
        await super().close_all()


async def let_session_tasks_finish() -> None:
    for _ in range(20):
        await asyncio.sleep(0.01)


async def test_registry_outlives_sessions_and_is_closed_once_at_shutdown(make_config, run_app) -> None:
    config = make_config()
    registry = CountingRegistry(config)
    http_app = build_http_app(config, registry=registry)
    assert http_app.registry is registry

    async with run_app(http_app) as driver:
        await driver.register()
        access = (await driver.exchange(await driver.login_for_code()))["access_token"]
        first = await driver.open_session(access)
        second = await driver.open_session(access)
        assert first != second
        for session in (first, second):
            assert "prod-pg" in await driver.tool_text(access, session, "list_connections")
        assert registry.describe_calls > 0, "tools must use the injected registry"

        ended = await driver.end_session(access, first)
        assert ended.status_code == 200
        await let_session_tasks_finish()
        assert registry.close_calls == 0, "ending one MCP session must not close the shared registry"

        assert (await driver.call_tool(access, first, "list_connections")).status_code == 404
        assert "prod-pg" in await driver.tool_text(access, second, "list_connections")
        assert registry.close_calls == 0

    assert registry.close_calls == 1


async def test_default_registry_is_created_and_owned_by_the_app(make_config, run_app) -> None:
    http_app = build_http_app(make_config())
    assert isinstance(http_app.registry, BackendRegistry)
    async with run_app(http_app) as driver:
        assert (await driver.http.get("/healthz")).status_code == 200
```

- [ ] **Step 3: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/e2e -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.transport.app'` (raised while importing the e2e
conftest).

- [ ] **Step 4: Implement the browser routes**

`src/ratatoskr/auth/web.py`:

```python
"""Browser leg of the authorization flow: ``/login`` (local form or OIDC redirect) and ``/oauth/callback``."""

import logging
from collections.abc import Sequence

from mcp.server.fastmcp import FastMCP
from starlette.datastructures import FormData
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response

from ratatoskr.auth.crypto import Signer
from ratatoskr.auth.csrf import CsrfProtector
from ratatoskr.auth.events import record_auth_event
from ratatoskr.auth.identity.base import IdentityError, PasswordIdentityProvider, RedirectIdentityProvider
from ratatoskr.auth.oauth_server import PendingRequest, RatatoskrOAuthProvider
from ratatoskr.auth.pages import apply_security_headers, login_page, message_page
from ratatoskr.auth.ratelimit import RateLimiter
from ratatoskr.observability.audit import AuditSink
from ratatoskr.transport.client_ip import Network, client_ip

logger = logging.getLogger("ratatoskr.auth.web")

LOGIN_PATH = "/login"
CALLBACK_PATH = "/oauth/callback"
OIDC_FLOW_MAX_AGE = 600
_MAX_USERNAME = 256
_MAX_PASSWORD = 1024


def _field(form: FormData, name: str, limit: int = 4096) -> str:
    value = form.get(name)
    return value[:limit] if isinstance(value, str) else ""


def _expired() -> Response:
    return message_page(
        "This sign-in link is invalid or has expired",
        "Go back to your MCP client and connect again.",
        400,
    )


class LoginRoutes:
    def __init__(
        self,
        *,
        provider: RatatoskrOAuthProvider,
        csrf: CsrfProtector,
        flow_signer: Signer,
        limiter: RateLimiter,
        audit: AuditSink,
        trusted_proxies: Sequence[Network],
        secure_cookies: bool,
        local: PasswordIdentityProvider | None = None,
        oidc: RedirectIdentityProvider | None = None,
    ) -> None:
        self._provider = provider
        self._csrf = csrf
        self._flow_signer = flow_signer
        self._limiter = limiter
        self._audit = audit
        self._trusted = tuple(trusted_proxies)
        self._secure = secure_cookies
        self._local = local
        self._oidc = oidc
        self.flow_cookie = "__Host-ratatoskr-oidc" if secure_cookies else "ratatoskr-oidc"

    def register(self, mcp: FastMCP) -> None:
        mcp.custom_route(LOGIN_PATH, methods=["GET", "POST"])(self.login)
        if self._oidc is not None:
            mcp.custom_route(CALLBACK_PATH, methods=["GET"])(self.callback)

    async def login(self, request: Request) -> Response:
        if request.method == "POST":
            return await self._login_post(request)
        return await self._login_get(request)

    # ── GET /login ──────────────────────────────────────────────────────

    async def _login_get(self, request: Request) -> Response:
        pending = await self._provider.load_pending(request.query_params.get("request", ""))
        if pending is None:
            return _expired()
        if self._oidc is not None:
            return await self._start_oidc(self._oidc, pending)
        return self._form(pending)

    def _form(
        self, pending: PendingRequest, *, username: str = "", error: str | None = None, status: int = 200
    ) -> Response:
        cookie_value, form_token = self._csrf.issue(pending.pending.id)
        response = login_page(
            request_id=pending.pending.id,
            csrf_token=form_token,
            client_name=pending.client.client_name,
            redirect_uri=str(pending.params.redirect_uri),
            username=username,
            error=error,
            status_code=status,
        )
        self._csrf.set_cookie(response, cookie_value)
        return response

    async def _start_oidc(self, oidc: RedirectIdentityProvider, pending: PendingRequest) -> Response:
        nonce, verifier = pending.pending.nonce, pending.pending.upstream_verifier
        if nonce is None or verifier is None:
            return _expired()
        try:
            url = await oidc.authorization_url(state=pending.pending.id, nonce=nonce, code_verifier=verifier)
        except IdentityError as exc:
            logger.warning("cannot start OIDC sign-in: %s", exc)
            return message_page("Sign-in is unavailable", "The identity provider could not be reached.", 502)
        response = apply_security_headers(RedirectResponse(url, status_code=302))
        response.set_cookie(
            self.flow_cookie,
            self._flow_signer.sign(pending.pending.id),
            max_age=OIDC_FLOW_MAX_AGE,
            path="/",
            secure=self._secure,
            httponly=True,
            samesite="lax",
        )
        return response

    # ── POST /login ─────────────────────────────────────────────────────

    async def _login_post(self, request: Request) -> Response:
        if self._local is None:
            return message_page("Not found", "Password sign-in is not enabled.", 404)
        form = await request.form()
        request_id = _field(form, "request")
        username = _field(form, "username", _MAX_USERNAME).strip()
        password = _field(form, "password", _MAX_PASSWORD)
        if not self._csrf.verify(request_id, request.cookies.get(self._csrf.cookie_name), _field(form, "csrf_token")):
            return message_page("Your sign-in form expired", "Reload the page and try again.", 403)
        pending = await self._provider.load_pending(request_id)
        if pending is None:
            return _expired()

        ip_key = f"login:ip:{client_ip(request.scope, self._trusted)}"
        user_key = f"login:user:{username.casefold()}"
        wait = max(await self._limiter.retry_after(ip_key), await self._limiter.retry_after(user_key))
        if wait > 0:
            record_auth_event(self._audit, "login_rate_limited", subject=username, auth_source="local", result="denied")
            response = self._form(
                pending,
                username=username,
                error=f"Too many attempts. Try again in {int(wait) + 1} seconds.",
                status=429,
            )
            response.headers["Retry-After"] = str(int(wait) + 1)
            return response

        principal = await self._local.verify_password(username, password)
        if principal is None:
            await self._limiter.hit(ip_key)
            await self._limiter.hit(user_key)
            record_auth_event(self._audit, "login_failed", subject=username, auth_source="local", result="denied")
            return self._form(pending, username=username, error="Invalid username or password.", status=401)

        await self._limiter.reset(user_key)
        taken = await self._provider.take_pending(request_id)
        if taken is None:
            return _expired()
        redirect_url = await self._provider.complete_authorization(taken, principal, None)
        record_auth_event(self._audit, "login_succeeded", subject=principal.subject, auth_source="local", result="ok")
        response = apply_security_headers(RedirectResponse(redirect_url, status_code=302))
        self._csrf.clear_cookie(response)
        return response

    # ── GET /oauth/callback ─────────────────────────────────────────────

    async def callback(self, request: Request) -> Response:
        if self._oidc is None:
            return message_page("Not found", "OIDC sign-in is not enabled.", 404)
        state = request.query_params.get("state", "")
        flow = request.cookies.get(self.flow_cookie, "")
        if not state or not flow or not self._flow_signer.verify(state, flow):
            return message_page(
                "Sign-in could not be verified",
                "Start the connection again from the same browser.",
                400,
            )
        pending = await self._provider.take_pending(state)
        if pending is None:
            return _expired()
        if request.query_params.get("error"):
            logger.info("identity provider returned error %r", request.query_params.get("error"))
            return self._finish(self._provider.denied_redirect(pending))
        code = request.query_params.get("code", "")
        nonce, verifier = pending.pending.nonce, pending.pending.upstream_verifier
        if not code or nonce is None or verifier is None:
            return _expired()
        try:
            login = await self._oidc.complete(code, verifier, nonce)
        except IdentityError as exc:
            logger.warning("OIDC sign-in failed: %s", exc)
            record_auth_event(self._audit, "login_failed", subject="unknown", auth_source="oidc", result="denied")
            return message_page("Sign-in failed", "The identity provider's answer could not be verified.", 400)
        redirect_url = await self._provider.complete_authorization(pending, login.principal, login.refresh_token)
        record_auth_event(
            self._audit, "login_succeeded", subject=login.principal.subject, auth_source="oidc", result="ok"
        )
        return self._finish(redirect_url)

    def _finish(self, redirect_url: str) -> Response:
        response = apply_security_headers(RedirectResponse(redirect_url, status_code=302))
        response.delete_cookie(self.flow_cookie, path="/", secure=self._secure, httponly=True, samesite="lax")
        return response
```

- [ ] **Step 5: Implement health**

`src/ratatoskr/observability/health.py`:

```python
"""``/healthz`` (process is up) and ``/readyz`` (state store accepts writes; backends are not checked)."""

import logging

from mcp.server.fastmcp import FastMCP
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from ratatoskr.state.store import Store

logger = logging.getLogger("ratatoskr.health")


class HealthRoutes:
    def __init__(self, store: Store) -> None:
        self._store = store

    async def healthz(self, request: Request) -> Response:
        return JSONResponse({"status": "ok"}, headers={"Cache-Control": "no-store"})

    async def readyz(self, request: Request) -> Response:
        try:
            await self._store.check_writable()
        except Exception:
            logger.warning("readiness check failed: state store is not writable", exc_info=True)
            return JSONResponse({"status": "unavailable"}, status_code=503, headers={"Cache-Control": "no-store"})
        return JSONResponse({"status": "ready"}, headers={"Cache-Control": "no-store"})

    def register(self, mcp: FastMCP) -> None:
        mcp.custom_route("/healthz", methods=["GET"])(self.healthz)
        mcp.custom_route("/readyz", methods=["GET"])(self.readyz)
```

- [ ] **Step 6: Implement the DCR rate limit middleware**

`src/ratatoskr/transport/register_limit.py`:

```python
"""Per-IP rate limit on dynamic client registration (``POST /register``, spec §5.2 step 1)."""

from collections.abc import Sequence

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ratatoskr.auth.ratelimit import RateLimiter
from ratatoskr.transport.client_ip import Network, client_ip

REGISTER_PATH = "/register"


class RegistrationRateLimitMiddleware:
    def __init__(self, app: ASGIApp, *, limiter: RateLimiter, trusted_proxies: Sequence[Network]) -> None:
        self._app = app
        self._limiter = limiter
        self._trusted = tuple(trusted_proxies)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["path"] == REGISTER_PATH and scope["method"] == "POST":
            key = f"register:ip:{client_ip(scope, self._trusted)}"
            wait = await self._limiter.retry_after(key)
            if wait > 0:
                retry = str(int(wait) + 1)
                response = JSONResponse(
                    {"error": "too_many_requests", "error_description": f"retry after {retry} seconds"},
                    status_code=429,
                    headers={"Retry-After": retry},
                )
                await response(scope, receive, send)
                return
            await self._limiter.hit(key)
        await self._app(scope, receive, send)
```

- [ ] **Step 7: Implement the composition root**

`src/ratatoskr/transport/app.py` (the only place that constructs `LogAuditSink`/`CompositeAuditSink`; see Task 0).
Shutdown order: the session manager exits first (no session can use a backend any more), then the registry is
closed, then the cleanup task, the audit writer (flushes what the shutdown itself recorded), the upstream HTTP client
and finally the store:

```python
"""Composition root for ``transport: streamable-http``: store, OAuth server, login pages, MCP app, lifespan.

Ownership rule (shared with Plan 1a's ``build_app``): whoever creates the backend registry closes it. The SDK enters
the FastMCP lifespan once per MCP session, so this module creates the registry, injects it into ``build_app`` (whose
lifespan then never closes it) and closes it once, in the process-level Starlette lifespan.
"""

import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from starlette.applications import Starlette

from ratatoskr.app import build_app
from ratatoskr.auth.crypto import Keyring
from ratatoskr.auth.csrf import CsrfProtector
from ratatoskr.auth.identity.local import LocalIdentityProvider
from ratatoskr.auth.identity.oidc import OidcIdentityProvider
from ratatoskr.auth.oauth_server import RatatoskrOAuthProvider
from ratatoskr.auth.ratelimit import LOGIN_RULE, REGISTER_RULE, RateLimiter
from ratatoskr.auth.resolver import TokenPrincipalResolver
from ratatoskr.auth.web import CALLBACK_PATH, LoginRoutes
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import CompositeAuditSink, LogAuditSink
from ratatoskr.observability.health import HealthRoutes
from ratatoskr.state.audit import SqliteAuditSink
from ratatoskr.state.maintenance import CleanupTask
from ratatoskr.state.records import Clock
from ratatoskr.state.sqlite import SqliteStore
from ratatoskr.transport.client_ip import parse_trusted_proxies
from ratatoskr.transport.preconditions import check_http_preconditions
from ratatoskr.transport.register_limit import RegistrationRateLimitMiddleware
from ratatoskr.transport.security import mcp_auth_settings, transport_security

logger = logging.getLogger("ratatoskr.transport")

UPSTREAM_HTTP_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class HttpApp:
    asgi: Starlette
    store: SqliteStore
    provider: RatatoskrOAuthProvider
    registry: BackendRegistry


def build_http_app(
    config: RatatoskrConfig,
    *,
    insecure_dev: bool = False,
    clock: Clock = time.time,
    registry: BackendRegistry | None = None,
) -> HttpApp:
    """``registry`` is for tests; production passes none and one is created here. Either way this app closes it."""
    settings = check_http_preconditions(config, insecure_dev=insecure_dev)
    for warning in settings.warnings:
        logger.warning(warning)
    server = config.server
    secure_cookies = settings.public_url.startswith("https://")
    trusted_proxies = parse_trusted_proxies(server.trusted_proxies)

    backends = registry if registry is not None else BackendRegistry(config)
    keyring = Keyring(settings.secret_key)
    store = SqliteStore(server.state_path)
    sqlite_sink = SqliteAuditSink(store)
    audit = CompositeAuditSink([LogAuditSink(), sqlite_sink])
    http_client: httpx.AsyncClient | None = None
    local = None
    oidc = None
    if settings.auth.mode == "local" and settings.auth.local is not None:
        local = LocalIdentityProvider(settings.auth.local.users)
    if settings.auth.mode == "oidc" and settings.auth.oidc is not None:
        http_client = httpx.AsyncClient(timeout=UPSTREAM_HTTP_TIMEOUT_SECONDS, follow_redirects=False)
        oidc = OidcIdentityProvider(settings.auth.oidc, settings.public_url + CALLBACK_PATH, http_client, clock)

    provider = RatatoskrOAuthProvider(
        config, store=store, keyring=keyring, audit=audit, clock=clock, local=local, oidc=oidc
    )
    mcp = build_app(
        config,
        resolver=TokenPrincipalResolver(),
        audit=audit,
        auth_server_provider=provider,
        auth_settings=mcp_auth_settings(settings.public_url),
        registry=backends,
    )
    mcp.settings.transport_security = transport_security(settings.public_url)

    LoginRoutes(
        provider=provider,
        csrf=CsrfProtector(keyring.csrf, secure=secure_cookies),
        flow_signer=keyring.oidc_flow,
        limiter=RateLimiter(store, LOGIN_RULE, clock),
        audit=audit,
        trusted_proxies=trusted_proxies,
        secure_cookies=secure_cookies,
        local=local,
        oidc=oidc,
    ).register(mcp)
    HealthRoutes(store).register(mcp)

    app = mcp.streamable_http_app()
    app.add_middleware(
        RegistrationRateLimitMiddleware,
        limiter=RateLimiter(store, REGISTER_RULE, clock),
        trusted_proxies=trusted_proxies,
    )
    cleanup = CleanupTask(store, audit_retention=server.audit_retention, clock=clock)
    session_manager_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(starlette_app: Starlette) -> AsyncIterator[None]:
        await store.open()
        sqlite_sink.start()
        cleanup.start()
        try:
            async with session_manager_lifespan(starlette_app):
                yield
        finally:
            # Sessions are gone once the session manager has exited; only then close the shared backends.
            await backends.close_all()
            await cleanup.stop()
            await sqlite_sink.aclose()
            if http_client is not None:
                await http_client.aclose()
            await store.close()

    app.router.lifespan_context = lifespan
    return HttpApp(asgi=app, store=store, provider=provider, registry=backends)
```

- [ ] **Step 8: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/e2e -q && .venv/Scripts/python -m mypy src && .venv/Scripts/python -m ruff check src tests`
Expected: PASS. The `list_connections` assertions only need the connection names (`prod-pg`, `staging-pg`) to
appear in 1a's table for permitted connections and to be absent otherwise (`Policy.visible_connections` +
`BackendRegistry.describe`, no I/O).

- [ ] **Step 9: Run the whole unit suite**

Run: `.venv/Scripts/python -m pytest tests/unit -q`
Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add src/ratatoskr/auth/web.py src/ratatoskr/observability/health.py src/ratatoskr/transport/register_limit.py src/ratatoskr/transport/app.py tests/unit/secure_http/e2e
git commit -m "Compose the streamable-HTTP app: login routes, health, DCR limit, end-to-end OAuth flow" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 14: Security regression tests over HTTP

**Files:**
- Test: `tests/unit/secure_http/e2e/test_http_security.py`

These pin behaviour built in Tasks 5–13 (and the SDK facts above), so they are expected to pass on first run. If
one fails, fix the implementation, not the assertion.

- [ ] **Step 1: Write the tests**

```python
"""Security properties of the HTTP surface (spec §10 "Güvenlik")."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from ratatoskr.transport.app import build_http_app

CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PASSWORD = "correct horse battery staple"


@pytest.fixture
def http_app(make_config):
    return build_http_app(make_config())


async def test_disallowed_redirect_uri_is_rejected_at_registration(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        response = await driver.register("https://evil.example/callback")
        insecure = await driver.register("http://claude.ai/api/mcp/auth_callback")
    assert response.status_code == 400 and response.json()["error"] == "invalid_redirect_uri"
    assert insecure.status_code == 400


@pytest.mark.parametrize("overrides", [{"code_challenge": None}, {"code_challenge_method": "plain"}])
async def test_authorize_without_s256_pkce_is_rejected(http_app, run_app, overrides) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        response = await driver.http.get("/authorize", params=driver.authorize_params(**overrides))
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(CLIENT_REDIRECT)
    assert parse_qs(urlsplit(location).query)["error"] == ["invalid_request"]
    assert "code" not in parse_qs(urlsplit(location).query)


async def test_authorize_for_another_resource_is_rejected(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        params = driver.authorize_params(resource="https://other.example.com/mcp")
        response = await driver.http.get("/authorize", params=params)
    assert parse_qs(urlsplit(response.headers["location"]).query)["error"] == ["invalid_request"]


async def test_login_post_without_csrf_is_rejected(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        no_token = await driver.submit_login(request_id, "", "kerem", PASSWORD)
        driver.http.cookies.clear()
        no_cookie = await driver.submit_login(request_id, csrf, "kerem", PASSWORD)
    assert no_token.status_code == 403
    assert no_cookie.status_code == 403
    assert "location" not in no_token.headers and "location" not in no_cookie.headers


async def test_csrf_token_is_bound_to_its_request(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        _, first_request, first_csrf = await driver.open_login(await driver.authorize())
        _, second_request, _ = await driver.open_login(await driver.authorize())
        response = await driver.submit_login(second_request, first_csrf, "kerem", PASSWORD)
    assert first_request != second_request
    assert response.status_code == 403


async def test_request_without_token_gets_401(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        response = await driver.mcp_post(None, driver.rpc("tools/list"))
        bogus = await driver.mcp_post("not-a-real-token", driver.rpc("tools/list"))
    assert response.status_code == 401
    assert (
        'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
        in (response.headers["www-authenticate"])
    )
    assert bogus.status_code == 401


async def test_wrong_host_is_rejected_by_dns_rebinding_protection(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        tokens = await driver.exchange(await driver.login_for_code())
        response = await driver.mcp_post(
            tokens["access_token"], driver.rpc("tools/list"), headers={"Host": "attacker.example"}
        )
        bad_origin = await driver.mcp_post(
            tokens["access_token"], driver.rpc("tools/list"), headers={"Origin": "https://attacker.example"}
        )
    assert response.status_code == 421
    assert bad_origin.status_code == 403


async def test_wrong_password_is_rate_limited(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        statuses = []
        for _ in range(6):
            _, request_id, csrf = await driver.open_login(await driver.authorize())
            statuses.append((await driver.submit_login(request_id, csrf, "kerem", "wrong")).status_code)
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        correct = await driver.submit_login(request_id, csrf, "kerem", PASSWORD)
    assert statuses == [401, 401, 401, 401, 401, 429]
    assert correct.status_code == 429 and int(correct.headers["retry-after"]) > 0


async def test_lockout_is_per_ip_and_per_username(http_app, run_app) -> None:
    async with run_app(http_app, peer="198.51.100.1") as attacker:
        await attacker.register()
        for _ in range(5):
            _, request_id, csrf = await attacker.open_login(await attacker.authorize())
            await attacker.submit_login(request_id, csrf, "nobody", "wrong")
        _, request_id, csrf = await attacker.open_login(await attacker.authorize())
        blocked_ip = await attacker.submit_login(request_id, csrf, "ayse", PASSWORD)
        async with attacker.spawn("198.51.100.2") as other:
            await other.register()
            _, request_id, csrf = await other.open_login(await other.authorize())
            other_ip = await other.submit_login(request_id, csrf, "ayse", PASSWORD)
            _, request_id, csrf = await other.open_login(await other.authorize())
            blocked_user = await other.submit_login(request_id, csrf, "nobody", "anything")
    assert blocked_ip.status_code == 429
    assert other_ip.status_code == 302
    assert blocked_user.status_code == 429


async def test_dynamic_registration_is_rate_limited(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        statuses = [(await driver.register()).status_code for _ in range(21)]
    assert statuses == [201] * 20 + [429]


async def test_invalid_login_link_shows_error_page(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        response = await driver.http.get("/login?request=does-not-exist")
    assert response.status_code == 400
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
```

- [ ] **Step 2: Run them**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/e2e/test_http_security.py -q`
Expected: PASS (12 tests). Sanity check that they bite: temporarily change `LOGIN_RULE` to `limit=50` in
`auth/ratelimit.py`, rerun, see `test_wrong_password_is_rate_limited` and `test_lockout_is_per_ip_and_per_username`
FAIL, then revert the change.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/secure_http/e2e/test_http_security.py
git commit -m "Add HTTP security tests: redirect allowlist, PKCE, CSRF, 401, DNS rebinding, rate limits" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 15: OIDC end-to-end tests with the fake issuer

**Files:**
- Test: `tests/unit/secure_http/e2e/test_http_oidc_flow.py`

The OIDC flow-binding cookie is `SameSite=Lax` (not Strict): the callback is a top-level navigation coming from the
issuer's site, on which browsers do not send Strict cookies when the issuer is on another site. The CSRF cookie of
the password form stays Strict. Expected to pass on first run (implementation from Tasks 9, 10 and 13).

- [ ] **Step 1: Write the tests**

```python
"""OIDC mode end to end: our /login redirects to the fake issuer, /oauth/callback finishes, refresh re-validates."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from ratatoskr.transport.app import build_http_app

CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def http_app(make_config, fake_issuer, clock):
    return build_http_app(make_config(mode="oidc"), clock=clock)


async def start_oidc_login(driver, fake_issuer) -> tuple[str, str]:
    """Returns (state, nonce) that our server sent to the issuer."""
    login = await driver.http.get(await driver.authorize())
    assert login.status_code == 302
    location = login.headers["location"]
    assert location.startswith(fake_issuer.authorization_endpoint + "?")
    query = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
    assert query["redirect_uri"] == "https://mcp.example.com/oauth/callback"
    assert query["code_challenge_method"] == "S256"
    assert "samesite=lax" in login.headers["set-cookie"].lower()
    return query["state"], query["nonce"]


async def sign_in(driver, fake_issuer, groups: list[str]) -> dict:
    await driver.register()
    state, nonce = await start_oidc_login(driver, fake_issuer)
    fake_issuer.queue_token_response(
        id_token=fake_issuer.id_token(nonce=nonce, groups=groups), access_token="up-a", refresh_token="up-r1"
    )
    callback = await driver.http.get("/oauth/callback", params={"code": "upstream-code", "state": state})
    assert callback.status_code == 302, callback.text
    assert fake_issuer.form()["code_verifier"]
    return await driver.exchange(driver.code_from(callback.headers["location"]))


async def test_oidc_login_refresh_and_offboarding(http_app, run_app, fake_issuer) -> None:
    async with run_app(http_app) as driver:
        tokens = await sign_in(driver, fake_issuer, ["admins"])
        session = await driver.open_session(tokens["access_token"])
        assert "staging-pg" in await driver.tool_text(tokens["access_token"], session, "list_connections")

        fake_issuer.queue_token_response(id_token=fake_issuer.id_token(groups=["analyst"]), refresh_token="up-r2")
        refreshed = await driver.refresh(tokens["refresh_token"])
        assert refreshed.status_code == 200, refreshed.text
        assert fake_issuer.form() == {"grant_type": "refresh_token", "refresh_token": "up-r1"}
        new = refreshed.json()
        listing = await driver.tool_text(new["access_token"], session, "list_connections")
        assert "prod-pg" in listing and "staging-pg" not in listing

        fake_issuer.queue_token_response(400, error="invalid_grant")
        rejected = await driver.refresh(new["refresh_token"])
        assert fake_issuer.form()["refresh_token"] == "up-r2"
        assert rejected.status_code == 400 and rejected.json()["error"] == "invalid_grant"
        assert (await driver.call_tool(new["access_token"], session, "list_connections")).status_code == 401


async def test_callback_without_flow_cookie_is_rejected(http_app, run_app, fake_issuer) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        state, _ = await start_oidc_login(driver, fake_issuer)
        driver.http.cookies.clear()
        response = await driver.http.get("/oauth/callback", params={"code": "c", "state": state})
    assert response.status_code == 400
    assert fake_issuer.token_requests == []


async def test_callback_with_forged_state_is_rejected(http_app, run_app, fake_issuer) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        await start_oidc_login(driver, fake_issuer)
        response = await driver.http.get("/oauth/callback", params={"code": "c", "state": "attacker-state"})
    assert response.status_code == 400


async def test_issuer_error_is_relayed_as_access_denied(http_app, run_app, fake_issuer) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        state, _ = await start_oidc_login(driver, fake_issuer)
        response = await driver.http.get("/oauth/callback", params={"error": "access_denied", "state": state})
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert response.headers["location"].startswith(CLIENT_REDIRECT)
    assert query["error"] == ["access_denied"] and query["state"] == ["claude-state"]


async def test_bad_id_token_fails_the_sign_in(http_app, run_app, fake_issuer) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        state, _ = await start_oidc_login(driver, fake_issuer)
        fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="replayed-nonce"))
        response = await driver.http.get("/oauth/callback", params={"code": "c", "state": state})
    assert response.status_code == 400
    assert "location" not in response.headers


async def test_password_form_is_disabled_in_oidc_mode(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        response = await driver.http.post("/login", data={"request": "x", "username": "a", "password": "b"})
    assert response.status_code == 404
```

- [ ] **Step 2: Run them**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/e2e/test_http_oidc_flow.py -q`
Expected: PASS (6 tests).

- [ ] **Step 3: Commit**

```bash
git add tests/unit/secure_http/e2e/test_http_oidc_flow.py
git commit -m "Add OIDC end-to-end tests: login, group refresh, offboarding, callback attacks" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 16: `serve` over streamable-HTTP and `ratatoskr hash-password`

**Files:**
- Create: `src/ratatoskr/transport/serve.py`
- Modify: `src/ratatoskr/cli.py` (functions `build_parser`, `_serve`, `main`; new helper `_serve_http`)
- Modify: `tests/unit/test_cli.py` (delete `test_serve_refuses_http_transport_for_now`)
- Test: `tests/unit/secure_http/test_cli_http.py`

The code below is written against Plan 1a's `cli.py` (Task 18 of the 1a plan: `resolve_config_path`,
`build_parser`, `summarize`, `_check_config`, `_serve`, `main(argv) -> int`, `EXIT_CONFIG_ERROR = 2`,
`load_config(path, *, insecure_dev=...)`, `setup_logging`). If 1a's final file differs, apply the same three changes:
a `hash-password` sub-command dispatched before any config is loaded, and the `streamable-http` branch of `serve`
calling `serve_http` instead of raising.

- [ ] **Step 1: Write the failing test**

```python
from __future__ import annotations

import io
import sys
from pathlib import Path

from argon2 import PasswordHasher

import ratatoskr.cli

CONFIG = """
server:
  transport: streamable-http
  public_url: https://mcp.example.com
  host: 0.0.0.0
  state_path: {state}
  secret_key: ${{TEST_RATATOSKR_SECRET}}
auth:
  mode: local
  local:
    users:
      - username: kerem
        password_hash: ${{TEST_RATATOSKR_HASH}}
        groups: [admins]
roles:
  admins: {{"*": write}}
connections:
  prod-pg:
    kind: postgres
    dsn: ${{TEST_RATATOSKR_DSN}}
"""


def test_hash_password_prints_an_argon2id_hash(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("s3cret-pass\n"))
    assert ratatoskr.cli.main(["hash-password"]) == 0
    printed = capsys.readouterr().out.strip()
    assert printed.startswith("$argon2id$")
    assert PasswordHasher().verify(printed, "s3cret-pass")


def test_hash_password_rejects_empty_input(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert ratatoskr.cli.main(["hash-password"]) == 1
    assert "empty" in capsys.readouterr().err


def test_serve_dispatches_streamable_http(monkeypatch, tmp_path: Path, password_hash: str) -> None:
    config_file = tmp_path / "config.yaml"
    config_file.write_text(CONFIG.format(state=(tmp_path / "state.db").as_posix()), encoding="utf-8")
    monkeypatch.setenv("TEST_RATATOSKR_SECRET", "s" * 40)
    monkeypatch.setenv("TEST_RATATOSKR_HASH", password_hash)
    monkeypatch.setenv("TEST_RATATOSKR_DSN", "postgresql://u:p@127.0.0.1:1/db")
    calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(
        ratatoskr.cli,
        "serve_http",
        lambda config, *, insecure_dev: calls.append((config.server.transport, insecure_dev)),
    )
    assert ratatoskr.cli.main(["serve", "--config", str(config_file)]) == 0
    assert calls == [("streamable-http", False)]
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/secure_http/test_cli_http.py -q`
Expected: FAIL — `SystemExit: 2` from argparse (`invalid choice: 'hash-password'`) in the two hash-password tests;
the serve test fails because `ratatoskr.cli` has no attribute `serve_http` (monkeypatch raises `AttributeError`).

- [ ] **Step 3: Implement `serve_http`**

`src/ratatoskr/transport/serve.py`:

```python
"""Run the streamable-http app under uvicorn."""

import logging

import uvicorn

from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.transport.app import build_http_app


def serve_http(config: RatatoskrConfig, *, insecure_dev: bool) -> None:
    """Build the app and block until shutdown.

    ``proxy_headers=False``: uvicorn must not rewrite the client address; ``transport.client_ip`` applies
    ``server.trusted_proxies`` itself. ``access_log=False``: request lines carry ``/login?request=…`` and
    ``/oauth/callback?code=…`` values that must not reach logs. ``log_config=None`` keeps Ratatoskr's logging.
    aiosqlite logs every statement with its parameters at DEBUG, so it is capped at INFO.
    """
    http_app = build_http_app(config, insecure_dev=insecure_dev)
    logging.getLogger("aiosqlite").setLevel(logging.INFO)
    uvicorn.run(
        http_app.asgi,
        host=config.server.host,
        port=config.server.port,
        proxy_headers=False,
        server_header=False,
        access_log=False,
        log_config=None,
        lifespan="on",
    )
```

- [ ] **Step 4: Wire the CLI**

In `src/ratatoskr/cli.py` add these imports (ruff sorts them):

```python
from ratatoskr.auth.password_cli import run_hash_password
from ratatoskr.transport.serve import serve_http
```

Replace `build_parser`, `_serve` and `main`, and add `_serve_http`, exactly as follows (`resolve_config_path`,
`summarize` and `_check_config` stay as 1a wrote them):

```python
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ratatoskr", description="Ratatoskr MCP server")
    parser.add_argument("--version", action="version", version=f"ratatoskr {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="run the MCP server")
    serve.add_argument("--config", help=f"config file (default: ${CONFIG_ENV_VAR} or {DEFAULT_CONFIG_PATH})")
    serve.add_argument(
        "--insecure-dev", action="store_true", help="allow http public_url on a loopback host (local testing only)"
    )
    check = commands.add_parser("check-config", help="validate the config file and print a summary")
    check.add_argument("--config", help=f"config file (default: ${CONFIG_ENV_VAR} or {DEFAULT_CONFIG_PATH})")
    commands.add_parser(
        "hash-password", help="read a password (prompted twice, or one line from stdin) and print its argon2id hash"
    )
    return parser


def _serve_http(config: RatatoskrConfig, *, insecure_dev: bool) -> int:
    logger.info("starting ratatoskr %s over streamable-http at %s", __version__, config.server.public_url)
    try:
        serve_http(config, insecure_dev=insecure_dev)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    return 0


def _serve(args: argparse.Namespace) -> int:
    path = resolve_config_path(args.config)
    try:
        config = load_config(path, insecure_dev=args.insecure_dev)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    setup_logging(config.server.log_level)
    if config.server.transport == "streamable-http":
        return _serve_http(config, insecure_dev=args.insecure_dev)
    if config.server.stdio_role is None:
        logger.warning("server.stdio_role is not set: the stdio user cannot see any connection")
    app = build_app(config, resolver=StdioPrincipalResolver(config.server.stdio_role), audit=LogAuditSink())
    logger.info("starting ratatoskr %s over stdio with %d connection(s)", __version__, len(config.connections))
    app.run(transport="stdio")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "hash-password":
        return run_hash_password(sys.stdin, sys.stdout, sys.stderr)
    if args.command == "check-config":
        return _check_config(args)
    return _serve(args)
```

Also update the module docstring to ``Command line: ``ratatoskr serve``, ``check-config`` and ``hash-password``.``

- [ ] **Step 5: Retire 1a's "HTTP is refused" test**

Delete `test_serve_refuses_http_transport_for_now` from `tests/unit/test_cli.py`; it asserts the refusal that step 4
removes and is superseded by `test_serve_dispatches_streamable_http`. Keep `test_serve_validates_http_rules_first`
(config validation still runs first and still exits 2 on an http `public_url`).

- [ ] **Step 6: Run everything touched**

Run: `.venv/Scripts/python -m pytest tests/unit -q && .venv/Scripts/python -m ruff check --fix src tests && .venv/Scripts/python -m mypy src`
Expected: PASS.

- [ ] **Step 7: Manual smoke test (optional but recommended)**

```bash
export TEST_HASH="$(printf 'pw\n' | .venv/Scripts/ratatoskr hash-password)"
mkdir -p .tmp-smoke && cat > .tmp-smoke/config.yaml <<'YAML'
server:
  transport: streamable-http
  public_url: http://127.0.0.1:8765
  host: 127.0.0.1
  port: 8765
  state_path: .tmp-smoke/state.db
  secret_key: smoke-test-secret-key-0123456789abcdef
auth:
  mode: local
  local:
    users:
      - username: dev
        password_hash: ${TEST_HASH}
        groups: [admins]
roles:
  admins: {"*": write}
connections:
  local-pg:
    kind: postgres
    dsn: postgresql://u:p@127.0.0.1:1/db
YAML
.venv/Scripts/ratatoskr serve --config .tmp-smoke/config.yaml --insecure-dev &
SERVER_PID=$!
sleep 4; curl -s http://127.0.0.1:8765/healthz; curl -s http://127.0.0.1:8765/readyz; curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8765/mcp
kill "$SERVER_PID"; rm -rf .tmp-smoke
```

Expected: the log shows the `INSECURE DEV MODE` warning; `{"status":"ok"}`, `{"status":"ready"}`, `401`. Without
`--insecure-dev` the same command exits with the `ConfigError` "server.public_url must use https".

- [ ] **Step 8: Commit**

```bash
git add src/ratatoskr/transport/serve.py src/ratatoskr/cli.py tests/unit/test_cli.py tests/unit/secure_http/test_cli_http.py
git commit -m "Serve streamable-HTTP from the CLI and add ratatoskr hash-password" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 17: Container image

**Files:**
- Create: `Dockerfile` (the stale 0.1 Dockerfile was deleted at the end of Plan 1a)
- Create: `.dockerignore`

Multi-stage: the builder installs the package into `/opt/ratatoskr` (a venv) and byte-compiles it; the runtime
stage copies only that venv, runs as uid/gid 10001, writes only to `/data` (SQLite + WAL files) and reads
`/config/config.yaml`. `PYTHONDONTWRITEBYTECODE=1` plus pre-compiled bytecode make it work with a read-only root
file system. `HEALTHCHECK` calls `/healthz` on port 8000 (keep `server.port: 8000` in containers). Compose, Caddy,
CI and `/metrics` are stage 4.

- [ ] **Step 1: Replace `Dockerfile`**

```dockerfile
# syntax=docker/dockerfile:1

# ── build: install the package into a self-contained virtualenv ─────────────
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN python -m venv /opt/ratatoskr
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src/ src/
RUN /opt/ratatoskr/bin/pip install . \
 && /opt/ratatoskr/bin/python -m compileall -q /opt/ratatoskr

# ── runtime: non-root, read-only friendly; only /data is written ────────────
FROM python:3.12-slim

ENV PATH=/opt/ratatoskr/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RATATOSKR_CONFIG=/config/config.yaml

RUN groupadd --system --gid 10001 ratatoskr \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin ratatoskr \
 && mkdir -p /data /config \
 && chown 10001:10001 /data \
 && chmod 0750 /data

COPY --from=builder /opt/ratatoskr /opt/ratatoskr

USER 10001:10001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000

# /healthz is exempt from DNS-rebinding checks, so the loopback Host header is fine.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]

ENTRYPOINT ["ratatoskr"]
CMD ["serve"]
```

- [ ] **Step 2: Create `.dockerignore`**

```text
.git
.venv
.mypy_cache
.pytest_cache
.ruff_cache
**/__pycache__
*.pyc
*.db
*.db-wal
*.db-shm
.env
tests
docs
```

- [ ] **Step 3: Build and verify (needs Docker; pulls `python:3.12-slim`)**

```bash
docker build -t ratatoskr:dev .
docker run -i --rm --read-only ratatoskr:dev hash-password <<< 'pw'
docker run --rm --entrypoint id ratatoskr:dev
docker inspect --format '{{json .Config.Healthcheck}}' ratatoskr:dev
```

Expected: build succeeds; the second command prints an `$argon2id$…` hash although the root file system is
read-only; `id` prints `uid=10001(ratatoskr) gid=10001(ratatoskr)`; the health check calls `/healthz`. Then run the
image with `--read-only -v ratatoskr-data:/data -v "$PWD/config.yaml:/config/config.yaml:ro" -p 8000:8000` and a
`streamable-http` config with `host: 0.0.0.0`; `docker ps` shows `(healthy)` after ~30 s.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "Rewrite Dockerfile: multi-stage, non-root uid 10001, read-only root, healthcheck" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 18: Authentik setup guide and manual checklist

**Files:**
- Create: `docs/authentik.md`

- [ ] **Step 1: Write the guide**

````markdown
# Authentik as the identity provider

Ratatoskr is an OAuth 2.1 authorization server towards MCP clients (claude.ai, Claude Desktop, Claude Code) and an
OpenID Connect relying party towards Authentik. People sign in at Authentik; Ratatoskr reads their groups from the
ID token and maps them to connections through `roles:` in `config.yaml`.

Throughout this page `https://mcp.example.com` is Ratatoskr's `server.public_url` and `https://auth.example.com` is
Authentik. Replace both.

## 1. Groups scope mapping

Authentik's default `profile` scope already carries a `groups` claim, but a dedicated scope keeps the claim explicit
and lets you shape it.

1. *Customization → Property Mappings → Create → Scope Mapping*.
2. Name `ratatoskr groups`, **Scope name** `groups`, description `Group membership for Ratatoskr`.
3. Expression:

   ```python
   return {"groups": [group.name for group in request.user.ak_groups.all()]}
   ```

## 2. OAuth2/OpenID provider

*Applications → Providers → Create → OAuth2/OpenID Provider*:

| Field | Value |
|---|---|
| Name | `ratatoskr` |
| Authorization flow | `default-provider-authorization-implicit-consent` (or the explicit-consent flow) |
| Client type | **Confidential** |
| Client ID / Client Secret | generated — copy both into the environment as `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` |
| Redirect URIs/Origins | **Strict**, exactly `https://mcp.example.com/oauth/callback` |
| Signing Key | a certificate, e.g. `authentik Self-signed Certificate` (**required**: without it Authentik signs ID tokens with HS256, which Ratatoskr rejects) |
| Scopes (advanced) | `authentik default OAuth Mapping: OpenID 'openid'`, `… 'email'`, `… 'profile'`, `… 'offline_access'`, `ratatoskr groups` |
| Subject mode | any; Ratatoskr uses the claim named by `subject_claim` (default `email`) |
| Access code validity | `minutes=1` (default) |
| Refresh token validity | at least as long as `auth.refresh_token_ttl` (default 30 days) |

`offline_access` is mandatory: Ratatoskr re-validates every user at Authentik on each of its own refreshes
(at most `auth.access_token_ttl`, default 1 hour, apart). Without an Authentik refresh token that check is impossible,
so the user would have to sign in again every hour.

## 3. Application

*Applications → Applications → Create*: name `Ratatoskr`, slug `mcp`, provider `ratatoskr`. Bind a policy or group
under *Policy / Group / User Bindings* if only some people may use it at all. The issuer is then
`https://auth.example.com/application/o/mcp/` (with the trailing slash).

## 4. Ratatoskr configuration

```yaml
server:
  transport: streamable-http
  public_url: https://mcp.example.com
  host: 0.0.0.0
  port: 8000
  secret_key: ${SERVER_SECRET_KEY}          # at least 32 characters; e.g. `openssl rand -base64 48`
  trusted_proxies: [172.18.0.0/16]          # the reverse proxy's address, so rate limits see real client IPs
auth:
  mode: oidc
  access_token_ttl: 1h
  refresh_token_ttl: 30d
  oidc:
    issuer: https://auth.example.com/application/o/mcp/
    client_id: ${OIDC_CLIENT_ID}
    client_secret: ${OIDC_CLIENT_SECRET}
    scopes: [openid, email, profile, groups, offline_access]
    groups_claim: groups
    subject_claim: email
roles:
  admins: { "*": write }
  devops: { prod-pg: read }
```

Changing `server.secret_key` invalidates every stored Authentik refresh token and every registered client secret:
all users must reconnect.

## 5. Verification checklist

Run these after every Authentik or Ratatoskr upgrade.

- [ ] `curl -s https://auth.example.com/application/o/mcp/.well-known/openid-configuration` returns JSON whose
      `issuer` is exactly the configured issuer and whose `id_token_signing_alg_values_supported` contains `RS256`.
- [ ] `ratatoskr check-config` succeeds and prints no secret.
- [ ] `curl -s https://mcp.example.com/healthz` → `{"status":"ok"}`; `/readyz` → `{"status":"ready"}`.
- [ ] `curl -s https://mcp.example.com/.well-known/oauth-authorization-server` lists `/authorize`, `/token`,
      `/register`, `/revoke` under `https://mcp.example.com`.
- [ ] In claude.ai: *Settings → Connectors → Add custom connector*, URL `https://mcp.example.com/mcp`. The browser
      goes to Authentik, then back to claude.ai; the connector shows as connected.
- [ ] Ask Claude to run `list_connections`: exactly the connections your groups grant are listed.
- [ ] Remove yourself from a group in Authentik. Within one access-token lifetime (default 1 hour) the connection
      disappears from `list_connections` without reconnecting.
- [ ] Deactivate a test user in Authentik. Their next refresh fails (`upstream_refresh_failed` in the audit log) and
      claude.ai asks them to reconnect; reconnecting is refused by Authentik.
- [ ] Audit trail: `sqlite3 /data/state.db "SELECT datetime(ts, 'unixepoch'), tool, subject, result FROM
      audit_events ORDER BY id DESC LIMIT 20"` shows `login_succeeded` and tool calls with the expected subject.
- [ ] Logs (`docker logs ratatoskr`) contain no access token, refresh token, client secret or Authentik code.

## Troubleshooting

| Symptom (Ratatoskr log) | Cause |
|---|---|
| `ID token signature rejected` / `issuer JWKS could not be imported` | No signing key selected on the provider (HS256) |
| `OIDC discovery issuer … does not match` | `auth.oidc.issuer` differs from Authentik's issuer (check the trailing slash and slug) |
| `claim 'email' is missing from the identity` | `email` scope not selected, or the user has no e-mail; or set `subject_claim: sub` |
| User sees no connections | The `groups` scope is missing or group names differ from the keys under `roles:` |
| Users must sign in every hour | `offline_access` scope missing on the provider |
| `Sign-in could not be verified` after Authentik | The browser dropped the `ratatoskr-oidc` cookie: start from the same browser, and do not open the callback URL in another profile |
````

- [ ] **Step 2: Commit**

```bash
git add docs/authentik.md
git commit -m "Add Authentik setup guide and manual verification checklist" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 19: Final verification

**Files:** none.

- [ ] **Step 1: Full gate**

Run: `.venv/Scripts/python -m pytest tests/unit -q && .venv/Scripts/python -m ruff check src tests && .venv/Scripts/python -m mypy src`
Expected: PASS. The 1b tests add 183 tests and ~15 s (argon2 and RSA key generation dominate; the RSA keys are
session-scoped).

- [ ] **Step 2: Integration suite still green (Docker)**

Run: `.venv/Scripts/python -m pytest -m integration -q`
Expected: PASS (1a's PostgreSQL tests; 1b adds none).

- [ ] **Step 3: Spec cross-check**

Confirm each item against the code: §5.2 DCR allowlist (`auth/redirects.py`), PKCE S256 (SDK + `authorize`), pending
10 min / code 5 min single-use (`oauth_server.py`), opaque 32-byte tokens stored as SHA-256 (`crypto.py`,
`sqlite.py`), access 1 h / refresh 30 d from config, rotation + reuse → family revoked + `token_reuse_detected`,
`/revoke` kills the family; §5.3 upstream refresh token AES-GCM sealed, re-validated on every refresh, failure revokes;
§5.4 rate limits + audit, CSRF + `SameSite=Strict` + CSP `frame-ancestors 'none'` + nosniff, DNS rebinding with the
`public_url` host, HTTP refuses to start without auth/https; §7 tables, WAL, `synchronous=NORMAL`, single writer,
migrations, hourly cleanup, audit batches 1 s/100 and 90-day retention; §8 `/healthz`, `/readyz`; §9 Dockerfile.
