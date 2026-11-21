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
