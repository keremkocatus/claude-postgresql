from __future__ import annotations

import httpx
import pytest
from pydantic import AnyHttpUrl

from ratatoskr.auth.identity.local import LocalIdentityProvider
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.loader import ConfigError
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.state.sqlite import SqliteStore
from ratatoskr.transport.app import build_http_app
from ratatoskr.transport.preconditions import check_http_preconditions


@pytest.fixture
def count_local_providers(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    built = [0]
    original = LocalIdentityProvider.__init__

    def counting(self: LocalIdentityProvider, *args: object, **kwargs: object) -> None:
        built[0] += 1
        original(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(LocalIdentityProvider, "__init__", counting)
    return built


def test_local_users_are_checked_once(make_config, count_local_providers) -> None:
    build_http_app(make_config())
    assert count_local_providers == [1]


def test_checked_settings_are_reused(make_config, count_local_providers) -> None:
    config = make_config()
    settings = check_http_preconditions(config, insecure_dev=False)
    assert count_local_providers == [1]
    build_http_app(config, settings=settings)
    assert count_local_providers == [1]


def _plain_http_issuer(make_config):
    config = make_config(mode="oidc", host="127.0.0.1")
    assert config.auth is not None and config.auth.oidc is not None
    oidc = config.auth.oidc.model_copy(update={"issuer": AnyHttpUrl("http://127.0.0.1:9000/application/o/mcp/")})
    return config.model_copy(update={"auth": config.auth.model_copy(update={"oidc": oidc})})


def test_plain_http_issuer_is_accepted_in_insecure_dev(make_config) -> None:
    build_http_app(_plain_http_issuer(make_config), insecure_dev=True)


def test_oidc_provider_refusal_becomes_a_config_error(make_config) -> None:
    config = _plain_http_issuer(make_config)
    settings = check_http_preconditions(config, insecure_dev=True)
    # The provider itself refuses plain http without --insecure-dev; the ValueError surfaces as a ConfigError.
    with pytest.raises(ConfigError, match="auth.oidc.issuer must use https"):
        build_http_app(config, insecure_dev=False, settings=settings)


class ClientTracker:
    """Every ``httpx.AsyncClient`` created and closed while a test runs, and every transport's proxy."""

    def __init__(self) -> None:
        self.created: list[httpx.AsyncClient] = []
        self.closed: list[httpx.AsyncClient] = []
        self.proxies: list[str] = []


@pytest.fixture
def clients(monkeypatch: pytest.MonkeyPatch) -> ClientTracker:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    tracker = ClientTracker()
    original_init = httpx.AsyncClient.__init__
    original_aclose = httpx.AsyncClient.aclose
    original_transport = httpx.AsyncHTTPTransport.__init__

    def init(self: httpx.AsyncClient, *args: object, **kwargs: object) -> None:
        tracker.created.append(self)
        original_init(self, *args, **kwargs)  # type: ignore[arg-type]

    async def aclose(self: httpx.AsyncClient) -> None:
        tracker.closed.append(self)
        await original_aclose(self)

    def transport(self: httpx.AsyncHTTPTransport, *args: object, proxy: object = None, **kwargs: object) -> None:
        if proxy is not None:
            tracker.proxies.append(str(proxy.url if isinstance(proxy, httpx.Proxy) else proxy))
        original_transport(self, *args, proxy=proxy, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(httpx.AsyncClient, "__init__", init)
    monkeypatch.setattr(httpx.AsyncClient, "aclose", aclose)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "__init__", transport)
    return tracker


def test_oidc_config_error_leaves_no_upstream_client(make_config, clients) -> None:
    config = _plain_http_issuer(make_config)
    settings = check_http_preconditions(config, insecure_dev=True)
    with pytest.raises(ConfigError):
        build_http_app(config, insecure_dev=False, settings=settings)
    assert clients.created == []


def test_an_app_that_never_starts_has_no_upstream_client(make_config, clients) -> None:
    build_http_app(make_config(mode="oidc"))
    assert clients.created == []


async def test_upstream_client_lives_exactly_as_long_as_the_app(make_config, clients) -> None:
    app = build_http_app(make_config(mode="oidc")).asgi
    async with app.router.lifespan_context(app):
        assert len(clients.created) == 1
        client = clients.created[0]
        assert client.timeout == httpx.Timeout(10.0) and client.follow_redirects is False
        assert clients.closed == []
    assert clients.closed == [client] and client.is_closed


async def test_upstream_client_honours_the_proxy_environment(make_config, clients, monkeypatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://egress.internal:3128")
    app = build_http_app(make_config(mode="oidc")).asgi
    async with app.router.lifespan_context(app):
        assert len(clients.created) == 1
    assert clients.proxies == ["http://egress.internal:3128"]


async def test_local_mode_has_no_upstream_client(make_config, clients) -> None:
    app = build_http_app(make_config()).asgi
    async with app.router.lifespan_context(app):
        pass
    assert clients.created == []


class _ClosingRegistry(BackendRegistry):
    def __init__(self, config: RatatoskrConfig) -> None:
        super().__init__(config)
        self.close_calls = 0

    async def close_all(self) -> None:
        self.close_calls += 1
        await super().close_all()


@pytest.mark.parametrize("mode", ["local", "oidc"])
async def test_startup_failure_releases_resources(make_config, monkeypatch, clients, mode) -> None:
    async def broken_open(self: SqliteStore) -> None:
        raise RuntimeError("state store cannot be opened")

    monkeypatch.setattr(SqliteStore, "open", broken_open)
    config = make_config(mode=mode)
    registry = _ClosingRegistry(config)
    app = build_http_app(config, registry=registry).asgi
    with pytest.raises(RuntimeError, match="cannot be opened"):
        async with app.router.lifespan_context(app):
            pytest.fail("the app must not start")
    assert registry.close_calls == 1
    # The upstream client is created first at startup, so the failure after it must close it.
    assert len(clients.created) == (1 if mode == "oidc" else 0)
    assert clients.closed == clients.created
