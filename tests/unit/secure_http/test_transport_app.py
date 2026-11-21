from __future__ import annotations

import pytest
from pydantic import AnyHttpUrl

from ratatoskr.auth.identity.local import LocalIdentityProvider
from ratatoskr.config.loader import ConfigError
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
