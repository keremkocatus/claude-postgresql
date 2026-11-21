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
