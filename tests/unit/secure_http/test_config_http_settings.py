from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from ratatoskr.config.loader import ConfigError, load_config
from ratatoskr.config.models import ServerSettings

_BASE = """
server:
{server}
connections:
  main:
    kind: postgres
    dsn: postgresql://u:p@127.0.0.1:1/db
"""


def _load(tmp_path: Path, server_yaml: str) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(_BASE.format(server=server_yaml), encoding="utf-8")
    load_config(path, env={})


def test_defaults() -> None:
    settings = ServerSettings()
    assert settings.trusted_proxies == []
    assert settings.audit_retention == timedelta(days=90)


def test_audit_retention_accepts_duration_strings() -> None:
    assert ServerSettings.model_validate({"audit_retention": "30d"}).audit_retention == timedelta(days=30)
    assert ServerSettings.model_validate({"audit_retention": 172800}).audit_retention == timedelta(days=2)
    assert ServerSettings.model_validate({"audit_retention": "1d"}).audit_retention == timedelta(days=1)


@pytest.mark.parametrize("value", ["23h", 3600, "0s"])
def test_audit_retention_below_one_day_is_a_config_error(tmp_path: Path, value: object) -> None:
    with pytest.raises(ConfigError, match=r"server\.audit_retention: .*at least 1 day") as info:
        _load(tmp_path, f"  audit_retention: {value}")
    assert str(value) not in str(info.value)


def test_trusted_proxies_accept_addresses_and_networks() -> None:
    settings = ServerSettings.model_validate({"trusted_proxies": ["10.0.0.0/8", "172.18.0.2", "fd00::/8"]})
    assert settings.trusted_proxies == ["10.0.0.0/8", "172.18.0.2/32", "fd00::/8"]


def test_trusted_proxies_are_normalized() -> None:
    settings = ServerSettings.model_validate({"trusted_proxies": ["10.1.2.3/8", "FD00::1/8"]})
    assert settings.trusted_proxies == ["10.0.0.0/8", "fd00::/8"]


def test_invalid_trusted_proxy_is_a_config_error() -> None:
    with pytest.raises(ValidationError, match="trusted_proxies"):
        ServerSettings.model_validate({"trusted_proxies": ["caddy"]})


def test_invalid_trusted_proxy_value_is_never_echoed(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"server\.trusted_proxies: entry 1 is not an IP address or CIDR") as info:
        _load(tmp_path, '  trusted_proxies: ["10.0.0.1", "s3cr3t-value"]')
    assert "s3cr3t" not in str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None


def test_allowed_redirect_hosts_accept_hostnames_ipv4_and_bracketed_ipv6() -> None:
    settings = ServerSettings.model_validate(
        {"allowed_redirect_hosts": ["claude.ai", "Claude.COM", "localhost", "127.0.0.1", "[::1]", "my-host.example"]}
    )
    assert settings.allowed_redirect_hosts == [
        "claude.ai",
        "claude.com",
        "localhost",
        "127.0.0.1",
        "[::1]",
        "my-host.example",
    ]


@pytest.mark.parametrize(
    "entry",
    [
        "https://claude.ai",
        "claude.ai/cb",
        "claude.ai:443",
        "*.claude.ai",
        "*",
        ".claude.ai",
        "claude.ai.",
        "::1",
        "[claude.ai]",
        "[::1]:8080",
        "999.1.1.1",
        "1.2.3",
        "user@claude.ai",
        "\u212aerem.dev",
        "cl\u0430ude.ai",
        "",
        " claude.ai",
        "-claude.ai",
    ],
)
def test_invalid_allowed_redirect_host_is_rejected(entry: str) -> None:
    with pytest.raises(ValidationError, match="allowed_redirect_hosts"):
        ServerSettings.model_validate({"allowed_redirect_hosts": [entry]})


def test_invalid_allowed_redirect_host_value_is_never_echoed(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match=r"server\.allowed_redirect_hosts: entry 1 is not a host name") as info:
        _load(tmp_path, '  allowed_redirect_hosts: ["claude.ai", "https://s3cr3t-value"]')
    assert "s3cr3t" not in str(info.value)
    assert info.value.__cause__ is None
    assert info.value.__context__ is None
