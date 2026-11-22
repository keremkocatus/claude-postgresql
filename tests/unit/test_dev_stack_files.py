"""compose.dev.yml and the dev configs under dev/ agree: loopback-only ports, matching hosts and ports."""

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
import yaml

from ratatoskr.config.loader import load_config
from ratatoskr.config.models import PostgresConnection

ROOT = Path(__file__).resolve().parents[2]


def _compose() -> dict[str, Any]:
    data = yaml.safe_load((ROOT / "compose.dev.yml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_published_ports_bind_loopback_only() -> None:
    for name, service in _compose()["services"].items():
        for port in service.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name} publishes {port} beyond this machine"


def _hosts(path: Path) -> set[str]:
    config = load_config(path, insecure_dev=True)
    hosts: set[str] = set()
    for connection in config.connections.values():
        if isinstance(connection, PostgresConnection):
            hosts.add(urlsplit(connection.dsn.get_secret_value()).netloc.rsplit("@", 1)[1])
            assert connection.write_dsn is not None
        else:
            hosts.add(f"{connection.url.host}:{connection.url.port}")
    return hosts


def test_container_config_uses_service_names() -> None:
    services = _compose()["services"]
    hosts = _hosts(ROOT / "dev" / "ratatoskr" / "stdio.yaml")
    assert {host.split(":")[0] for host in hosts} <= set(services)


def test_host_config_uses_the_published_ports() -> None:
    published = {
        "127.0.0.1:" + str(port).split(":")[1]
        for service in _compose()["services"].values()
        for port in service.get("ports", [])
    }
    assert _hosts(ROOT / "dev" / "ratatoskr" / "local-http.yaml") == published


def test_host_config_passes_the_insecure_dev_preconditions(monkeypatch: pytest.MonkeyPatch) -> None:
    import ratatoskr.transport.preconditions as preconditions

    monkeypatch.setattr(preconditions, "_check_state_path", lambda path: None)
    config = load_config(ROOT / "dev" / "ratatoskr" / "local-http.yaml", insecure_dev=True)
    settings = preconditions.check_http_preconditions(config, insecure_dev=True)
    assert settings.public_url == "http://127.0.0.1:8000"


def test_prometheus_scrapes_the_dev_metrics_port() -> None:
    config = load_config(ROOT / "dev" / "ratatoskr" / "stdio.yaml")
    prometheus = yaml.safe_load((ROOT / "dev" / "prometheus" / "prometheus.yml").read_text(encoding="utf-8"))
    targets = {t for job in prometheus["scrape_configs"] for group in job["static_configs"] for t in group["targets"]}
    assert f"ratatoskr:{config.server.metrics_port}" in targets
    assert config.server.metrics_host == "0.0.0.0"


def test_log_generator_has_unix_line_endings() -> None:
    assert b"\r\n" not in (ROOT / "dev" / "loggen" / "loggen.sh").read_bytes()
