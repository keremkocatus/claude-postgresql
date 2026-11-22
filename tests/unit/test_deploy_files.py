"""compose.yml, deploy/Caddyfile and deploy/config.example.yaml agree with each other and with the image."""

import ipaddress
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from ratatoskr.config.loader import load_config

ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_RE = re.compile(r"\$\{(?P<name>[A-Z_]+):-(?P<default>[^}]+)\}")


def _compose() -> dict[str, Any]:
    data = yaml.safe_load((ROOT / "compose.yml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _default(value: str) -> str:
    match = _DEFAULT_RE.fullmatch(value)
    assert match is not None, value
    return match.group("default")


def test_ratatoskr_service_is_locked_down() -> None:
    service = _compose()["services"]["ratatoskr"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert "ports" not in service, "only Caddy is published; 8000 and the metrics port stay on the compose network"
    assert "ratatoskr-data:/data" in service["volumes"]
    assert "./config.yaml:/config/config.yaml:ro" in service["volumes"]
    assert service["stop_grace_period"] in ("15s", "20s", "30s")  # the audit flush needs >= 10 s


def test_caddy_address_is_the_trusted_proxy() -> None:
    compose = _compose()
    caddy_ip = _default(compose["services"]["caddy"]["networks"]["edge"]["ipv4_address"])
    ipam = compose["networks"]["edge"]["ipam"]["config"][0]
    subnet = ipaddress.ip_network(_default(ipam["subnet"]))
    ip_range = ipaddress.ip_network(_default(ipam["ip_range"]))
    assert ipaddress.ip_address(caddy_ip) in subnet
    assert ip_range.subnet_of(subnet)
    # Docker hands out dynamic addresses only from ip_range, so no other container can take Caddy's.
    assert ipaddress.ip_address(caddy_ip) not in ip_range
    assert _default(compose["services"]["ratatoskr"]["environment"]["RATATOSKR_PROXY_IP"]) == caddy_ip


def test_caddyfile_proxies_to_the_service_and_hides_internal_paths() -> None:
    caddyfile = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    assert "{$RATATOSKR_DOMAIN}" in caddyfile
    assert "reverse_proxy ratatoskr:8000" in caddyfile
    assert re.search(r"path /healthz /readyz /metrics\b", caddyfile)
    assert "Strict-Transport-Security" in caddyfile
    assert re.search(r"request_body \{\s+max_size 8MB\s+\}", caddyfile), "request bodies are capped at the proxy"


def test_compose_config_template_is_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    import ratatoskr.transport.preconditions as preconditions
    from ratatoskr.auth.identity.local import hash_password
    from ratatoskr.transport.preconditions import check_http_preconditions

    monkeypatch.setattr(preconditions, "_check_state_path", lambda path: None)  # /data is the container's
    env = {
        "RATATOSKR_DOMAIN": "mcp.example.com",
        "RATATOSKR_PROXY_IP": _default(_compose()["services"]["ratatoskr"]["environment"]["RATATOSKR_PROXY_IP"]),
        "SERVER_SECRET_KEY": "example-secret-key-0123456789-abcdefghijklmnop",
        "ALICE_PASSWORD_HASH": hash_password("example-password"),
        "APP_DB_DSN": "postgresql://ratatoskr_read:pw@db.internal:5432/app",
    }
    config = load_config(ROOT / "deploy" / "config.example.yaml", env=env)
    assert (config.server.host, config.server.port) == ("0.0.0.0", 8000)  # the image's health check
    assert config.server.trusted_proxies == [env["RATATOSKR_PROXY_IP"] + "/32"]
    assert check_http_preconditions(config, insecure_dev=False).public_url == "https://mcp.example.com"


def test_env_example_single_quotes_the_password_hash() -> None:
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    hashes = [line for line in lines if line.startswith("ALICE_PASSWORD_HASH=")]
    assert hashes and all(line.split("=", 1)[1].startswith("'") for line in hashes), (
        "argon2 hashes contain '$': unquoted, compose would try to interpolate them"
    )
