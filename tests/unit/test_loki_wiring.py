"""A `kind: loki` connection through config loading, policy, make_config, the registry and check-config."""

from pathlib import Path

import pytest
import respx

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.backends.loki.backend import LokiBackend
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.cli import main, summarize
from ratatoskr.config.loader import ConfigError, load_config
from ratatoskr.config.loki_models import LokiConnection
from ratatoskr.config.models import Access
from ratatoskr.config.notices import config_warnings
from tests.fakes import make_config

TOKEN = "loki-token-VALUE-never-shown"
TENANT = "tenant-7731"


def _write(tmp_path: Path, connection: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(
        f"server: {{stdio_role: admins}}\nroles: {{admins: {{'*': write}}}}\nconnections:\n  logs:\n{connection}",
        encoding="utf-8",
    )
    return path


def test_connection_loads_from_yaml(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "    kind: loki\n"
        "    url: https://logs.example.com\n"
        "    tenant: ${LOKI_TENANT}\n"
        "    auth:\n      type: bearer\n      token: ${LOKI_TOKEN}\n",
    )
    connection = load_config(path, env={"LOKI_TOKEN": TOKEN, "LOKI_TENANT": TENANT}).connections["logs"]
    assert isinstance(connection, LokiConnection)
    assert connection.tenant is not None and connection.tenant.get_secret_value() == TENANT


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("    kind: loki\n    url: http://l:3100\n    mode: write\n", "connections.logs.mode: loki connections are"),
        ("    kind: loki\n", "connections.logs.url: Field required"),
        ("    kind: loki\n    url: http://l:3100\n    tenant: 'a b'\n", "connections.logs.tenant: tenant must be"),
        (
            "    kind: loki\n    url: http://l:3100\n    headers: {X-Scope-OrgID: t}\n",
            "connections.logs.headers: headers: X-Scope-OrgID cannot be set here; use tenant",
        ),
    ],
)
def test_error_paths_drop_the_kind_tag(tmp_path: Path, body: str, expected: str) -> None:
    with pytest.raises(ConfigError, match=expected):
        load_config(_write(tmp_path, body), env={})


@pytest.mark.parametrize(
    "body",
    [
        "    kind: loki\n    url: http://l:3100\n    tenant: '${LOKI_TOKEN} x'\n",
        "    kind: loki\n    url: http://l:3100\n    headers: { X-Scope-OrgID: '${LOKI_TOKEN}' }\n",
        "    kind: ${LOKI_TOKEN}\n    url: http://l:3100\n",
    ],
)
def test_validation_errors_never_echo_secrets(tmp_path: Path, body: str) -> None:
    with pytest.raises(ConfigError) as caught:
        load_config(_write(tmp_path, body), env={"LOKI_TOKEN": TOKEN})
    assert TOKEN not in str(caught.value)


def test_policy_caps_loki_at_read() -> None:
    config = make_config(connections={"logs": {"kind": "loki"}}, roles={"admins": {"*": "write"}})
    principal = Principal("alice", "Alice", frozenset({"admins"}), "local")
    assert Policy(config).effective_access(principal, "logs") == Access.READ


async def test_registry_builds_opens_and_closes_loki_backends(loki_api: respx.Router) -> None:
    config = make_config(connections={"db": {}, "logs": {"kind": "loki", "description": "Logs"}})
    registry = BackendRegistry(config)
    backend = await registry.get("logs")
    assert isinstance(backend, LokiBackend)
    assert backend.is_open
    assert registry.describe("logs").kind == "loki"
    assert registry.max_response_bytes("logs") == 65536
    await registry.close_all()
    assert not backend.is_open


def test_summary_says_whether_a_tenant_is_set_but_never_shows_it() -> None:
    config = make_config(
        connections={
            "logs": {"kind": "loki", "tenant": TENANT, "auth": {"type": "bearer", "token": TOKEN}},
            "other": {"kind": "loki", "headers": {"X-A": "b"}},
        }
    )
    summary = summarize(config)
    assert "  - logs: loki, mode=read, auth: bearer, tenant: yes, extra headers: 0" in summary
    assert "  - other: loki, mode=read, auth: none, tenant: no, extra headers: 1" in summary
    for secret in (TOKEN, TENANT, "loki.internal"):
        assert secret not in summary


def test_check_config_prints_no_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = _write(
        tmp_path,
        "    kind: loki\n    description: Production logs\n    url: http://logs.example.com:3100\n"
        "    tenant: ${LOKI_TENANT}\n    auth: {type: basic, username: '123', password: '${LOKI_TOKEN}'}\n",
    )
    monkeypatch.setenv("LOKI_TOKEN", TOKEN)
    monkeypatch.setenv("LOKI_TENANT", TENANT)
    assert main(["check-config", "--config", str(path)]) == 0
    captured = capsys.readouterr()
    assert "logs: loki, mode=read, auth: basic, tenant: yes, extra headers: 0  Production logs" in captured.out
    assert "Warning: connections.logs: credentials are sent over plain http; use an https url" in captured.out
    for secret in (TOKEN, TENANT, "logs.example.com"):
        assert secret not in captured.out + captured.err


def test_plain_http_warning_covers_loki() -> None:
    config = make_config(connections={"logs": {"kind": "loki", "auth": {"type": "bearer", "token": "t"}}})
    assert config_warnings(config) == ["connections.logs: credentials are sent over plain http; use an https url"]
