"""A `kind: prometheus` connection end to end through config loading, policy, make_config and the registry."""

from pathlib import Path

import pytest
import respx

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.loader import ConfigError, load_config
from ratatoskr.config.models import Access, PostgresConnection
from ratatoskr.config.prometheus_models import PrometheusConnection
from tests.fakes import make_config

TOKEN = "prom-token-VALUE-never-shown"


def _write(tmp_path: Path, connection: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(f"roles: {{admins: {{'*': write}}}}\nconnections:\n  prom:\n{connection}", encoding="utf-8")
    return path


def test_connection_loads_from_yaml(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "    kind: prometheus\n"
        "    url: https://mimir.example.com/prometheus\n"
        "    auth:\n      type: bearer\n      token: ${PROM_TOKEN}\n"
        "    headers:\n      X-Scope-OrgID: ${PROM_TENANT}\n",
    )
    connection = load_config(path, env={"PROM_TOKEN": TOKEN, "PROM_TENANT": "team-a"}).connections["prom"]
    assert isinstance(connection, PrometheusConnection)
    assert connection.headers["X-Scope-OrgID"].get_secret_value() == "team-a"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("    kind: prometheus\n    url: http://p:9090\n    mode: write\n", "connections.prom.mode: prometheus "),
        ("    kind: prometheus\n", "connections.prom.url: Field required"),
        ("    kind: prometheus\n    url: http://p:9090\n    dsn: x\n", "connections.prom.dsn: Extra inputs"),
    ],
)
def test_error_paths_drop_the_kind_tag(tmp_path: Path, body: str, expected: str) -> None:
    with pytest.raises(ConfigError, match=expected):
        load_config(_write(tmp_path, body), env={})


@pytest.mark.parametrize(
    "body",
    [
        "    kind: prometheus\n    url: http://p:9090\n    auth: { type: bearer, token: '${PROM_TOKEN}', x: 1 }\n",
        "    kind: prometheus\n    url: ${PROM_TOKEN}\n",
        "    kind: prometheus\n    url: http://u:${PROM_TOKEN}@p:9090\n",
        "    kind: prometheus\n    url: http://p:9090\n    auth: { type: '${PROM_TOKEN}' }\n",
        "    kind: ${PROM_TOKEN}\n    url: http://p:9090\n",
        '    kind: prometheus\n    url: http://p:9090\n    headers: { X-A: "a\\nb${PROM_TOKEN}" }\n',
    ],
)
def test_validation_errors_never_echo_secrets(tmp_path: Path, body: str) -> None:
    with pytest.raises(ConfigError) as caught:
        load_config(_write(tmp_path, body), env={"PROM_TOKEN": TOKEN})
    assert TOKEN not in str(caught.value)


def test_unknown_auth_type_lists_the_choices(tmp_path: Path) -> None:
    body = "    kind: prometheus\n    url: http://p:9090\n    auth: { type: digest }\n"
    with pytest.raises(ConfigError, match="auth: unknown value; expected one of 'none', 'basic', 'bearer'"):
        load_config(_write(tmp_path, body), env={})


def test_policy_caps_prometheus_at_read() -> None:
    config = make_config(connections={"prom": {"kind": "prometheus"}}, roles={"admins": {"*": "write"}})
    principal = Principal("alice", "Alice", frozenset({"admins"}), "local")
    assert Policy(config).effective_access(principal, "prom") == Access.READ


def test_make_config_builds_both_kinds() -> None:
    config = make_config(connections={"db": {}, "prom": {"kind": "prometheus", "description": "m"}})
    assert isinstance(config.connections["db"], PostgresConnection)
    prom = config.connections["prom"]
    assert isinstance(prom, PrometheusConnection)
    assert prom.description == "m"


async def test_registry_builds_opens_and_closes_prometheus_backends(prom_api: respx.Router) -> None:
    config = make_config(connections={"db": {}, "prom": {"kind": "prometheus"}})
    registry = BackendRegistry(config)
    backend = await registry.get("prom")
    assert isinstance(backend, PrometheusBackend)
    assert backend.is_open
    assert registry.describe("prom").kind == "prometheus"
    assert registry.max_response_bytes("prom") == 65536
    await registry.close_all()
    assert not backend.is_open
