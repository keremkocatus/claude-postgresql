from pathlib import Path

import pytest

from ratatoskr.cli import main, summarize
from ratatoskr.config.notices import config_warnings
from tests.fakes import make_config

TOKEN = "prom-token-7731"
CONFIG = """
server:
  stdio_role: admins
roles:
  admins: {"*": write}
connections:
  metrics:
    kind: prometheus
    description: Production metrics
    url: https://prometheus.internal.example.com
    auth:
      type: bearer
      token: ${PROM_TOKEN}
    headers:
      X-Scope-OrgID: team-7731
"""


def test_summary_names_the_auth_type_but_no_secret() -> None:
    config = make_config(
        connections={
            "metrics": {"kind": "prometheus", "auth": {"type": "bearer", "token": TOKEN}, "headers": {"X-A": "b"}}
        }
    )
    summary = summarize(config)
    assert "  - metrics: prometheus, mode=read, auth: bearer, extra headers: 1" in summary
    assert TOKEN not in summary
    assert "prometheus.internal" not in summary


def test_check_config_prints_no_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setenv("PROM_TOKEN", TOKEN)
    assert main(["check-config", "--config", str(path)]) == 0
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "metrics: prometheus, mode=read, auth: bearer, extra headers: 1  Production metrics" in captured.out
    for secret in (TOKEN, "team-7731", "prometheus.internal"):
        assert secret not in output


@pytest.mark.parametrize(
    ("url", "auth", "warned"),
    [
        ("http://prometheus.example.com:9090", {"type": "bearer", "token": "t"}, True),
        ("https://prometheus.example.com", {"type": "bearer", "token": "t"}, False),
        ("http://127.0.0.1:9090", {"type": "basic", "username": "u", "password": "p"}, False),
        ("http://[::1]:9090", {"type": "bearer", "token": "t"}, False),
        ("http://localhost:9090", {"type": "bearer", "token": "t"}, False),
        ("http://[fd00::7]:9090", {"type": "bearer", "token": "t"}, True),
        ("http://prometheus.example.com:9090", {"type": "none"}, False),
    ],
)
def test_credentials_over_plain_http_are_warned_about(url: str, auth: dict[str, str], warned: bool) -> None:
    config = make_config(connections={"metrics": {"kind": "prometheus", "url": url, "auth": auth}})
    expected = ["connections.metrics: credentials are sent over plain http; use an https url"] if warned else []
    assert config_warnings(config) == expected
