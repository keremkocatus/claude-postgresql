from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from ratatoskr.cli import DEFAULT_CONFIG_PATH, main, resolve_config_path

STDIO_CONFIG = """
server:
  stdio_role: admins
roles:
  admins: {"*": write}
connections:
  main:
    kind: postgres
    description: Main database
    dsn: ${MAIN_DSN}
"""

HTTP_CONFIG = """
server:
  transport: streamable-http
  public_url: https://mcp.example.com
  secret_key: ${SECRET}
auth:
  mode: local
  local:
    users:
      - username: kerem
        password_hash: x
connections:
  main:
    kind: postgres
    dsn: ${MAIN_DSN}
"""

OIDC_CONFIG = """
server:
  transport: streamable-http
  public_url: https://mcp.example.com
  secret_key: ${SECRET}
auth:
  mode: oidc
  oidc:
    issuer: https://idp.example.com
    client_id: ratatoskr
    client_secret: ${CLIENT_SECRET}
roles:
  admins: {"*": write}
connections:
  main:
    kind: postgres
    dsn: ${MAIN_DSN}
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_config_path_precedence() -> None:
    assert resolve_config_path("a.yaml", {"RATATOSKR_CONFIG": "b.yaml"}) == Path("a.yaml")
    assert resolve_config_path(None, {"RATATOSKR_CONFIG": "b.yaml"}) == Path("b.yaml")
    assert resolve_config_path(None, {}) == DEFAULT_CONFIG_PATH


def test_check_config_ok_prints_summary_without_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://u:hunter2@db.internal/app")
    assert main(["check-config", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 0
    out = capsys.readouterr().out
    assert "Config OK" in out
    assert "main: postgres, mode=read  Main database" in out
    assert "stdio_role: admins" in out
    assert "hunter2" not in out
    assert "db.internal" not in out


@pytest.mark.parametrize("break_config", [False, True])
def test_check_config_never_prints_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], break_config: bool
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://dbuser:dsn-pass-7731@db.internal:5432/app?password=qs-pass-7731")
    monkeypatch.setenv("SECRET", "secret-key-7731-" + "k" * 32)
    monkeypatch.setenv("CLIENT_SECRET", "client-secret-7731")
    text = OIDC_CONFIG
    if break_config:  # a validation error elsewhere must not echo the resolved secrets either
        text = text.replace("https://mcp.example.com", "http://mcp.example.com")
    code = main(["check-config", "--config", str(_write(tmp_path, text))])
    assert code == (2 if break_config else 0)
    captured = capsys.readouterr()
    output = captured.out + captured.err
    for secret in ("dsn-pass-7731", "qs-pass-7731", "secret-key-7731", "client-secret-7731", "db.internal", "dbuser"):
        assert secret not in output
    if not break_config:
        assert "auth: oidc" in captured.out


def test_check_config_error_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MAIN_DSN", raising=False)
    assert main(["check-config", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 2
    assert "environment variable 'MAIN_DSN' is not defined" in capsys.readouterr().err


def test_check_config_uses_env_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
    monkeypatch.setenv("RATATOSKR_CONFIG", str(_write(tmp_path, STDIO_CONFIG)))
    assert main(["check-config"]) == 0


def test_serve_refuses_http_transport_for_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
    monkeypatch.setenv("SECRET", "s" * 32)
    assert main(["serve", "--config", str(_write(tmp_path, HTTP_CONFIG))]) == 2
    assert "'streamable-http' is not available in this version yet" in capsys.readouterr().err


def test_serve_validates_http_rules_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
    monkeypatch.setenv("SECRET", "s" * 32)
    text = HTTP_CONFIG.replace("https://mcp.example.com", "http://mcp.example.com")
    assert main(["serve", "--config", str(_write(tmp_path, text))]) == 2
    assert "must use https" in capsys.readouterr().err


def test_serve_runs_stdio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
    calls: list[str] = []

    def fake_run(self: FastMCP[Any], transport: str = "stdio", mount_path: str | None = None) -> None:
        calls.append(transport)

    monkeypatch.setattr(FastMCP, "run", fake_run)
    assert main(["serve", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 0
    assert calls == ["stdio"]
