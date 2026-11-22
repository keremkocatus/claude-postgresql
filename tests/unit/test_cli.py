import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

import ratatoskr
from ratatoskr import cli
from ratatoskr.cli import DEFAULT_CONFIG_PATH, main, resolve_config_path
from ratatoskr.transport import stdio

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

# argon2id hash of "test-password": serve and check-config reject anything that is not a valid argon2id hash.
TEST_PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$vqjtPycf4eCOEVef7XA3Mw$0+yulBFTphKjBkP93QxBsGWmg2Gtx6xSnkaEDxhPAgs"

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
        password_hash: '{password_hash}'
connections:
  main:
    kind: postgres
    dsn: ${MAIN_DSN}
""".replace("{password_hash}", TEST_PASSWORD_HASH)

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
    import ratatoskr.transport.preconditions as preconditions

    # The config keeps the default /data/state.db (container path); host writability is not under test here.
    monkeypatch.setattr(preconditions, "_check_state_path", lambda path: None)
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

    async def fake_run(self: FastMCP[Any]) -> None:
        calls.append("stdio")

    monkeypatch.setattr(FastMCP, "run_stdio_async", fake_run)
    assert main(["serve", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 0
    assert calls == ["stdio"]


LEAKY_DSN = "postgresql://dbuser:leak-pass-4417@db.internal/app"


def test_serve_unexpected_error_is_logged_redacted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")

    def failing_build_app(*args: Any, **kwargs: Any) -> FastMCP[Any]:
        raise RuntimeError(f"cannot start with {LEAKY_DSN}")

    monkeypatch.setattr(stdio, "build_app", failing_build_app)
    assert main(["serve", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 1
    captured = capsys.readouterr()
    assert "leak-pass-4417" not in captured.out + captured.err
    assert "fatal error" in captured.err


def test_serve_keyboard_interrupt_exits_130(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")

    async def interrupted_run(self: FastMCP[Any]) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(FastMCP, "run_stdio_async", interrupted_run)
    assert main(["serve", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 130


def test_serve_stdio_metrics_port_in_use_exits_1(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from ratatoskr.observability.metrics_server import MetricsServer, MetricsStartupError

    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")

    def busy(self: MetricsServer) -> Any:
        raise MetricsStartupError("cannot listen for metrics on 127.0.0.1:9100 (Address already in use)")

    monkeypatch.setattr(MetricsServer, "running", busy)
    text = STDIO_CONFIG.replace("  stdio_role: admins", "  stdio_role: admins\n  metrics_port: 9100")
    assert main(["serve", "--config", str(_write(tmp_path, text))]) == 1
    err = capsys.readouterr().err
    assert "cannot listen for metrics on 127.0.0.1:9100" in err
    assert "fatal error" not in err


def test_check_config_unexpected_error_prints_only_the_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def failing_load_config(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError(f"cannot read {LEAKY_DSN}")

    monkeypatch.setattr(cli, "load_config", failing_load_config)
    assert main(["check-config", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 1
    captured = capsys.readouterr()
    assert "RuntimeError" in captured.err
    assert "leak-pass-4417" not in captured.out + captured.err
    assert "db.internal" not in captured.out + captured.err


def _read_message(lines: queue.Queue[str | None], timeout: float) -> dict[str, Any]:
    line = lines.get(timeout=timeout)
    assert line is not None, "server closed stdout early"
    message = json.loads(line)
    assert isinstance(message, dict)
    assert message.get("jsonrpc") == "2.0"
    return message


def test_serve_stdio_subprocess_speaks_json_rpc_without_leaking(tmp_path: Path) -> None:
    """Real process over stdio; the DSN points at a closed local port and is never opened."""
    password = "subproc-pass-9182"
    config = STDIO_CONFIG.replace("${MAIN_DSN}", f"postgresql://app:{password}@127.0.0.1:1/app")
    path = _write(tmp_path, config)
    env = {key: value for key, value in os.environ.items() if key != "RATATOSKR_CONFIG"}
    process = subprocess.Popen(
        [sys.executable, "-m", "ratatoskr", "serve", "--config", str(path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=env,
    )
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    lines: queue.Queue[str | None] = queue.Queue()
    stdout_lines: list[str] = []
    stderr_chunks: list[str] = []

    def pump_stdout() -> None:
        assert process.stdout is not None
        for raw in process.stdout:
            stdout_lines.append(raw)
            lines.put(raw)
        lines.put(None)

    def pump_stderr() -> None:
        assert process.stderr is not None
        stderr_chunks.append(process.stderr.read())

    threads = [threading.Thread(target=pump_stdout, daemon=True), threading.Thread(target=pump_stderr, daemon=True)]
    for thread in threads:
        thread.start()

    def send(message: dict[str, Any]) -> None:
        assert process.stdin is not None
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()

    try:
        send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            }
        )
        initialized = _read_message(lines, 30)
        assert initialized["id"] == 1
        assert initialized["result"]["serverInfo"] == {"name": "ratatoskr", "version": ratatoskr.__version__}
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = _read_message(lines, 30)
        assert tools["id"] == 2
        assert len(tools["result"]["tools"]) == 19
        send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_connections"}})
        called = _read_message(lines, 30)
        assert called["id"] == 3
        assert "| main | postgres |" in called["result"]["content"][0]["text"]
        assert called["result"]["isError"] is False
        process.stdin.close()
        assert process.wait(timeout=30) == 0
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=10)

    for raw in stdout_lines:
        if raw.strip():
            assert json.loads(raw)["jsonrpc"] == "2.0"
    output = "".join(stdout_lines) + "".join(stderr_chunks)
    assert password not in output
    assert "Processing request" not in "".join(stderr_chunks)  # log_level INFO keeps the SDK's per-request lines out


def test_check_config_says_whether_writes_use_a_separate_role(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    config = STDIO_CONFIG + (
        "    mode: write\n"
        "  other:\n"
        "    kind: postgres\n"
        "    mode: write\n"
        "    dsn: ${MAIN_DSN}\n"
        "    write_dsn: ${WRITE_DSN}\n"
        "  reports:\n"
        "    kind: postgres\n"
        "    dsn: ${MAIN_DSN}\n"
    )
    monkeypatch.setenv("MAIN_DSN", "postgresql://reader:r-secret@db.internal/app")
    monkeypatch.setenv("WRITE_DSN", "postgresql://writer:w-secret@db.internal/app")
    assert main(["check-config", "--config", str(_write(tmp_path, config))]) == 0
    out = capsys.readouterr().out
    assert "  - main: postgres, mode=write, separate write role: no  Main database" in out
    assert "  - other: postgres, mode=write, separate write role: yes" in out
    assert "  - reports: postgres, mode=read\n" in out
    for secret in ("r-secret", "w-secret", "writer", "reader", "db.internal"):
        assert secret not in out
