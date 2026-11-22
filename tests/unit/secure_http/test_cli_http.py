"""``ratatoskr serve`` over streamable-http, ``check-config --insecure-dev`` and ``ratatoskr hash-password``."""

from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest
import uvicorn
from argon2 import PasswordHasher

import ratatoskr.cli
from ratatoskr.auth.password_cli import DESCRIPTION
from ratatoskr.cli import main
from ratatoskr.transport.preconditions import HttpSettings
from tests.unit.secure_http.conftest import SECRET_KEY

CONFIG = """
server:
  transport: streamable-http
  public_url: {public_url}
  host: {host}
  state_path: {state}
  secret_key: ${{TEST_RATATOSKR_SECRET}}
auth:
  mode: local
  local:
    users:
      - username: kerem
        password_hash: ${{TEST_RATATOSKR_HASH}}
        groups: [admins]
roles:
  admins: {{"*": write}}
connections:
  prod-pg:
    kind: postgres
    dsn: ${{TEST_RATATOSKR_DSN}}
"""


@pytest.fixture
def write_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, password_hash: str):
    monkeypatch.setenv("TEST_RATATOSKR_SECRET", SECRET_KEY)
    monkeypatch.setenv("TEST_RATATOSKR_HASH", password_hash)
    monkeypatch.setenv("TEST_RATATOSKR_DSN", "postgresql://u:p@127.0.0.1:1/db")

    def write(public_url: str = "https://mcp.example.com", host: str = "0.0.0.0") -> str:
        path = tmp_path / "config.yaml"
        text = CONFIG.format(public_url=public_url, host=host, state=(tmp_path / "state.db").as_posix())
        path.write_text(text, encoding="utf-8")
        return str(path)

    return write


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, bool, HttpSettings]]:
    calls: list[tuple[str, bool, HttpSettings]] = []

    def fake_serve_http(config, *, insecure_dev, settings):
        calls.append((config.server.transport, insecure_dev, settings))

    monkeypatch.setattr(ratatoskr.cli, "serve_http", fake_serve_http)
    return calls


# ── hash-password ───────────────────────────────────────────────────────────


def test_hash_password_prints_an_argon2id_hash(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("s3cret-pass\n"))
    assert main(["hash-password"]) == 0
    printed = capsys.readouterr().out.strip()
    assert printed.startswith("$argon2id$")
    assert PasswordHasher().verify(printed, "s3cret-pass")


def test_hash_password_warns_about_short_passwords_but_hashes_them(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("short-pw\n"))
    assert main(["hash-password"]) == 0
    captured = capsys.readouterr()
    assert PasswordHasher().verify(captured.out.strip(), "short-pw")
    assert "shorter than 12 characters" in captured.err and "short-pw" not in captured.err


def test_hash_password_does_not_warn_from_12_characters(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO("twelve-chars\n"))
    assert main(["hash-password"]) == 0
    assert capsys.readouterr().err == ""


def test_hash_password_rejects_empty_input(monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))
    assert main(["hash-password"]) == 1
    assert "empty" in capsys.readouterr().err


def test_hash_password_help_is_the_command_description(capsys) -> None:
    with pytest.raises(SystemExit) as exited:
        main(["hash-password", "--help"])
    assert exited.value.code == 0
    out = " ".join(capsys.readouterr().out.split())
    assert DESCRIPTION in out
    assert "PowerShell 5.1" in out


# ── serve ───────────────────────────────────────────────────────────────────


def test_serve_dispatches_streamable_http(write_config, served) -> None:
    assert main(["serve", "--config", write_config()]) == 0
    assert [(transport, insecure) for transport, insecure, _ in served] == [("streamable-http", False)]
    settings = served[0][2]
    assert settings.public_url == "https://mcp.example.com" and settings.local_provider is not None


def test_serve_passes_insecure_dev_on_loopback(write_config, served) -> None:
    path = write_config(public_url="http://127.0.0.1:8000", host="127.0.0.1")
    assert main(["serve", "--config", path, "--insecure-dev"]) == 0
    assert [(transport, insecure) for transport, insecure, _ in served] == [("streamable-http", True)]


def test_serve_logs_precondition_warnings_once_on_stderr(write_config, monkeypatch, capsys) -> None:
    """The CLI runs the preconditions and logs their warnings; the app it builds reuses that result."""
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)
    path = write_config(public_url="http://127.0.0.1:8000", host="127.0.0.1")
    assert main(["serve", "--config", path, "--insecure-dev"]) == 0
    captured = capsys.readouterr()
    assert captured.err.count("INSECURE DEV MODE") == 1
    assert '"level": "WARNING"' in captured.err
    assert "INSECURE DEV MODE" not in captured.out


WEAK_HASH = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash("pw")


@pytest.mark.parametrize("command", ["serve", "check-config"])
def test_weak_hash_warning_is_reported_exactly_once(write_config, monkeypatch, capsys, command) -> None:
    monkeypatch.setenv("TEST_RATATOSKR_HASH", WEAK_HASH)
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)
    assert main([command, "--config", write_config()]) == 0
    captured = capsys.readouterr()
    assert (captured.out + captured.err).count("OWASP") == 1
    assert WEAK_HASH not in captured.out + captured.err


@pytest.mark.parametrize("command", ["serve", "check-config"])
def test_metrics_port_is_accepted_without_a_warning(write_config, monkeypatch, capsys, command) -> None:
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)
    path = Path(write_config())
    path.write_text(path.read_text(encoding="utf-8").replace("  host:", "  metrics_port: 9100\n  host:"), "utf-8")
    assert main([command, "--config", str(path)]) == 0
    captured = capsys.readouterr()
    assert "server.metrics_port" not in captured.out + captured.err
    assert "not implemented" not in captured.out + captured.err


def test_check_config_reports_an_unwritable_state_directory(write_config, tmp_path, capsys) -> None:
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("x", encoding="utf-8")
    path = Path(write_config())
    text = path.read_text(encoding="utf-8")
    state_line = next(line for line in text.splitlines() if "state_path" in line)
    path.write_text(text.replace(state_line, f"  state_path: {(blocker / 'sub' / 'state.db').as_posix()}"), "utf-8")
    assert main(["check-config", "--config", str(path)]) == 2
    err = capsys.readouterr().err
    assert "server.state_path" in err and "Traceback" not in err


def test_serve_reports_http_precondition_errors(write_config, served, capsys) -> None:
    assert main(["serve", "--config", write_config(public_url="https://mcp.example.com/mcp")]) == 2
    assert "no path" in capsys.readouterr().err
    assert served == []


def test_serve_fatal_error_is_logged_redacted(write_config, monkeypatch, capsys) -> None:
    def explode(config, *, insecure_dev, settings):
        raise RuntimeError("could not reach postgresql://admin:hunter2@db.internal/app")

    monkeypatch.setattr(ratatoskr.cli, "serve_http", explode)
    assert main(["serve", "--config", write_config()]) == 1
    err = capsys.readouterr().err
    assert "fatal error" in err and "hunter2" not in err


def test_serve_startup_failure_exits_1(write_config, monkeypatch, capsys) -> None:
    def failed_startup(self, sockets=None):
        raise SystemExit(3)  # what uvicorn does when the lifespan fails or the port is taken

    monkeypatch.setattr(uvicorn.Server, "run", failed_startup)
    assert main(["serve", "--config", write_config()]) == 1
    assert "could not start" in capsys.readouterr().err


def test_serve_keyboard_interrupt_exits_130(write_config, monkeypatch) -> None:
    def interrupt(config, *, insecure_dev, settings):
        raise KeyboardInterrupt

    monkeypatch.setattr(ratatoskr.cli, "serve_http", interrupt)
    assert main(["serve", "--config", write_config()]) == 130


# ── check-config ────────────────────────────────────────────────────────────


def test_check_config_accepts_http_without_a_transport_note(write_config, capsys) -> None:
    assert main(["check-config", "--config", write_config()]) == 0
    out = capsys.readouterr().out
    assert "Config OK" in out and "transport: streamable-http" in out
    assert "not available" not in out and "Warning" not in out


def test_check_config_takes_insecure_dev_like_serve(write_config, capsys) -> None:
    path = write_config(public_url="http://127.0.0.1:8000", host="127.0.0.1")
    assert main(["check-config", "--config", path]) == 2
    assert "must use https" in capsys.readouterr().err
    assert main(["check-config", "--config", path, "--insecure-dev"]) == 0
    assert "Warning: INSECURE DEV MODE" in capsys.readouterr().out


def test_check_config_insecure_dev_still_requires_a_loopback_host(write_config, capsys) -> None:
    path = write_config(public_url="http://127.0.0.1:8000", host="0.0.0.0")
    assert main(["check-config", "--config", path, "--insecure-dev"]) == 2
    assert "--insecure-dev is only allowed when server.host" in capsys.readouterr().err


@pytest.mark.parametrize("command", ["check-config", "serve"])
@pytest.mark.parametrize("stored", ["not-a-hash", "$argon2id$garbage"])
def test_invalid_local_password_hash_is_a_config_error(write_config, monkeypatch, capsys, served, command, stored):
    monkeypatch.setenv("TEST_RATATOSKR_HASH", stored)
    assert main([command, "--config", write_config()]) == 2
    err = capsys.readouterr().err
    assert "auth.local user 'kerem': password_hash must be an argon2id hash" in err
    assert stored.split("$")[-1] not in err
    assert served == []


@pytest.mark.parametrize("command", ["check-config", "serve"])
def test_check_config_and_serve_apply_the_same_http_preconditions(
    write_config, monkeypatch, capsys, served, command
) -> None:
    monkeypatch.setenv("TEST_RATATOSKR_SECRET", "too-short")
    assert main([command, "--config", write_config()]) == 2
    err = capsys.readouterr().err
    assert "at least 32 characters" in err and "too-short" not in err
    assert served == []
