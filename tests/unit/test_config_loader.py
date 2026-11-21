from pathlib import Path

import pytest

from ratatoskr.config.loader import ConfigError, load_config

BASE = """
server:
  stdio_role: admins
roles:
  admins: {"*": write}
connections:
  main:
    kind: postgres
    mode: write
    dsn: ${MAIN_DSN}
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_env_interpolation(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, BASE), env={"MAIN_DSN": "postgresql://u:pw@db/app"})
    assert config.connections["main"].dsn.get_secret_value() == "postgresql://u:pw@db/app"


def test_interpolation_inside_a_longer_string(tmp_path: Path) -> None:
    text = BASE.replace("${MAIN_DSN}", "postgresql://app:${PG_PASSWORD}@db/app")
    config = load_config(_write(tmp_path, text), env={"PG_PASSWORD": "s3cret"})
    assert config.connections["main"].dsn.get_secret_value() == "postgresql://app:s3cret@db/app"


def test_file_interpolation_strips_trailing_newline(tmp_path: Path) -> None:
    secret = tmp_path / "dsn.txt"
    secret.write_text("postgresql://u:filepw@db/app\n", encoding="utf-8")
    text = BASE.replace("${MAIN_DSN}", "${file:" + secret.as_posix() + "}")
    config = load_config(_write(tmp_path, text), env={})
    assert config.connections["main"].dsn.get_secret_value() == "postgresql://u:filepw@db/app"


def test_undefined_variable_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="connections.main.dsn: environment variable 'MAIN_DSN' is not defined"):
        load_config(_write(tmp_path, BASE), env={})


def test_missing_secret_file_is_an_error(tmp_path: Path) -> None:
    text = BASE.replace("${MAIN_DSN}", "${file:" + (tmp_path / "nope").as_posix() + "}")
    with pytest.raises(ConfigError, match="cannot read secret file"):
        load_config(_write(tmp_path, text), env={})


def test_invalid_reference_syntax(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid reference"):
        load_config(_write(tmp_path, BASE.replace("${MAIN_DSN}", "${not valid}")), env={})


def test_empty_variable_value_is_allowed(tmp_path: Path) -> None:
    text = BASE.replace("dsn: ${MAIN_DSN}", "dsn: postgresql://db/app\n    description: '${DESC}'")
    config = load_config(_write(tmp_path, text), env={"DESC": ""})
    assert config.connections["main"].description == ""


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(tmp_path / "absent.yaml", env={})


def test_invalid_yaml(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(_write(tmp_path, "connections: [unclosed"), env={})


def test_top_level_must_be_mapping(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="mapping at the top level"):
        load_config(_write(tmp_path, "- a\n- b\n"), env={})


def test_validation_errors_are_readable_and_hide_secrets(tmp_path: Path) -> None:
    text = BASE.replace("mode: write", "mode: admin")
    with pytest.raises(ConfigError) as excinfo:
        load_config(_write(tmp_path, text), env={"MAIN_DSN": "postgresql://u:topsecret@db/app"})
    message = str(excinfo.value)
    assert "connections.main.mode" in message
    assert "topsecret" not in message


def test_unknown_role_connection_is_reported(tmp_path: Path) -> None:
    text = BASE.replace('admins: {"*": write}', "admins: {ghost: read}")
    with pytest.raises(ConfigError, match="roles.admins references unknown connection"):
        load_config(_write(tmp_path, text), env={"MAIN_DSN": "postgresql://db/app"})


def test_insecure_dev_is_passed_to_validation(tmp_path: Path) -> None:
    text = BASE.replace("server:\n", "server:\n  host: 0.0.0.0\n")
    with pytest.raises(ConfigError, match="--insecure-dev is only allowed"):
        load_config(_write(tmp_path, text), env={"MAIN_DSN": "postgresql://db/app"}, insecure_dev=True)


def test_uses_os_environ_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://env@db/app")
    config = load_config(_write(tmp_path, BASE))
    assert config.connections["main"].dsn.get_secret_value() == "postgresql://env@db/app"
