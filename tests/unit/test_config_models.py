from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ratatoskr.config.models import Access, RatatoskrConfig


def _config(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"connections": {"main": {"kind": "postgres", "dsn": "postgresql://u:p@h/db"}}}
    data.update(overrides)
    return data


def _http(**server: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "transport": "streamable-http",
        "public_url": "https://mcp.example.com",
        "secret_key": "k" * 32,
    }
    base.update(server)
    auth = {"mode": "local", "local": {"users": [{"username": "kerem", "password_hash": "x"}]}}
    return _config(server=base, auth=auth)


def test_defaults() -> None:
    config = RatatoskrConfig.model_validate(_config())
    connection = config.connections["main"]
    assert config.server.transport == "stdio"
    assert connection.mode == "read"
    assert connection.statement_timeout == timedelta(seconds=30)
    assert connection.limits.max_rows == 500
    assert connection.limits.max_response_bytes == 65536
    assert connection.pool.write_max_size == 2
    assert connection.tls is None


def test_access_order() -> None:
    assert Access.NONE < Access.READ < Access.WRITE


def test_duration_strings_are_parsed() -> None:
    data = _config()
    data["connections"]["main"]["statement_timeout"] = "5m"
    config = RatatoskrConfig.model_validate(data)
    assert config.connections["main"].statement_timeout == timedelta(minutes=5)


@pytest.mark.parametrize("name", ["Prod", "-x", "has space", "a" * 64, "dot.name"])
def test_rejects_bad_connection_names(name: str) -> None:
    data = _config(connections={name: {"kind": "postgres", "dsn": "postgresql://h/db"}})
    with pytest.raises(ValidationError, match="invalid connection name"):
        RatatoskrConfig.model_validate(data)


@pytest.mark.parametrize("name", ["prod-pg", "staging_pg", "0db", "a" * 63])
def test_accepts_good_connection_names(name: str) -> None:
    RatatoskrConfig.model_validate(_config(connections={name: {"kind": "postgres", "dsn": "postgresql://h/db"}}))


def test_roles_must_reference_known_connections() -> None:
    with pytest.raises(ValidationError, match="roles.devops references unknown connection"):
        RatatoskrConfig.model_validate(_config(roles={"devops": {"main": "read", "ghost": "write"}}))


def test_roles_accept_wildcard() -> None:
    config = RatatoskrConfig.model_validate(_config(roles={"admins": {"*": "write"}}))
    assert config.roles == {"admins": {"*": "write"}}


def test_roles_reject_unknown_level() -> None:
    with pytest.raises(ValidationError):
        RatatoskrConfig.model_validate(_config(roles={"admins": {"*": "admin"}}))


def test_stdio_role_must_be_defined() -> None:
    with pytest.raises(ValidationError, match="stdio_role 'ops' is not defined"):
        RatatoskrConfig.model_validate(_config(server={"stdio_role": "ops"}))


def test_unknown_keys_are_rejected() -> None:
    data = _config()
    data["connections"]["main"]["passwrd"] = "typo"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RatatoskrConfig.model_validate(data)


def test_unknown_connection_kind_is_rejected() -> None:
    with pytest.raises(ValidationError, match="does not match any of the expected tags"):
        RatatoskrConfig.model_validate(_config(connections={"m": {"kind": "mysql", "dsn": "x"}}))


def test_pool_min_cannot_exceed_max() -> None:
    data = _config()
    data["connections"]["main"]["pool"] = {"min_size": 6, "max_size": 5}
    with pytest.raises(ValidationError, match="cannot exceed"):
        RatatoskrConfig.model_validate(data)


def test_tls_files_must_exist(tmp_path: Path) -> None:
    data = _config()
    data["connections"]["main"]["tls"] = {"mode": "verify-full", "ca_file": str(tmp_path / "missing.pem")}
    with pytest.raises(ValidationError, match="tls.ca_file does not exist"):
        RatatoskrConfig.model_validate(data)


def test_http_transport_valid_config() -> None:
    config = RatatoskrConfig.model_validate(_http())
    assert config.server.transport == "streamable-http"


def test_http_transport_requires_auth_secret_and_url() -> None:
    data = _config(server={"transport": "streamable-http"})
    with pytest.raises(ValidationError) as excinfo:
        RatatoskrConfig.model_validate(data)
    message = str(excinfo.value)
    assert "an auth section is required" in message
    assert "server.secret_key is required" in message
    assert "server.public_url is required" in message


def test_http_transport_requires_https() -> None:
    with pytest.raises(ValidationError, match="must use https"):
        RatatoskrConfig.model_validate(_http(public_url="http://mcp.example.com"))


def test_insecure_dev_allows_http_on_loopback() -> None:
    data = _http(public_url="http://localhost:8000", host="127.0.0.1")
    config = RatatoskrConfig.model_validate(data, context={"insecure_dev": True})
    assert str(config.server.public_url).startswith("http://localhost")


def test_insecure_dev_rejected_on_public_bind() -> None:
    data = _http(public_url="http://localhost:8000", host="0.0.0.0")
    with pytest.raises(ValidationError, match="only allowed when server.host is"):
        RatatoskrConfig.model_validate(data, context={"insecure_dev": True})


def test_local_auth_needs_users() -> None:
    data = _http()
    data["auth"] = {"mode": "local", "local": {"users": []}}
    with pytest.raises(ValidationError, match="at least one user"):
        RatatoskrConfig.model_validate(data)


def test_oidc_auth_needs_oidc_block() -> None:
    data = _http()
    data["auth"] = {"mode": "oidc"}
    with pytest.raises(ValidationError, match="needs auth.oidc"):
        RatatoskrConfig.model_validate(data)


def test_auth_ttls_accept_durations() -> None:
    data = _http()
    data["auth"]["access_token_ttl"] = "15m"
    config = RatatoskrConfig.model_validate(data)
    assert config.auth is not None
    assert config.auth.access_token_ttl == timedelta(minutes=15)


def test_log_level_is_normalised() -> None:
    config = RatatoskrConfig.model_validate(_config(server={"log_level": "debug"}))
    assert config.server.log_level == "DEBUG"
    with pytest.raises(ValidationError, match="log_level"):
        RatatoskrConfig.model_validate(_config(server={"log_level": "LOUD"}))


def test_oidc_block_requires_client_secret() -> None:
    data = _http()
    data["auth"] = {"mode": "oidc", "oidc": {"issuer": "https://id.example.com", "client_id": "ratatoskr"}}
    with pytest.raises(ValidationError, match="client_secret"):
        RatatoskrConfig.model_validate(data)


# -- write_dsn ---------------------------------------------------------------------------------------------------


def _pg(**values: Any) -> dict[str, Any]:
    return _config(connections={"main": {"kind": "postgres", "dsn": "postgresql://reader@h/db", **values}})


def test_write_dsn_defaults_to_none() -> None:
    assert RatatoskrConfig.model_validate(_pg(mode="write")).connections["main"].write_dsn is None


def test_write_dsn_is_a_secret_on_write_connections() -> None:
    connection = RatatoskrConfig.model_validate(
        _pg(mode="write", write_dsn="postgresql://writer:w-secret@h/db")
    ).connections["main"]
    assert connection.write_dsn is not None
    assert connection.write_dsn.get_secret_value() == "postgresql://writer:w-secret@h/db"
    assert "w-secret" not in repr(connection)


def test_write_dsn_is_rejected_on_read_connections() -> None:
    with pytest.raises(ValidationError, match="write_dsn is only allowed with mode: write") as excinfo:
        RatatoskrConfig.model_validate(_pg(mode="read", write_dsn="postgresql://writer:w-secret@h/db"))
    assert "w-secret" not in str(excinfo.value.errors(include_input=False, include_url=False))
