from pathlib import Path

import pytest

from ratatoskr.config.loader import load_config

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example.yaml"


def test_example_config_is_valid() -> None:
    config = load_config(EXAMPLE, env={"APP_DB_DSN": "postgresql://reader:pw@localhost:5432/app"})
    assert config.server.transport == "stdio"
    assert config.server.stdio_role == "admins"
    assert list(config.connections) == ["app-db"]
    assert config.connections["app-db"].mode == "read"


def test_commented_write_connection_example_is_valid(tmp_path: Path) -> None:
    lines = EXAMPLE.read_text(encoding="utf-8").splitlines()
    start = lines.index("  # staging-db:")
    block = [line.replace("  # ", "  ", 1) for line in lines[start:] if line.startswith("  # ")]
    path = tmp_path / "config.yaml"
    path.write_text("\n".join(lines[:start] + block) + "\n", encoding="utf-8")
    env = {
        "APP_DB_DSN": "postgresql://reader:pw@localhost/app",
        "STAGING_DB_DSN": "postgresql://reader:pw@localhost/staging",
        "STAGING_DB_WRITE_DSN": "postgresql://writer:pw@localhost/staging",
    }
    staging = load_config(path, env=env).connections["staging-db"]
    assert staging.mode == "write"
    assert staging.write_dsn is not None


def _uncomment_http(lines: list[str], *, oidc: bool) -> list[str]:
    """The config with the commented streamable-http server keys and auth section turned on."""
    out: list[str] = []
    server_keys = auth = False
    for line in lines:
        if line.startswith("  # ── streamable-http only"):
            server_keys = True
            continue
        if server_keys and not line.startswith("  # "):
            server_keys = False
        if line == "# auth:":
            auth = True
        if auth and not line.startswith("#"):
            auth = False
        if server_keys:
            out.append(line.replace("  # ", "  ", 1))
        elif auth:
            body = line[2:]
            if oidc and body.startswith("  # "):
                body = "  " + body[4:]
            elif oidc:
                body = body.replace("mode: local ", "mode: oidc ", 1)
            out.append(body)
        else:
            out.append(line.replace("transport: stdio ", "transport: streamable-http ", 1))
    return out


@pytest.mark.parametrize("oidc", [False, True], ids=["local", "oidc"])
def test_commented_http_example_is_valid(tmp_path: Path, oidc: bool) -> None:
    from ratatoskr.auth.identity.local import hash_password
    from ratatoskr.transport.preconditions import check_http_preconditions

    path = tmp_path / "config.yaml"
    path.write_text("\n".join(_uncomment_http(EXAMPLE.read_text(encoding="utf-8").splitlines(), oidc=oidc)) + "\n")
    env = {
        "APP_DB_DSN": "postgresql://reader:pw@localhost/app",
        "SERVER_SECRET_KEY": "example-secret-key-0123456789-abcdefghijklmnop",
        "ALICE_PASSWORD_HASH": hash_password("example-password"),
        "OIDC_CLIENT_ID": "ratatoskr",
        "OIDC_CLIENT_SECRET": "s" * 40,
    }
    config = load_config(path, env=env)
    assert config.server.transport == "streamable-http"
    assert config.server.trusted_proxies == ["172.18.0.0/16"]
    assert config.auth is not None and config.auth.mode == ("oidc" if oidc else "local")
    assert config.auth.session_max_age.days == 30
    assert (config.auth.oidc is not None) is oidc
    settings = check_http_preconditions(config, insecure_dev=False)
    assert settings.public_url == "https://mcp.example.com"
