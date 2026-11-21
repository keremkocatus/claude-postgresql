from pathlib import Path

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
