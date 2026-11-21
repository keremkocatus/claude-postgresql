from pathlib import Path

from ratatoskr.config.loader import load_config

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example.yaml"


def test_example_config_is_valid() -> None:
    config = load_config(EXAMPLE, env={"APP_DB_DSN": "postgresql://reader:pw@localhost:5432/app"})
    assert config.server.transport == "stdio"
    assert config.server.stdio_role == "admins"
    assert list(config.connections) == ["app-db"]
    assert config.connections["app-db"].mode == "read"
