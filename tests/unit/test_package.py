import importlib.metadata
import tomllib
from pathlib import Path

import ratatoskr

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def test_version_is_single_sourced_from_the_package() -> None:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    assert "version" not in project["project"]
    assert project["project"]["dynamic"] == ["version"]
    assert project["tool"]["hatch"]["version"]["path"] == "src/ratatoskr/__init__.py"


def test_installed_metadata_matches_the_package_version() -> None:
    assert importlib.metadata.version("ratatoskr-mcp") == ratatoskr.__version__
