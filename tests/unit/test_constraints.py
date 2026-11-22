"""constraints.txt pins every direct runtime dependency of pyproject.toml at a version its specifier allows."""

import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[2]


def _pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (ROOT / "constraints.txt").read_text(encoding="utf-8").splitlines():
        line = line.split(";", 1)[0].strip()
        if line and not line.startswith("#"):
            name, version = line.split("==")
            pins[canonicalize_name(name)] = version.strip()
    return pins


def test_every_direct_dependency_is_pinned_within_its_range() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    pins = _pins()
    for spec in project["dependencies"]:
        requirement = Requirement(spec)
        name = canonicalize_name(requirement.name)
        assert name in pins, f"{name} is missing from constraints.txt"
        assert requirement.specifier.contains(pins[name]), f"{name}=={pins[name]} is outside {requirement.specifier}"
