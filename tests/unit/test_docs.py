"""The documentation set stays consistent with the code: links resolve, every setting and metric is documented once."""

import re
from pathlib import Path
from typing import get_args

import pytest
from pydantic import BaseModel

from ratatoskr.auth.events import AuthEventName
from ratatoskr.config.loki_models import LokiConnection
from ratatoskr.config.models import AuthSettings, PostgresConnection, ServerSettings
from ratatoskr.config.prometheus_models import PrometheusConnection

ROOT = Path(__file__).resolve().parents[2]
PAGES = sorted(
    [*(ROOT / name for name in ("README.md", "CHANGELOG.md", "CONTRIBUTING.md", "MIGRATION.md", "SECURITY.md"))]
    + list((ROOT / "docs").glob("*.md"))
)
CONFIGURATION = (ROOT / "docs" / "configuration.md").read_text(encoding="utf-8")
LINK_RE = re.compile(r"\[[^\]]*\]\((?!https?://|mailto:)([^)\s]+)\)")
CODE_BLOCK_RE = re.compile(r"```.*?```", re.DOTALL)


def _anchor(heading: str) -> str:
    """GitHub's heading anchor: lower case, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(page: Path) -> set[str]:
    text = CODE_BLOCK_RE.sub("", page.read_text(encoding="utf-8"))
    return {_anchor(line.lstrip("#")) for line in text.splitlines() if line.startswith("#")}


def test_the_documentation_set_is_complete() -> None:
    names = {page.relative_to(ROOT).as_posix() for page in PAGES}
    expected = {
        "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "MIGRATION.md", "SECURITY.md", "docs/authentik.md",
        "docs/configuration.md", "docs/connectors.md", "docs/postgres-roles.md", "docs/security-model.md",
    }  # fmt: skip
    assert expected <= names


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.relative_to(ROOT).as_posix())
def test_relative_links_resolve(page: Path) -> None:
    text = CODE_BLOCK_RE.sub("", page.read_text(encoding="utf-8"))
    for target in LINK_RE.findall(text):
        path, _, fragment = target.partition("#")
        resolved = (page.parent / path).resolve() if path else page
        assert resolved.exists(), f"{page.name}: {target} does not exist"
        if fragment and resolved.suffix == ".md":
            assert fragment in _anchors(resolved), f"{page.name}: {target} has no such heading"


def _fields(model: type[BaseModel]) -> list[str]:
    return list(model.model_fields)


@pytest.mark.parametrize(
    ("model", "prefix"),
    [(ServerSettings, "server."), (AuthSettings, "auth."), (PostgresConnection, "connections.<name>.")],
    ids=["server", "auth", "postgres"],
)
def test_every_setting_is_in_the_reference(model: type[BaseModel], prefix: str) -> None:
    missing = [field for field in _fields(model) if f"`{prefix}{field}" not in CONFIGURATION]
    assert missing == []


def _section(heading: str) -> str:
    start = CONFIGURATION.index(f"## {heading}\n")
    end = CONFIGURATION.find("\n## ", start + 1)
    return CONFIGURATION[start:end]


@pytest.mark.parametrize(
    ("model", "heading"),
    [(PrometheusConnection, "Prometheus connections"), (LokiConnection, "Loki connections")],
    ids=["prometheus", "loki"],
)
def test_every_connection_setting_is_in_its_section(model: type[BaseModel], heading: str) -> None:
    section = _section(heading)
    keys = [field for field in _fields(model) if field not in ("kind", "description", "limits")]
    limits = model.model_fields["limits"].annotation
    assert isinstance(limits, type) and issubclass(limits, BaseModel)
    keys += [f"limits.{field}" for field in _fields(limits)]
    assert [key for key in keys if f"`{key}`" not in section] == []


def test_metrics_section_names_every_series_and_auth_event() -> None:
    section = _section("Metrics")
    for series in ("ratatoskr_tool_calls_total", "ratatoskr_tool_duration_seconds", "ratatoskr_backend_up"):
        assert f"`{series}`" in section
    assert "`ratatoskr_auth_events_total`" in section
    assert [event for event in get_args(AuthEventName) if f"`{event}`" not in section] == []


def test_settings_live_only_in_the_reference() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "| `server." not in readme, "the settings tables belong in docs/configuration.md"
    for page in PAGES:
        assert "not implemented" not in page.read_text(encoding="utf-8"), page.name
