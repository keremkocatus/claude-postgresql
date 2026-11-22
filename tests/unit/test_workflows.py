"""GitHub Actions hygiene: actions pinned by commit SHA with a version comment, least privilege, no extra secrets.

The workflows cannot run locally; `actionlint` (see CONTRIBUTING.md) checks their syntax, this test their policy.
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<comment>.*)$", re.MULTILINE)
PINNED_RE = re.compile(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}")
VERSION_COMMENT_RE = re.compile(r"\s+# v\d+\.\d+\.\d+")
WRITE_SCOPES = {"release.yml": {"image": {"packages"}}}


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_there_are_workflows() -> None:
    assert [path.name for path in WORKFLOWS] == ["ci.yml", "release.yml"]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_is_pinned_by_sha_with_a_version_comment(path: Path) -> None:
    for match in USES_RE.finditer(path.read_text(encoding="utf-8")):
        ref = match.group("ref")
        if ref.startswith("./"):
            continue
        assert PINNED_RE.fullmatch(ref), f"{path.name}: {ref} is not pinned to a commit SHA"
        assert VERSION_COMMENT_RE.fullmatch(match.group("comment")), f"{path.name}: {ref} lacks a '# vX.Y.Z' comment"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_permissions_are_read_only_except_where_listed(path: Path) -> None:
    workflow = _load(path)
    assert workflow["permissions"] == {"contents": "read"}
    allowed = WRITE_SCOPES.get(path.name, {})
    for name, job in workflow["jobs"].items():
        granted = {scope for scope, level in job.get("permissions", {}).items() if level == "write"}
        assert granted <= allowed.get(name, set()), f"{path.name}: job {name} asks for {granted}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_only_github_token_and_no_privileged_triggers(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert set(re.findall(r"secrets\.(\w+)", text)) <= {"GITHUB_TOKEN"}
    assert "pull_request_target" not in text
    assert "workflow_run" not in text


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_checkout_does_not_keep_credentials(path: Path) -> None:
    for job in _load(path)["jobs"].values():
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_docker_images_run_by_workflows_are_digest_pinned() -> None:
    for path in WORKFLOWS:
        for image in re.findall(r"TRIVY_IMAGE:\s*(\S+)", path.read_text(encoding="utf-8")):
            assert re.fullmatch(r"aquasec/trivy@sha256:[0-9a-f]{64}", image), image


def test_ci_runs_every_check_the_conventions_name() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for command in (
        "python -m ruff check src tests",
        "python -m ruff format --check src tests",
        "python -m mypy src",
        "python -m pytest -q",
        "python -m pytest -m integration -q",
        "docker compose -f compose.yml config --quiet",
        "docker compose -f compose.dev.yml config --quiet",
    ):
        assert command in text, command


def test_release_publishes_multi_arch_with_sbom_and_provenance() -> None:
    release = _load(ROOT / ".github" / "workflows" / "release.yml")
    assert release["jobs"]["image"]["needs"] == "ci"
    [push] = [step for step in release["jobs"]["image"]["steps"] if step.get("with", {}).get("push") is True]
    assert push["with"]["platforms"] == "linux/amd64,linux/arm64"
    assert push["with"]["sbom"] is True
    assert push["with"]["provenance"] == "mode=max"
