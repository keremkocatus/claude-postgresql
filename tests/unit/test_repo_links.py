"""Every link to the GitHub repository uses one slug, so renaming the repository is one search-and-replace.

After the owner renames the repository on GitHub, replace REPO_SLUG's value everywhere (this file included):
    git grep -l "keremkocatus/claude-postgresql" -- ":!docs/superpowers" \
      | xargs sed -i "s#keremkocatus/claude-postgresql#keremkocatus/ratatoskr#g"
The image name does not depend on the repository name: it is always ghcr.io/<owner>/ratatoskr.
"""

import os
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO_SLUG = "keremkocatus/claude-postgresql"
IMAGE = "ghcr.io/keremkocatus/ratatoskr"
SKIP_DIRS = {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "superpowers"}
SUFFIXES = {".md", ".toml", ".yml", ".yaml", ".py", ".txt", ".example", ""}
GITHUB_RE = re.compile(r"github\.com/keremkocatus/([A-Za-z0-9_.-]+)")
GHCR_RE = re.compile(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+")


def _files() -> list[Path]:
    found: list[Path] = []
    for directory, subdirectories, names in os.walk(ROOT):
        subdirectories[:] = [name for name in subdirectories if name not in SKIP_DIRS]
        found += [Path(directory) / name for name in names if Path(name).suffix in SUFFIXES]
    return found


def test_every_repository_link_uses_the_one_slug() -> None:
    repo = REPO_SLUG.split("/", 1)[1]
    seen = 0
    for path in _files():
        for name in GITHUB_RE.findall(path.read_text(encoding="utf-8", errors="replace")):
            seen += 1
            assert name.removesuffix(".git") == repo, f"{path.relative_to(ROOT)} links to keremkocatus/{name}"
    assert seen >= 5


def test_every_image_reference_uses_the_published_name() -> None:
    for path in _files():
        for image in GHCR_RE.findall(path.read_text(encoding="utf-8", errors="replace")):
            assert image == IMAGE, f"{path.relative_to(ROOT)} names {image}"


def test_project_urls_point_at_the_repository() -> None:
    urls = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["urls"]
    base = f"https://github.com/{REPO_SLUG}"
    assert urls["Repository"] == base
    assert all(url.startswith(base) for url in urls.values())
    assert f'org.opencontainers.image.source="{base}"' in (ROOT / "Dockerfile").read_text(encoding="utf-8")
