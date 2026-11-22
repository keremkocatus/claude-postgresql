"""No regex in src may use ``$``: it also matches before a final "\\n", so ``re.match(r"^...$", value)`` lets
``"team-a\\n"`` through a whole-value check. Validation uses ``fullmatch`` (or ``\\Z``)."""

from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "ratatoskr"
_REGEX_FUNCTIONS = frozenset({"compile", "match", "search", "fullmatch", "sub", "subn", "split", "findall", "finditer"})
_ESCAPE = re.compile(r"\\.", re.DOTALL)
_CHARACTER_CLASS = re.compile(r"\[\^?\]?[^\]]*\]")


def _patterns() -> list[tuple[str, int, str]]:
    found: list[tuple[str, int, str]] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.args):
                continue
            owner = node.func.value
            if not (isinstance(owner, ast.Name) and owner.id == "re" and node.func.attr in _REGEX_FUNCTIONS):
                continue
            pattern = node.args[0]
            parts = pattern.values if isinstance(pattern, ast.JoinedStr) else [pattern]
            text = "".join(
                part.value for part in parts if isinstance(part, ast.Constant) and isinstance(part.value, str)
            )
            found.append((path.relative_to(SRC).as_posix(), node.lineno, text))
    return found


def _uses_dollar(pattern: str) -> bool:
    bare = _CHARACTER_CLASS.sub("", _ESCAPE.sub("", pattern))
    return "$" in bare


def test_the_scan_finds_the_patterns() -> None:
    files = {path for path, _, _ in _patterns()}
    assert {"config/loki_models.py", "config/http_models.py", "config/models.py", "backends/series.py"} <= files


def test_dollar_detection() -> None:
    assert _uses_dollar(r"^[a-z]+$")
    assert _uses_dollar(r"\.\d+(?=Z$)")
    assert not _uses_dollar(r"\$argon2id\$v=19")
    assert not _uses_dollar(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
    assert not _uses_dollar(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def test_no_pattern_in_src_uses_dollar() -> None:
    offenders = [f"{path}:{line}: {pattern}" for path, line, pattern in _patterns() if _uses_dollar(pattern)]
    assert offenders == []
