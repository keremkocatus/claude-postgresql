"""Load the YAML config file, resolve ``${VAR}`` / ``${file:/path}`` references and validate it.

Every ``ConfigError`` is raised *outside* the ``except`` block that caught the underlying problem, so its
``__context__`` and ``__cause__`` stay ``None``: no exception carrying input values (YAML snippets, decoded
bytes, pydantic inputs) is reachable from the error object.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from ratatoskr.config.models import RatatoskrConfig

_REFERENCE_RE = re.compile(r"\$\{([^}]*)\}")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KIND_TAGS = frozenset({"postgres", "prometheus"})


class ConfigError(Exception):
    """The configuration file is missing, malformed or invalid. The message never contains secret values."""


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    """SafeLoader that rejects a mapping key defined twice instead of silently keeping the last value."""

    def construct_mapping(self, node: Any, deep: bool = False) -> Any:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError:
                continue  # unhashable key: the base constructor reports it
            if duplicate:
                raise yaml.constructor.ConstructorError(None, None, f"duplicate key '{key}'", key_node.start_mark)
        return super().construct_mapping(node, deep=deep)


def load_config(path: Path, env: Mapping[str, str] | None = None, *, insecure_dev: bool = False) -> RatatoskrConfig:
    """Read *path*, interpolate references from *env* (default ``os.environ``) and validate the result."""
    environment = os.environ if env is None else env
    text = _read_text(path, f"cannot read config file {path}")
    raw = _parse_yaml(path, text)
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {path} must contain a mapping at the top level")
    resolved = _interpolate(raw, environment, "")
    try:
        return RatatoskrConfig.model_validate(resolved, context={"insecure_dev": insecure_dev})
    except ValidationError as exc:
        message = _format_validation_error(path, exc)
    raise ConfigError(message)


def _read_text(path: Path, prefix: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        message = f"{prefix}: the file is not valid UTF-8"
    except OSError as exc:
        message = f"{prefix}: {exc.strerror or type(exc).__name__}"
    raise ConfigError(message)


def _parse_yaml(path: Path, text: str) -> Any:
    try:
        return yaml.load(text, Loader=_UniqueKeyLoader)  # a SafeLoader subclass: no arbitrary objects
    except yaml.YAMLError as exc:
        message = f"config file {path} is not valid YAML: {_describe_yaml_error(exc)}"
    raise ConfigError(message)


def _describe_yaml_error(exc: yaml.YAMLError) -> str:
    """Only the problem text and its position: never the source snippet, which may hold a secret."""
    problem = getattr(exc, "problem", None) or "syntax error"
    mark = getattr(exc, "problem_mark", None)
    if mark is None:
        return str(problem)
    return f"{problem} (line {mark.line + 1}, column {mark.column + 1})"


def _interpolate(value: Any, env: Mapping[str, str], where: str) -> Any:
    if isinstance(value, dict):
        return {key: _interpolate(item, env, f"{where}.{key}" if where else str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate(item, env, f"{where}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, str):
        return _REFERENCE_RE.sub(lambda match: _resolve(match.group(1).strip(), env, where), value)
    return value


def _resolve(reference: str, env: Mapping[str, str], where: str) -> str:
    if reference.startswith("file:"):
        file_path = Path(reference[len("file:") :])
        return _read_text(file_path, f"{where}: cannot read secret file {file_path}").rstrip("\r\n")
    if not _ENV_NAME_RE.match(reference):
        raise ConfigError(f"{where}: invalid reference '${{{reference}}}'; use ${{VAR_NAME}} or ${{file:/path}}")
    if reference not in env:
        raise ConfigError(f"{where}: environment variable '{reference}' is not defined")
    return env[reference]


def _format_validation_error(path: Path, exc: ValidationError) -> str:
    lines = [f"config file {path} is invalid:"]
    for error in exc.errors(include_input=False, include_url=False):
        location = [str(part) for part in error["loc"]]
        if len(location) >= 3 and location[0] == "connections" and location[2] in _KIND_TAGS:
            del location[2]
        message = str(error["msg"]).removeprefix("Value error, ")
        if error["type"] == "union_tag_invalid":
            # pydantic's text repeats the given tag, which could be a misplaced ${SECRET}
            message = f"unknown value; expected one of {error.get('ctx', {}).get('expected_tags', '')}"
        lines.append(f"  - {'.'.join(location) or '<root>'}: {message}")
    return "\n".join(lines)
