"""Load the YAML config file, resolve ``${VAR}`` / ``${file:/path}`` references and validate it."""

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
_KIND_TAGS = frozenset({"postgres"})


class ConfigError(Exception):
    """The configuration file is missing, malformed or invalid. The message never contains secret values."""


def load_config(path: Path, env: Mapping[str, str] | None = None, *, insecure_dev: bool = False) -> RatatoskrConfig:
    """Read *path*, interpolate references from *env* (default ``os.environ``) and validate the result."""
    environment = os.environ if env is None else env
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror or exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file {path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {path} must contain a mapping at the top level")
    resolved = _interpolate(raw, environment, "")
    try:
        return RatatoskrConfig.model_validate(resolved, context={"insecure_dev": insecure_dev})
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(path, exc)) from None


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
        try:
            return file_path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise ConfigError(f"{where}: cannot read secret file {file_path}: {exc.strerror or exc}") from None
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
        lines.append(f"  - {'.'.join(location) or '<root>'}: {message}")
    return "\n".join(lines)
