"""The identity a tool call runs as."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Principal:
    subject: str
    display_name: str
    groups: frozenset[str]
    auth_source: Literal["stdio", "local", "oidc"]
