"""Warnings about settings that are accepted but do nothing yet; ``serve`` and ``check-config`` report them."""

from __future__ import annotations

from ratatoskr.config.models import RatatoskrConfig


def config_warnings(config: RatatoskrConfig) -> list[str]:
    warnings: list[str] = []
    if config.server.metrics_port is not None:
        warnings.append(
            f"server.metrics_port is set ({config.server.metrics_port}) but metrics are not implemented yet;"
            " nothing listens on that port"
        )
    return warnings
