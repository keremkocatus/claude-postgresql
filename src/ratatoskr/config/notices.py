"""Start-up warnings ``serve`` and ``check-config`` report: settings accepted but not implemented yet, and risky but
allowed choices such as credentials sent over plain http."""

from __future__ import annotations

from ratatoskr.config.models import LOOPBACK_HOSTS, RatatoskrConfig
from ratatoskr.config.prometheus_models import PrometheusConnection


def config_warnings(config: RatatoskrConfig) -> list[str]:
    warnings: list[str] = []
    if config.server.metrics_port is not None:
        warnings.append(
            f"server.metrics_port is set ({config.server.metrics_port}) but metrics are not implemented yet;"
            " nothing listens on that port"
        )
    for name, connection in sorted(config.connections.items()):
        if (
            isinstance(connection, PrometheusConnection)
            and connection.auth.type != "none"
            and connection.url.scheme == "http"
            and connection.url.host not in LOOPBACK_HOSTS
        ):
            warnings.append(f"connections.{name}: credentials are sent over plain http; use an https url")
    return warnings
