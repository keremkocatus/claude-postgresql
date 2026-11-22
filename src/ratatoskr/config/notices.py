"""Start-up warnings ``serve`` and ``check-config`` report: risky but allowed choices such as credentials sent over
plain http."""

from __future__ import annotations

from ratatoskr.config.http_models import HttpConnection
from ratatoskr.config.models import LOOPBACK_HOSTS, RatatoskrConfig


def config_warnings(config: RatatoskrConfig) -> list[str]:
    warnings: list[str] = []
    for name, connection in sorted(config.connections.items()):
        if (
            isinstance(connection, HttpConnection)
            and connection.auth.type != "none"
            and connection.url.scheme == "http"
            and (connection.url.host or "").strip("[]") not in LOOPBACK_HOSTS  # pydantic keeps IPv6 brackets
        ):
            warnings.append(f"connections.{name}: credentials are sent over plain http; use an https url")
    return warnings
