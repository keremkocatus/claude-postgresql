"""Run the streamable-http app under uvicorn, with every log line going through Ratatoskr's redacting handler."""

from __future__ import annotations

import logging

import uvicorn
from starlette.types import ASGIApp

from ratatoskr.config.models import RatatoskrConfig, ServerSettings
from ratatoskr.transport.app import build_http_app
from ratatoskr.transport.preconditions import HttpSettings

UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.asgi")
UVICORN_ACCESS_LOGGER = "uvicorn.access"
# aiosqlite logs every statement with its parameters (token hashes, sealed secrets) at DEBUG.
AIOSQLITE_LOGGER = "aiosqlite"


class HttpServerStartupError(RuntimeError):
    """uvicorn could not start (lifespan failed, address in use); the reason is already in the log."""


def route_uvicorn_logs_to_root() -> None:
    """Drop handlers uvicorn (or an earlier ``uvicorn.run``) installed so its records reach the root JSON handler.

    ``setup_logging`` puts the only handler, which redacts, on the root logger. uvicorn's default
    ``LOGGING_CONFIG`` would give ``uvicorn``/``uvicorn.access`` their own plain handlers with ``propagate=False``,
    bypassing that redaction. ``uvicorn.access`` only loses its handlers: with ``access_log=False`` uvicorn keeps it
    from propagating, so request lines (which carry ``?code=`` and ``?request=`` values) are never written.
    """
    for name in (*UVICORN_LOGGERS, UVICORN_ACCESS_LOGGER):
        uvicorn_logger = logging.getLogger(name)
        for handler in list(uvicorn_logger.handlers):
            uvicorn_logger.removeHandler(handler)
    for name in UVICORN_LOGGERS:
        logging.getLogger(name).propagate = True


def uvicorn_config(app: ASGIApp, server: ServerSettings) -> uvicorn.Config:
    """``log_config=None``: uvicorn installs no logging config of its own.

    ``access_log=False``: request lines carry ``/login?request=…`` and ``/oauth/callback?code=…`` values that must
    not reach logs (uvicorn then also empties ``uvicorn.access`` and stops it propagating). ``proxy_headers=False``:
    uvicorn must not rewrite the client address; ``transport.client_ip`` applies ``server.trusted_proxies`` itself.
    """
    config = uvicorn.Config(
        app,
        host=server.host,
        port=server.port,
        proxy_headers=False,
        server_header=False,
        access_log=False,
        log_config=None,
        lifespan="on",
    )
    route_uvicorn_logs_to_root()
    return config


def serve_http(config: RatatoskrConfig, *, insecure_dev: bool, settings: HttpSettings | None = None) -> None:
    """Build the app and block until shutdown. Raises ``ConfigError`` before binding when the config is unfit.

    ``settings`` is the result of :func:`check_http_preconditions` when the caller already ran it (and reported its
    warnings); without it ``build_http_app`` runs the preconditions and logs the warnings itself.
    """
    http_app = build_http_app(config, insecure_dev=insecure_dev, settings=settings)
    logging.getLogger(AIOSQLITE_LOGGER).setLevel(logging.INFO)
    try:
        uvicorn.Server(uvicorn_config(http_app.asgi, config.server)).run()
    except SystemExit as exc:
        # uvicorn ends a failed startup with sys.exit(3); the CLI keeps its own exit codes (1 for this).
        if exc.code in (0, None):
            raise
        raise HttpServerStartupError("the HTTP server could not start; see the log lines above") from None
