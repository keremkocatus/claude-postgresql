from __future__ import annotations

import io
import logging
from collections.abc import Iterator

import pytest
import uvicorn
from starlette.applications import Starlette

from ratatoskr.observability.logging import setup_logging
from ratatoskr.transport import serve as serve_module
from ratatoskr.transport.preconditions import check_http_preconditions
from ratatoskr.transport.serve import UVICORN_LOGGERS, uvicorn_config


@pytest.fixture
def clean_uvicorn_loggers() -> Iterator[None]:
    yield
    for name in (*UVICORN_LOGGERS, "uvicorn.access"):
        named = logging.getLogger(name)
        for handler in list(named.handlers):
            named.removeHandler(handler)
        named.propagate = True
    logging.getLogger("aiosqlite").setLevel(logging.NOTSET)


def test_uvicorn_logs_go_through_the_redacting_root_handler(make_config, clean_uvicorn_loggers) -> None:
    stream = io.StringIO()
    setup_logging("INFO", stream=stream)
    # What uvicorn's default LOGGING_CONFIG (or an earlier uvicorn.run) leaves behind: own handlers, no propagation.
    bypass = io.StringIO()
    logging.getLogger("uvicorn.error").addHandler(logging.StreamHandler(bypass))
    logging.getLogger("uvicorn").addHandler(logging.StreamHandler(bypass))
    logging.getLogger("uvicorn").propagate = False
    logging.getLogger("uvicorn.access").addHandler(logging.StreamHandler(bypass))

    config = uvicorn_config(Starlette(), make_config().server)

    assert config.log_config is None and config.access_log is False and config.proxy_headers is False
    assert config.server_header is False
    for name in UVICORN_LOGGERS:
        assert logging.getLogger(name).handlers == [] and logging.getLogger(name).propagate
    assert not logging.getLogger("uvicorn.access").hasHandlers()
    logging.getLogger("uvicorn.error").error("connect to postgresql://admin:hunter2@db.internal/app failed")
    logging.getLogger("uvicorn.access").warning("GET /oauth/callback?code=secret-code-123 HTTP/1.1")
    out = stream.getvalue()
    assert '"logger": "uvicorn.error"' in out
    assert "postgresql://***" in out and "hunter2" not in out
    assert "secret-code-123" not in out
    assert bypass.getvalue() == ""


def test_serve_http_runs_uvicorn_with_that_config(make_config, monkeypatch, clean_uvicorn_loggers) -> None:
    seen: list[uvicorn.Config] = []
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: seen.append(self.config))
    config = make_config(server_extra={"port": 8123})
    serve_module.serve_http(config, insecure_dev=False)
    assert len(seen) == 1
    assert (seen[0].host, seen[0].port, seen[0].log_config, seen[0].access_log) == ("0.0.0.0", 8123, None, False)
    assert isinstance(seen[0].app, Starlette)
    assert logging.getLogger("aiosqlite").level == logging.INFO


def test_uvicorn_startup_failure_becomes_an_exception(make_config, monkeypatch, clean_uvicorn_loggers) -> None:
    """uvicorn ends a failed startup (lifespan error, port in use) with ``sys.exit(3)``; the CLI maps errors to 1."""

    def failed_startup(self, sockets=None):
        raise SystemExit(3)

    monkeypatch.setattr(uvicorn.Server, "run", failed_startup)
    with pytest.raises(serve_module.HttpServerStartupError):
        serve_module.serve_http(make_config(), insecure_dev=False)


def test_serve_http_reuses_checked_settings(make_config, monkeypatch, clean_uvicorn_loggers) -> None:
    monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)
    config = make_config()
    settings = check_http_preconditions(config, insecure_dev=False)
    built: list[object] = []
    real_build = serve_module.build_http_app

    def spy(config, *, insecure_dev, settings=None):
        built.append(settings)
        return real_build(config, insecure_dev=insecure_dev, settings=settings)

    monkeypatch.setattr(serve_module, "build_http_app", spy)
    serve_module.serve_http(config, insecure_dev=False, settings=settings)
    assert built == [settings]
