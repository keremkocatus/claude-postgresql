"""Command line: ``ratatoskr serve``, ``ratatoskr check-config`` and ``ratatoskr hash-password``."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from ratatoskr import __version__
from ratatoskr.auth.password_cli import DESCRIPTION as HASH_PASSWORD_DESCRIPTION
from ratatoskr.auth.password_cli import run_hash_password
from ratatoskr.config.http_models import HttpConnection
from ratatoskr.config.loader import ConfigError, load_config
from ratatoskr.config.loki_models import LokiConnection
from ratatoskr.config.models import PostgresConnection, RatatoskrConfig
from ratatoskr.config.notices import config_warnings
from ratatoskr.observability.logging import setup_logging
from ratatoskr.observability.metrics_server import MetricsStartupError
from ratatoskr.transport.preconditions import check_http_preconditions
from ratatoskr.transport.serve import HttpServerStartupError, serve_http
from ratatoskr.transport.stdio import serve_stdio

DEFAULT_CONFIG_PATH = Path("/config/config.yaml")
CONFIG_ENV_VAR = "RATATOSKR_CONFIG"
EXIT_UNEXPECTED_ERROR = 1
EXIT_CONFIG_ERROR = 2
EXIT_INTERRUPTED = 130

logger = logging.getLogger("ratatoskr.cli")


def resolve_config_path(argument: str | None, env: Mapping[str, str] | None = None) -> Path:
    """--config wins, then RATATOSKR_CONFIG, then /config/config.yaml."""
    environment = os.environ if env is None else env
    if argument:
        return Path(argument)
    if environment.get(CONFIG_ENV_VAR):
        return Path(environment[CONFIG_ENV_VAR])
    return DEFAULT_CONFIG_PATH


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ratatoskr", description="Ratatoskr MCP server")
    parser.add_argument("--version", action="version", version=f"ratatoskr {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="run the MCP server")
    serve.add_argument("--config", help=f"config file (default: ${CONFIG_ENV_VAR} or {DEFAULT_CONFIG_PATH})")
    serve.add_argument(
        "--insecure-dev", action="store_true", help="allow http public_url on a loopback host (local testing only)"
    )
    check = commands.add_parser("check-config", help="validate the config file and print a summary")
    check.add_argument("--config", help=f"config file (default: ${CONFIG_ENV_VAR} or {DEFAULT_CONFIG_PATH})")
    check.add_argument(
        "--insecure-dev", action="store_true", help="validate as `serve --insecure-dev` would (local testing only)"
    )
    commands.add_parser(
        "hash-password",
        help="print the argon2id hash of a password for auth.local.users[].password_hash",
        description=HASH_PASSWORD_DESCRIPTION,
    )
    return parser


def _metrics_summary(config: RatatoskrConfig) -> str:
    server = config.server
    if server.metrics_port is None:
        return "off"
    host = f"[{server.metrics_host}]" if ":" in server.metrics_host else server.metrics_host
    return f"http://{host}:{server.metrics_port}/metrics"


def summarize(config: RatatoskrConfig) -> str:
    """A secret-free overview of the configuration."""
    server = config.server
    lines = [f"transport: {server.transport}", f"metrics: {_metrics_summary(config)}"]
    if server.transport == "stdio":
        lines.append(f"stdio_role: {server.stdio_role or '(not set: the stdio user cannot see any connection)'}")
    lines.append(f"auth: {config.auth.mode if config.auth else 'none'}")
    lines.append(f"roles ({len(config.roles)}): {', '.join(sorted(config.roles)) or '-'}")
    lines.append(f"connections ({len(config.connections)}):")
    for name in sorted(config.connections):
        connection = config.connections[name]
        description = f"  {connection.description}" if connection.description else ""
        details = ""
        if isinstance(connection, PostgresConnection) and connection.mode == "write":
            details = f", separate write role: {'yes' if connection.write_dsn is not None else 'no'}"
        elif isinstance(connection, HttpConnection):
            tenant = ""
            if isinstance(connection, LokiConnection):
                tenant = f", tenant: {'yes' if connection.tenant is not None else 'no'}"
            details = f", auth: {connection.auth.type}{tenant}, extra headers: {len(connection.headers)}"
        lines.append(f"  - {name}: {connection.kind}, mode={connection.mode}{details}{description}")
    return "\n".join(lines)


def _check_config(args: argparse.Namespace) -> int:
    path = resolve_config_path(args.config)
    try:
        config = load_config(path, insecure_dev=args.insecure_dev)
        # The same checks and warnings serve reports before binding, so the two commands cannot disagree.
        warnings: tuple[str, ...] = tuple(config_warnings(config))
        if config.server.transport == "streamable-http":
            warnings = check_http_preconditions(config, insecure_dev=args.insecure_dev).warnings
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except Exception as exc:
        # Unexpected: its message may carry config values, so only the class name is shown.
        print(f"Unexpected error while checking the config: {type(exc).__name__}", file=sys.stderr)
        return EXIT_UNEXPECTED_ERROR
    print(f"Config OK: {path}")
    print(summarize(config))
    for warning in warnings:
        print(f"Warning: {warning}")
    return 0


def _serve(args: argparse.Namespace) -> int:
    path = resolve_config_path(args.config)
    try:
        config = load_config(path, insecure_dev=args.insecure_dev)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    setup_logging(config.server.log_level)
    if config.server.transport == "streamable-http":
        return _serve_http(config, insecure_dev=args.insecure_dev)
    if config.server.stdio_role is None:
        logger.warning("server.stdio_role is not set: the stdio user cannot see any connection")
    for warning in config_warnings(config):
        logger.warning(warning)
    try:
        logger.info("starting ratatoskr %s over stdio with %d connection(s)", __version__, len(config.connections))
        asyncio.run(serve_stdio(config))
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except MetricsStartupError as exc:
        logger.error("%s", exc)
        return EXIT_UNEXPECTED_ERROR
    except Exception:
        # Through the redacting JSON handler: a raw traceback on stderr could carry a DSN or password.
        logger.exception("fatal error")
        return EXIT_UNEXPECTED_ERROR
    return 0


def _serve_http(config: RatatoskrConfig, *, insecure_dev: bool) -> int:
    try:
        # Same checks and messages as check-config; the result goes to the app so they are not run (or their
        # warnings logged) a second time.
        settings = check_http_preconditions(config, insecure_dev=insecure_dev)
        for warning in settings.warnings:
            logger.warning(warning)
        logger.info("starting ratatoskr %s over streamable-http at %s", __version__, settings.public_url)
        serve_http(config, insecure_dev=insecure_dev, settings=settings)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    except HttpServerStartupError as exc:
        logger.error("%s", exc)  # uvicorn already logged why
        return EXIT_UNEXPECTED_ERROR
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except Exception:
        # Through the redacting JSON handler: a raw traceback on stderr could carry a DSN or password.
        logger.exception("fatal error")
        return EXIT_UNEXPECTED_ERROR
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "hash-password":
        return run_hash_password(sys.stdin, sys.stdout, sys.stderr)
    if args.command == "check-config":
        return _check_config(args)
    return _serve(args)
