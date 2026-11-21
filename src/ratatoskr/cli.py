"""Command line: ``ratatoskr serve`` and ``ratatoskr check-config``."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from ratatoskr import __version__
from ratatoskr.app import build_app
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.config.loader import ConfigError, load_config
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import LogAuditSink
from ratatoskr.observability.logging import setup_logging

DEFAULT_CONFIG_PATH = Path("/config/config.yaml")
CONFIG_ENV_VAR = "RATATOSKR_CONFIG"
EXIT_CONFIG_ERROR = 2

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
    return parser


def summarize(config: RatatoskrConfig) -> str:
    """A secret-free overview of the configuration."""
    server = config.server
    lines = [f"transport: {server.transport}"]
    if server.transport == "stdio":
        lines.append(f"stdio_role: {server.stdio_role or '(not set: the stdio user cannot see any connection)'}")
    lines.append(f"auth: {config.auth.mode if config.auth else 'none'}")
    lines.append(f"roles ({len(config.roles)}): {', '.join(sorted(config.roles)) or '-'}")
    lines.append(f"connections ({len(config.connections)}):")
    for name in sorted(config.connections):
        connection = config.connections[name]
        description = f"  {connection.description}" if connection.description else ""
        lines.append(f"  - {name}: {connection.kind}, mode={connection.mode}{description}")
    return "\n".join(lines)


def _check_config(args: argparse.Namespace) -> int:
    path = resolve_config_path(args.config)
    try:
        config = load_config(path)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    print(f"Config OK: {path}")
    print(summarize(config))
    return 0


def _serve(args: argparse.Namespace) -> int:
    path = resolve_config_path(args.config)
    try:
        config = load_config(path, insecure_dev=args.insecure_dev)
        if config.server.transport != "stdio":
            raise ConfigError(
                "server.transport 'streamable-http' is not available in this version yet; "
                "use transport: stdio (HTTP with OAuth arrives in the next release)."
            )
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG_ERROR
    setup_logging(config.server.log_level)
    if config.server.stdio_role is None:
        logger.warning("server.stdio_role is not set: the stdio user cannot see any connection")
    app = build_app(config, resolver=StdioPrincipalResolver(config.server.stdio_role), audit=LogAuditSink())
    logger.info("starting ratatoskr %s over stdio with %d connection(s)", __version__, len(config.connections))
    app.run(transport="stdio")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "check-config":
        return _check_config(args)
    return _serve(args)
