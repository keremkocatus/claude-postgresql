<p align="center"><img src="docs/assets/ratatoskr.svg" alt="Ratatoskr: a squirrel carrying a database cylinder" width="128"></p>

# Ratatoskr

[![CI](https://github.com/keremkocatus/ratatoskr-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/keremkocatus/ratatoskr-mcp/actions/workflows/ci.yml)

Ratatoskr is an MCP server that gives Claude (claude.ai, Claude Desktop, Claude Code) controlled access to
**several PostgreSQL databases, Prometheus servers and Loki log stores at once**, with per-group access levels and
an audit trail. MIT licensed.

> **Status: 1.0.0, not released yet** (the package says `1.0.0.dev0`). Runs locally over **stdio**, or as a team
> server over **streamable HTTP** behind a TLS proxy, as a claude.ai custom connector: Ratatoskr is its own OAuth 2.1
> authorization server, and people sign in with local users or through an OIDC provider such as Authentik.
> Coming from `claude-postgresql` 0.1? See [`MIGRATION.md`](MIGRATION.md): there is no backward compatibility.

## Features

- Any number of named PostgreSQL (12 or newer), Prometheus and Loki connections in one server; the tool set stays
  the same (19 tools). Prometheus connections also work with Mimir, Thanos Query and VictoriaMetrics.
- Access per group: `read` or `write`, capped by each connection's `mode`. Unknown and forbidden connections look
  identical ("Connection 'x' not found.").
- Read-only enforcement by PostgreSQL itself rather than by SQL pattern matching (see the
  [security model](docs/security-model.md) and the [role recipe](docs/postgres-roles.md)).
- Every tool call is audited: one JSON log line with `event: audit` (the SQL, PromQL or LogQL with secrets masked
  and truncated to 4096 characters, plus the SHA-256 of the full text) and a `result` of `ok`, `denied`, `error` or
  `timeout`; over HTTP also in SQLite (`/data/state.db`, kept 90 days by default).
- Failed calls return an `Error: ...` text with MCP `isError: true`, so the host sees them as failures.
- Responses are clamped (rows and bytes) with an explicit note on how to narrow the request.
- Remote use over streamable HTTP with OAuth 2.1 (dynamic client registration, PKCE, rotating refresh tokens with
  reuse detection, revocation), local argon2id users or OIDC (Authentik) and rate-limited sign-in.
- Prometheus metrics on a separate port: tool calls, latency, backend reachability, auth events.
- Query results and log lines are returned exactly as stored (long log lines are cut, and marked). Masking of DSNs,
  passwords and tokens applies to error messages, logs and the audited query text, never to your data.

## Quick start: team server (Docker Compose + Caddy)

[`compose.yml`](compose.yml) runs Ratatoskr behind Caddy, which gets a Let's Encrypt certificate for your domain.
You need a host with Docker, a DNS name pointing at it and ports 80 and 443 open.

```bash
git clone https://github.com/keremkocatus/ratatoskr-mcp.git ratatoskr && cd ratatoskr
cp .env.example .env                          # set RATATOSKR_DOMAIN and the secrets
cp deploy/config.example.yaml config.yaml     # users, roles, connections
docker compose build
docker compose run --rm ratatoskr hash-password   # paste the hash into .env, inside single quotes
docker compose run --rm ratatoskr check-config
docker compose up -d
```

Then add `https://<RATATOSKR_DOMAIN>/mcp` as a custom connector in claude.ai, or in Claude Code with
`claude mcp add --transport http ratatoskr https://<RATATOSKR_DOMAIN>/mcp`; see [connectors](docs/connectors.md).
Give each connection a restricted database role ([PostgreSQL roles](docs/postgres-roles.md)); for single sign-on
follow [Authentik](docs/authentik.md).

The container runs as uid 10001 with a read-only root file system, keeps its state in the `ratatoskr-data` volume
and is reachable only through Caddy, which also hides `/healthz`, `/readyz` and `/metrics` and cuts request
bodies off after 8 MB. Configuration changes need `docker compose restart ratatoskr`.

## Quick start: on your machine (stdio)

Requires Python 3.12+.

```bash
pip install -e .                      # from a checkout; or: uv pip install -e .
cp config.example.yaml config.yaml    # edit connections and roles
export APP_DB_DSN='postgresql://ratatoskr_read:password@localhost:5432/app'
ratatoskr check-config --config config.yaml
claude mcp add ratatoskr -e APP_DB_DSN="$APP_DB_DSN" -- ratatoskr serve --config "$PWD/config.yaml"
```

Claude Desktop takes the same command in `claude_desktop_config.json`; see [connectors](docs/connectors.md). Logs
go to **stderr** as JSON with secrets masked; stdout is the MCP channel.

## Try it with sample data

[`compose.dev.yml`](compose.dev.yml) starts PostgreSQL with a small shop database (and the restricted roles of the
role recipe), Prometheus, Loki with a log generator, all on this machine:

```bash
docker compose -f compose.dev.yml up -d
claude mcp add ratatoskr-dev -- docker compose -f "$PWD/compose.dev.yml" run --rm -T --use-aliases ratatoskr
```

Or run Ratatoskr from your checkout over HTTP against the same stack
(`ratatoskr serve --insecure-dev --config dev/ratatoskr/local-http.yaml`, then connect a client to
`http://127.0.0.1:8000/mcp` and sign in as `dev` / `ratatoskr-dev`). `docker compose -f compose.dev.yml down -v`
removes it all.

## Tools

| Tool | Access | What it does |
|---|---|---|
| `list_connections` | - | Connections you may use, their kind, description and your access level. Call it first. |
| `connection_health` | read | Reachability, latency and server version of one or all of your connections. |
| `pg_list_schemas` | read | Non-system schemas (filtered by `allowed_schemas`). |
| `pg_list_tables` | read | Tables, views and partitions of a schema with estimated rows and size; `name_like` filter. |
| `pg_describe_table` | read | Columns, constraints (PK/FK/unique/check), incoming FKs and indexes in one call. |
| `pg_query` | read | One read-only statement; rows as a Markdown table. |
| `pg_execute` | write | One or more statements in a single atomic transaction. |
| `pg_explain` | read / write | Plan; `analyze=true` runs the statement in a transaction that is rolled back. |
| `pg_activity` | read | Active sessions and waiting locks. |
| `pg_table_stats` | read | Size, scans, live/dead tuples, vacuum and analyze times. |
| `pg_server_info` | read | Version, current database and size, uptime, database list. |
| `prom_query` | read | PromQL at one instant (default now): each series with its value, or a scalar. A range selector (`up[5m]`) returns the raw samples. |
| `prom_query_range` | read | PromQL over a window (default the last hour): per series points, min/max/avg/last and sampled points. |
| `prom_list_metrics` | read | Metric names with data in a window, with type and help; `name_contains` and `match` filters. |
| `prom_label_values` | read | Values of one label, optionally only on series matching a selector. |
| `prom_alerts` | read | Firing and pending alerts, and the state of every rule group (unhealthy rules with their last error). |
| `loki_query` | read | LogQL over a window (default the last hour, at most `max_range`). Log queries: lines newest first (`direction: forward` for oldest first), each stream's labels once, `limit` lines (default 100). Metric queries: per series points, min/max/avg/last and sampled points. |
| `loki_labels` | read | Label names on streams with data in a window, optionally only streams matching a `selector`. |
| `loki_label_values` | read | Values of one label, optionally only on streams matching a `selector`. |

Prometheus tools take `connection` from `list_connections` and refuse a PostgreSQL connection (and the `pg_*` tools a
Prometheus one). Times accept RFC3339 (`2026-11-22T10:00:00Z`), unix seconds, or `now`, `now-15m`, `now-2h`; windows
(`start`/`end` of `prom_query_range`, `prom_list_metrics` and `prom_label_values`) default to the last hour. Time and
`step` arguments longer than 64 characters are refused. A `step` must be at least `1ms` and is rounded to whole
milliseconds; without `step`, `prom_query_range` picks a round one that gives up to about 120 points. Label names
for `prom_label_values` are plain Prometheus names (`^[A-Za-z_][A-Za-z0-9_]*$`).

Loki tools refuse other kinds of connection the same way and take the same time formats. `loki_query` always uses
Loki's range endpoint: a log query returns at most `limit` lines and says when Loki stopped at the limit (narrow with
a shorter window, more label matchers or a `|= "text"` filter); labels shared by every stream are shown once at the top
and each stream's own labels once above its lines; timestamps have milliseconds (UTC); lines of a multi-line entry
are indented under it. A metric query (`count_over_time`, `rate`, `sum by`) is summarised like `prom_query_range`;
`step` applies to it (default: up to about 120 points). Label names for `loki_label_values` follow the same pattern
as for Prometheus.

## Documentation

| Page | What it covers |
|---|---|
| [Configuration reference](docs/configuration.md) | Every setting, connection kind, metrics, containers, environment variables. |
| [Connectors](docs/connectors.md) | claude.ai custom connector, Claude Desktop, Claude Code. |
| [PostgreSQL roles](docs/postgres-roles.md) | Restricted read role and separate write role, tested SQL. |
| [Authentik](docs/authentik.md) | Single sign-on with OIDC, Caddy example, verification checklist. |
| [Security model](docs/security-model.md) | What Ratatoskr enforces and what it leaves to roles and proxies. |
| [Migration from 0.1](MIGRATION.md) | `claude-postgresql` 0.1 to Ratatoskr 1.0. |
| [Changelog](CHANGELOG.md), [Contributing](CONTRIBUTING.md), [Security policy](SECURITY.md) | |

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the setup, the checks CI runs and the conventions
([`CLAUDE.md`](CLAUDE.md)).

## License

MIT, see [`LICENSE`](LICENSE).
