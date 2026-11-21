# Ratatoskr

Ratatoskr is an MCP server that gives Claude (Claude Desktop, Claude Code) controlled access to **several
PostgreSQL databases at once**, with per-group access levels and an audit trail. Prometheus and Loki backends are
planned.

> **Status: 1.0.0.dev0.** This release runs over **stdio** (local). The remote HTTP transport (claude.ai
> connector, OAuth login with local users or OIDC such as Authentik, Docker image) is coming in the next release.
> Coming from `claude-postgresql` 0.1? The `PG_MCP_*` environment variables are gone; everything lives in one
> YAML file.

## Features

- Any number of named PostgreSQL connections (PostgreSQL 12 or newer) in one server; the tool set stays the same
  (11 tools).
- Access per group: `read` or `write`, capped by each connection's `mode`. Unknown and forbidden connections look
  identical ("Connection 'x' not found.").
- Read-only enforcement by PostgreSQL itself rather than by SQL pattern matching (see [Security model](#security-model)).
- Every tool call is audited: one JSON log line with `event: audit` (SQL with secrets masked and truncated to 4096
  characters, plus the SHA-256 of the full text) and a `result` of `ok` (the tool answered; a health report that
  shows a connection down is still `ok`), `denied` (no identity, unknown or forbidden connection, insufficient
  access), `error` (PostgreSQL or backend error, guard rejection, unexpected failure, client cancellation) or
  `timeout` (deadline or `statement_timeout`). Arguments that do not match a tool's schema are rejected by the
  MCP layer before the call reaches Ratatoskr, so they are not audited.
- Failed calls return an `Error: ...` text with MCP `isError: true`, so the host sees them as failures.
- Responses are clamped (rows and bytes) with an explicit note on how to narrow the request. Rows that do not fit
  are left out whole; only a single row that alone exceeds the limit is cut.
- Query results are returned exactly as stored. Masking of DSNs, passwords and tokens applies to error messages,
  logs and the audited SQL, never to your data.

## Quick start (stdio)

Requires Python 3.12+.

```bash
pip install -e .                      # or: uv pip install -e .
cp config.example.yaml config.yaml    # edit connections and roles
export APP_DB_DSN='postgresql://ratatoskr_read:password@localhost:5432/app'
ratatoskr check-config --config config.yaml
```

`check-config` validates the file and prints a summary without any secret (exit code 2 on a config error).
Secrets are never written in the YAML file: use `${ENV_VAR}` or `${file:/run/secrets/name}`; an undefined
variable is an error.

### Claude Desktop

```json
{
  "mcpServers": {
    "ratatoskr": {
      "command": "ratatoskr",
      "args": ["serve", "--config", "/absolute/path/to/config.yaml"],
      "env": { "APP_DB_DSN": "postgresql://ratatoskr_read:password@localhost:5432/app" }
    }
  }
}
```

If `ratatoskr` is not on Claude Desktop's `PATH`, use the absolute path of the executable (for a virtualenv:
`.venv/bin/ratatoskr`, on Windows `.venv\Scripts\ratatoskr.exe`).

### Claude Code

```bash
claude mcp add ratatoskr -e APP_DB_DSN='postgresql://ratatoskr_read:password@localhost:5432/app' \
  -- ratatoskr serve --config /absolute/path/to/config.yaml
```

The config path can also come from `RATATOSKR_CONFIG` (default `/config/config.yaml`). Logs go to **stderr** as
JSON with DSNs and passwords masked; stdout is the MCP stdio channel.

## Configuration

One YAML file; [`config.example.yaml`](config.example.yaml) is the annotated reference. Durations accept seconds or
`30s`, `5m`, `1h`, `30d`.

| Key | Default | Meaning |
|---|---|---|
| `server.transport` | `stdio` | Only `stdio` runs in this release; `check-config` validates a `streamable-http` config but notes that `serve` will refuse it. |
| `server.stdio_role` | unset | Group you act as over stdio. Unset means you see no connection. |
| `server.log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `roles.<group>` | `{}` | `{ <connection> or "*": read \| write }`. |
| `connections.<name>.kind` | required | `postgres`. Names: `^[a-z0-9][a-z0-9_-]{0,62}$`. |
| `connections.<name>.dsn` | required | `postgresql://user:password@host:port/db`, via `${VAR}` / `${file:...}`. |
| `connections.<name>.mode` | `read` | `write` enables `pg_execute` and write-level `pg_explain(analyze=true)`. |
| `connections.<name>.write_dsn` | unset | `mode: write` only: login for the write pool (`pg_execute`, write-level `pg_explain`). Unset: the write pool uses `dsn`. Recommended (see below). |
| `connections.<name>.description` | `""` | Shown to Claude in `list_connections`. |
| `connections.<name>.statement_timeout` | `30s` | Server-side timeout of every statement. |
| `connections.<name>.pool` | `min_size: 1, max_size: 5, write_max_size: 2` | Read pool; the write pool opens lazily. |
| `connections.<name>.allowed_schemas` | `[]` (all) | Filters the discovery tools only (see below). |
| `connections.<name>.limits` | `max_rows: 500, max_response_bytes: 65536, max_query_length: 20000` | Response and input limits. |
| `connections.<name>.tls` | unset | `mode` (`disable`, `require`, `verify-ca`, `verify-full` = default), `ca_file`, `cert_file` + `key_file`. Unset: the DSN's `sslmode`. |

TLS notes:

- `tls.mode: require` encrypts without verifying and **ignores `ca_file`** (libpq would treat `require` plus a CA
  file as `verify-ca`). Use `verify-ca` or `verify-full` to check the certificate.
- Python 3.13+ enables `VERIFY_X509_STRICT` by default, which rejects internal CA certificates without a
  `keyUsage` extension (libpq accepts them). Reissue the CA, or run on Python 3.12.

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

## Security model

Effective access is `min(max(grants of your groups), connection.mode)`; no grant means no access. Over stdio you
act as a member of `server.stdio_role`.

Read access is enforced in layers:

1. Read-pool sessions start with `default_transaction_read_only=on` and `statement_timeout` as startup parameters.
2. User SQL is sent only through the extended protocol (prepared statements), which accepts a single statement,
   so `COMMIT; DELETE ...` cannot escape the transaction.
3. Every read runs inside `BEGIN READ ONLY` and is always rolled back.
4. When a connection goes back to the pool, the session is reset: role and session authorization, SQL prepared
   statements, temporary tables and sequence state, plus `RESET ALL`.
5. Catalog (discovery) queries pin `search_path` to `pg_catalog`, so user objects cannot shadow catalog functions.
6. `pg_query` and `pg_explain` refuse `COPY`, `DO` blocks, `dblink*(...)` calls and server-file functions
   (`pg_read_file`, `pg_ls_dir`, `pg_stat_file`, ...) before anything reaches the database. This is a
   convenience that catches the obvious cases, not a guarantee.

Write connections: `pg_execute` runs all statements in one transaction (on the `write_dsn` login when set) and rejects `COPY` and transaction
control (`BEGIN`, `COMMIT`, `SAVEPOINT`, ...); a few dangerous operations (`pg_read_file`, `COPY ... PROGRAM`,
`ALTER SYSTEM`, ...) are refused early, but that list is a convenience, not a guarantee. Write-level
`pg_explain(analyze=true)` is rolled back, but **non-transactional effects persist**: sequence increments
(`nextval`) and anything done through another connection.

**The database role in each DSN is the real boundary.** The layers above do not stop extensions that open their
own connections (`dblink`, `postgres_fdw`), and they cannot take away privileges the role already has.

- Give every connection a dedicated role with only the grants it needs. Never use a superuser or the table owner.
- Do not grant `dblink`, `postgres_fdw` or membership in `pg_read_server_files`, `pg_write_server_files` or
  `pg_execute_server_program`.
- On a write connection, set **`write_dsn`** to a separate write role and keep `dsn` on a read-only role. Every
  read (`pg_query`, discovery, read-level `pg_explain`) logs in with `dsn`, so readers never act as the write role;
  only `pg_execute` and write-level `pg_explain(analyze=true)` use `write_dsn`. Without it both pools log in as
  the same user, and PostgreSQL lets a session end any other session of its own user: a read-only caller could
  then end in-flight writes with `pg_terminate_backend`. The same applies to separate connections that point at
  one server with one user. TLS settings apply to both pools.
- `allowed_schemas` filters the discovery tools only; it does not restrict SQL sent to `pg_query`. Use `GRANT`s.
- Error messages never contain the DSN, host or password.

A minimal read role:

```sql
CREATE ROLE ratatoskr_read LOGIN PASSWORD 'change-me'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE app TO ratatoskr_read;
GRANT USAGE ON SCHEMA public TO ratatoskr_read;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ratatoskr_read;
-- tables created later by app_owner:
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT SELECT ON TABLES TO ratatoskr_read;
-- optional, lets pg_activity show other users' queries:
GRANT pg_read_all_stats TO ratatoskr_read;
```

And a separate write role for `write_dsn` (grant only what `pg_execute` should be able to change):

```sql
CREATE ROLE ratatoskr_write LOGIN PASSWORD 'change-me-too'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
GRANT CONNECT ON DATABASE app TO ratatoskr_write;
GRANT USAGE ON SCHEMA public TO ratatoskr_write;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ratatoskr_write;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ratatoskr_write;
```

```yaml
connections:
  app-db:
    kind: postgres
    mode: write
    dsn: ${APP_DB_READ_DSN}         # postgresql://ratatoskr_read:...@host/app
    write_dsn: ${APP_DB_WRITE_DSN}  # postgresql://ratatoskr_write:...@host/app
```

## Development

```bash
pip install --index-url https://pypi.org/simple -e ".[dev]"
python -m pytest -q                     # unit tests, no network
python -m pytest -m integration -q      # needs Docker: starts PostgreSQL with testcontainers
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
```

See [`CLAUDE.md`](CLAUDE.md) for project conventions.

## License

MIT, see [`LICENSE`](LICENSE).
