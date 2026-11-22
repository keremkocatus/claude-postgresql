# Migrating from claude-postgresql 0.1 to Ratatoskr 1.0

Ratatoskr 1.0 is a rewrite of `claude-postgresql` 0.1. **Nothing is backward compatible**: the package, command,
configuration, tool names and HTTP sign-in all changed. Plan a fresh setup rather than an in-place upgrade; there is
no data to migrate (0.1 kept tokens in memory, and its optional query history table is not read by 1.0).

## 1. Install the new package or image

| 0.1 | 1.0 |
|---|---|
| package `claude-postgresql`, command `claude-postgresql` | package `ratatoskr-mcp`, command `ratatoskr serve` |
| module `claude_postgresql` | module `ratatoskr` |
| Dockerfile with `PG_MCP_TRANSPORT=streamable-http`, Railway (`railway.json`) | image running `ratatoskr serve`, `compose.yml` with Caddy; no Railway files |
| `docker-compose.yml` (PostgreSQL + pgAdmin for development) | `compose.dev.yml` (PostgreSQL, Prometheus, Loki with sample data) |

## 2. Move the settings into one YAML file

0.1 read `PG_MCP_*` environment variables and a `.env` file. 1.0 reads one YAML file
([reference](docs/configuration.md)); `PG_MCP_*` variables and `.env` are ignored. Secrets stay in the environment
and are referenced as `${NAME}`. Start from [`config.example.yaml`](config.example.yaml) (stdio) or
[`deploy/config.example.yaml`](deploy/config.example.yaml) (HTTP behind Caddy), name your database connection
(here `app-db`) and give yourself a group with access to it:

```yaml
server:
  stdio_role: admins
roles:
  admins: { app-db: write }      # or read
connections:
  app-db:
    kind: postgres
    mode: write                  # 0.1 allowed writes unless PG_MCP_READ_ONLY=true; 1.0 defaults to read
    dsn: ${APP_DB_DSN}
```

| 0.1 variable | 1.0 setting |
|---|---|
| `PG_MCP_DATABASE_URL` | `connections.<name>.dsn` (as `${VAR}`); add more connections as needed |
| `PG_MCP_READ_ONLY` | `connections.<name>.mode: read` (the default) and `read` grants in `roles` |
| `PG_MCP_POOL_MIN_SIZE`, `PG_MCP_POOL_MAX_SIZE` | `connections.<name>.pool.min_size`, `max_size` (defaults 1 and 5, was 2 and 10) |
| `PG_MCP_STATEMENT_TIMEOUT` (milliseconds) | `connections.<name>.statement_timeout` as a duration, e.g. `30s` |
| `PG_MCP_COMMAND_TIMEOUT` | none; `statement_timeout` and the tools' own deadlines apply |
| `PG_MCP_MAX_RESULT_ROWS` | `connections.<name>.limits.max_rows` (default 500) |
| `PG_MCP_MAX_QUERY_LENGTH` | `connections.<name>.limits.max_query_length` (default 20000, was 10000) |
| `PG_MCP_ALLOWED_SCHEMAS` | `connections.<name>.allowed_schemas`: filters the discovery tools only, not SQL |
| `PG_MCP_ALLOWED_TABLES` | removed: grant only those tables to the connection's role ([PostgreSQL roles](docs/postgres-roles.md)) |
| `PG_MCP_SSL_ENABLED`, `PG_MCP_SSL_CA_FILE`, `PG_MCP_SSL_CERT_FILE`, `PG_MCP_SSL_KEY_FILE` | `connections.<name>.tls`: `mode`, `ca_file`, `cert_file`, `key_file` |
| `PG_MCP_SSL_REQUIRE=true` (verified certificate) / `false` (unverified) | `tls.mode: verify-full` / `tls.mode: require` |
| `PG_MCP_QUERY_HISTORY_TABLE`, `PG_MCP_QUERY_HISTORY_DB` | removed: every tool call is audited in the JSON log and, over HTTP, in SQLite (`audit_events`) |
| `PG_MCP_LOG_QUERIES` | removed: the audit event of each call carries the query text (secrets masked) |
| `PG_MCP_LOG_LEVEL` | `server.log_level` |
| `PG_MCP_TRANSPORT` (`stdio`, `sse`, `streamable-http`) | `server.transport`: `stdio` or `streamable-http`; `sse` is gone |
| `PG_MCP_HOST`, `PG_MCP_PORT` | `server.host`, `server.port` (in the image keep `0.0.0.0` and `8000`) |
| `PG_MCP_PUBLIC_URL` | `server.public_url` (an https origin; plain http only with `--insecure-dev` on loopback) |
| `PG_MCP_ADMIN_PASSWORD` | `auth.local.users` with argon2id hashes from `ratatoskr hash-password`, or `auth.mode: oidc` |

Run `ratatoskr check-config --config config.yaml` until it reports `Config OK`.

## 3. Use a restricted database role

0.1 blocked writes by inspecting SQL. 1.0 relies on read-only sessions and, above all, on the database role: give
the connection a role that can only read (and, for `mode: write`, a separate write role as `write_dsn`) following
[PostgreSQL roles](docs/postgres-roles.md). Do not reuse an owner or superuser DSN from 0.1.

## 4. HTTP deployments: sign-in changed

0.1 protected HTTP with one shared admin password and kept tokens in memory. 1.0 needs `auth` (local users or
OIDC), `server.secret_key` (at least 32 random characters) and a writable `/data` volume for its SQLite state; it
refuses to serve HTTP without them. Every user signs in as themselves, and access follows their groups.

After switching, remove the old connector in claude.ai (or `claude mcp remove` in Claude Code) and add it again
with the new URL `https://<your domain>/mcp`: registrations and tokens from 0.1 are not valid. See
[connectors](docs/connectors.md).

## 5. Tool names

Prompts or saved instructions that name 0.1 tools need the new names. Every `pg_*` tool now takes a `connection`
argument (a name from `list_connections`).

| 0.1 tool | 1.0 tool |
|---|---|
| `list_schemas` | `pg_list_schemas` |
| `list_tables`, `get_table_sizes` | `pg_list_tables` (estimated rows and size) |
| `describe_table`, `get_table_columns`, `get_indexes`, `get_foreign_keys`, `get_constraints` | `pg_describe_table` |
| `execute_select` | `pg_query` |
| `execute_dml`, `execute_transaction` | `pg_execute` (one or more statements in one transaction; needs write access) |
| `explain_query` | `pg_explain` (`analyze=true` is rolled back) |
| `get_running_queries`, `get_locks` | `pg_activity` |
| `get_table_stats` | `pg_table_stats` |
| `connection_status` | `connection_health` |
| `list_databases`, `get_database_size` | `pg_server_info` |

New in 1.0: `list_connections`, the Prometheus tools (`prom_*`) and the Loki tools (`loki_*`).
