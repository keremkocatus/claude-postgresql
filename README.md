# Ratatoskr

Ratatoskr is an MCP server that gives Claude (claude.ai, Claude Desktop, Claude Code) controlled access to
**several PostgreSQL databases, Prometheus servers and Loki log stores at once**, with per-group access levels and
an audit trail.

> **Status: 1.0.0.dev0.** Runs locally over **stdio**, or remotely over **streamable HTTP** as a claude.ai custom
> connector: Ratatoskr is its own OAuth 2.1 authorization server, and people sign in with local users or through an
> OIDC provider such as Authentik. The Docker image is built from the [`Dockerfile`](Dockerfile).
> Coming from `claude-postgresql` 0.1? The `PG_MCP_*` environment variables are gone; everything lives in one
> YAML file.

## Features

- Any number of named PostgreSQL (12 or newer), Prometheus and Loki connections in one server; the tool set stays
  the same (19 tools). Prometheus connections also work with Mimir, Thanos Query and VictoriaMetrics.
- Access per group: `read` or `write`, capped by each connection's `mode`. Unknown and forbidden connections look
  identical ("Connection 'x' not found.").
- Read-only enforcement by PostgreSQL itself rather than by SQL pattern matching (see [Security model](#security-model)).
- Every tool call is audited: one JSON log line with `event: audit` (the SQL, PromQL or LogQL with secrets masked and truncated to 4096
  characters, plus the SHA-256 of the full text) and a `result` of `ok` (the tool answered; a health report that
  shows a connection down is still `ok`), `denied` (no identity, unknown or forbidden connection, insufficient
  access), `error` (PostgreSQL, Prometheus, Loki or backend error, guard rejection, unexpected failure, client cancellation) or
  `timeout` (deadline, `statement_timeout`, Prometheus' query timeout or Loki's HTTP 504). Arguments that do not match a tool's schema are rejected by the
  MCP layer before the call reaches Ratatoskr, so they are not audited.
- Failed calls return an `Error: ...` text with MCP `isError: true`, so the host sees them as failures.
- Responses are clamped (rows and bytes) with an explicit note on how to narrow the request. Rows that do not fit
  are left out whole; only a single row that alone exceeds the limit is cut.
- Remote use over streamable HTTP with OAuth 2.1 (dynamic client registration, PKCE, rotating refresh tokens with
  reuse detection, revocation), local argon2id users or OIDC (Authentik), rate-limited login pages, and a
  persistent audit trail in SQLite (`/data/state.db`, kept 90 days by default).
- Query results and log lines are returned exactly as stored (long log lines are cut, and marked). Masking of DSNs,
  passwords and tokens applies to error messages, logs and the audited query text, never to your data.

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

## Quick start (remote: claude.ai connector over HTTP)

Ratatoskr serves plain HTTP on port 8000 and needs a reverse proxy that terminates TLS (Caddy, nginx, Traefik) at a
public https origin, here `https://mcp.example.com`.

1. Build the image (multi-stage, `python:3.12-slim`, runs as uid 10001, writes only to `/data`, so it runs with a
   read-only root file system):

   ```bash
   docker build -t ratatoskr .
   ```

2. Create a password hash for each local user. It prompts twice without echo (or reads one line from stdin):

   ```bash
   docker run -it --rm ratatoskr hash-password
   ```

   On Windows PowerShell 5.1, piping a password replaces non-ASCII characters; use the prompt for those.

3. Write `config.yaml` (see the commented HTTP section of [`config.example.yaml`](config.example.yaml)):

   ```yaml
   server:
     transport: streamable-http
     public_url: https://mcp.example.com
     host: 0.0.0.0
     port: 8000
     secret_key: ${SERVER_SECRET_KEY}        # >= 32 random characters
     trusted_proxies: [172.17.0.1]           # the address your reverse proxy connects from (see below)
   auth:
     mode: local
     local:
       users:
         - username: alice
           password_hash: ${ALICE_PASSWORD_HASH}
           groups: [admins]
   roles:
     admins: { "*": read }
   connections:
     app-db:
       kind: postgres
       dsn: ${APP_DB_DSN}
   ```

4. Check it, then run it. The image reads `/config/config.yaml` and keeps its state in the `/data` volume:

   ```bash
   export SERVER_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
   docker run --rm --read-only -v "$PWD/config.yaml:/config/config.yaml:ro" \
     -e SERVER_SECRET_KEY -e ALICE_PASSWORD_HASH -e APP_DB_DSN ratatoskr check-config
   docker run -d --name ratatoskr --read-only --restart unless-stopped -p 127.0.0.1:8000:8000 \
     -v ratatoskr-data:/data -v "$PWD/config.yaml:/config/config.yaml:ro" \
     -e SERVER_SECRET_KEY -e ALICE_PASSWORD_HASH -e APP_DB_DSN ratatoskr
   ```

   `docker ps` shows `(healthy)` once `/healthz` answers. The state lives in the named volume `ratatoskr-data`;
   if you bind-mount a host directory on `/data` instead, it must be owned by uid 10001
   (`sudo chown 10001:10001 /srv/ratatoskr-data`), otherwise `check-config` and `serve` stop with
   `server.state_path: ... is not writable by uid 10001`. `docker stop` sends SIGTERM: in-flight requests get a
   few seconds to finish and queued audit events are written before the process exits. Keep the stop grace period
   at **10 s or more** (Docker's default; do not lower it with `docker stop -t` or compose `stop_grace_period`),
   otherwise SIGKILL can cut off the audit flush.

   **`trusted_proxies`** must hold the address the *container* sees the proxy connect from. With the proxy on the
   host and `-p 127.0.0.1:8000:8000` as above, that is the Docker bridge gateway, not `127.0.0.1`: find it with
   `docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}'` (usually `172.17.0.1`; for a
   user-defined network use its name instead of `bridge`). Simpler and tighter: run the proxy (e.g. Caddy) in the
   same Docker network as Ratatoskr, do not publish port 8000 at all, and list that network's subnet or the proxy
   container's address ([`docs/authentik.md`](docs/authentik.md) has a Caddy example). With a wrong value every
   client shares the proxy's rate-limit bucket.

   **Configuration changes need a restart** (`docker restart ratatoskr`); there is no reload on SIGHUP. After the
   restart they apply at once to existing sessions too: roles, local users' groups, removed users and changed
   passwords are checked on every request with an access token (OIDC groups follow at the next refresh).

5. Point the reverse proxy at port 8000. In claude.ai open *Settings → Connectors → Add custom connector* and enter
   `https://mcp.example.com/mcp`: claude.ai registers itself, sends you to Ratatoskr's sign-in page and connects.
   Claude Code uses the same URL: `claude mcp add --transport http ratatoskr https://mcp.example.com/mcp`. Claude
   Code registers as a public client (no client secret, PKCE only); that is supported, including `/revoke`.

For single sign-on with Authentik (`auth.mode: oidc`), follow [`docs/authentik.md`](docs/authentik.md); it also has
a Caddy example and a verification checklist.

For local testing without TLS, `serve --insecure-dev` (and `check-config --insecure-dev`) accept an `http://`
`public_url`, but only when both `server.host` and the `public_url` host are loopback (`127.0.0.1`, `localhost`,
`::1`).

## Configuration

One YAML file; [`config.example.yaml`](config.example.yaml) is the annotated reference. Durations accept seconds or
`30s`, `5m`, `1h`, `30d`.

| Key | Default | Meaning |
|---|---|---|
| `server.transport` | `stdio` | `stdio` (local) or `streamable-http` (remote; needs `auth`, `public_url` and `secret_key`). |
| `server.stdio_role` | unset | Group you act as over stdio. Unset means you see no connection. |
| `server.log_level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `server.public_url` | unset | HTTP: the public https origin without a path, e.g. `https://mcp.example.com`; the MCP endpoint is `<public_url>/mcp`. |
| `server.host` / `server.port` | `127.0.0.1` / `8000` | HTTP listen address. In the container use `0.0.0.0` and `8000` (the health check uses 8000). |
| `server.secret_key` | unset | HTTP: at least 32 characters. Seals stored client secrets and upstream refresh tokens and signs cookies. Changing it signs everyone out. |
| `server.state_path` | `/data/state.db` | HTTP: SQLite state (clients, tokens, rate limits, audit trail). |
| `server.trusted_proxies` | `[]` | HTTP: IPs/CIDRs of your reverse proxies; `X-Forwarded-For` is honoured only from them (rate limits use the client IP). |
| `server.allowed_redirect_hosts` | `[claude.ai, claude.com, localhost, 127.0.0.1]` | HTTP: exact hosts (any port) an OAuth client may register in a `redirect_uri`; https required except on loopback. |
| `server.audit_retention` | `90d` | HTTP: audit rows in SQLite older than this are deleted hourly (at least `1d`). |
| `server.metrics_port` | unset | Reserved; metrics are not implemented yet. A value is accepted but nothing listens on it (`serve` and `check-config` warn). |
| `auth.mode` | required for HTTP | `local` (users in the file) or `oidc` (e.g. Authentik). Ignored over stdio. |
| `auth.access_token_ttl` | `1h` | Access token lifetime; also how often an OIDC user is re-checked at the issuer. |
| `auth.refresh_token_ttl` | `30d` | Refresh token lifetime (each refresh rotates it). Must not exceed `session_max_age`. |
| `auth.session_max_age` | `30d` | Absolute lifetime of a sign-in; refreshing never extends it (at least `1d`). |
| `auth.local.users[]` | - | `username`, `password_hash` (argon2id from `ratatoskr hash-password`), `groups`. |
| `auth.oidc` | - | `issuer` (https), `client_id`, `client_secret`, `scopes` (default `openid email profile groups offline_access`), `groups_claim` (`groups`), `subject_claim` (`email`). |
| `roles.<group>` | `{}` | `{ <connection> or "*": read \| write }`. |
| `connections.<name>.kind` | required | `postgres`, `prometheus` or `loki`. Names: `^[a-z0-9][a-z0-9_-]{0,62}$`. |
| `connections.<name>.dsn` | required | PostgreSQL: `postgresql://user:password@host:port/db`, via `${VAR}` / `${file:...}`. |
| `connections.<name>.mode` | `read` | PostgreSQL: `write` enables `pg_execute` and write-level `pg_explain(analyze=true)`. |
| `connections.<name>.write_dsn` | unset | PostgreSQL, `mode: write` only: login for the write pool (`pg_execute`, write-level `pg_explain`). Unset: the write pool uses `dsn`. Recommended (see below). |
| `connections.<name>.description` | `""` | Every kind: shown to Claude in `list_connections`. |
| `connections.<name>.statement_timeout` | `30s` | PostgreSQL: server-side timeout of every statement. |
| `connections.<name>.pool` | `min_size: 1, max_size: 5, write_max_size: 2` | PostgreSQL: read pool; the write pool opens lazily. |
| `connections.<name>.allowed_schemas` | `[]` (all) | PostgreSQL: filters the discovery tools only (see below). |
| `connections.<name>.limits` | `max_rows: 500, max_response_bytes: 65536, max_query_length: 20000` | PostgreSQL: response and input limits. |
| `connections.<name>.tls` | unset | PostgreSQL: `mode` (`disable`, `require`, `verify-ca`, `verify-full` = default), `ca_file`, `cert_file` + `key_file`. Unset: the DSN's `sslmode`. |

TLS notes:

- `tls.mode: require` encrypts without verifying and **ignores `ca_file`** (libpq would treat `require` plus a CA
  file as `verify-ca`). Use `verify-ca` or `verify-full` to check the certificate.
- Python 3.13+ enables `VERIFY_X509_STRICT` by default, which rejects internal CA certificates without a
  `keyUsage` extension (libpq accepts them). Reissue the CA, or run on Python 3.12.

### Prometheus connections

```yaml
connections:
  metrics:
    kind: prometheus
    description: "Production metrics"
    url: https://prometheus.example.com
    auth: { type: bearer, token: ${PROM_TOKEN} }
```

| Key | Default | Meaning |
|---|---|---|
| `url` | required | API root (`http` or `https`); requests go to `<url>/api/v1/...`. For Mimir include its prefix (`https://mimir.example.com/prometheus`). No credentials, query string or fragment. Redirects are not followed. |
| `mode` | `read` | Always `read`: every Prometheus tool is a read, and `mode: write` is rejected. |
| `auth` | `{type: none}` | `none`, `basic` (`username`, `password`) or `bearer` (`token`); secrets via `${VAR}` / `${file:...}`, never empty. A token must be printable ASCII without spaces; a username or password must not contain line breaks, NUL or other control characters (a `${VAR}` with a trailing newline is refused at load time). |
| `headers` | `{}` | Extra request headers, e.g. `X-Scope-OrgID` for a Mimir/Cortex tenant. Values are treated as secrets and must be printable ASCII (spaces only between words; no line breaks, NUL or control characters, so a trailing newline from a secret is refused at load time). `Authorization`, `Proxy-Authorization`, `Host`, `Content-Length`, `Content-Type`, `Transfer-Encoding` and `Connection` are refused. |
| `timeout` | `30s` | Per request (1s to 10m); also sent to Prometheus as the query evaluation timeout. Each tool call has one deadline for all its requests, `timeout` + 5s (`prom_list_metrics` and `prom_alerts` send two, `connection_health` up to two). |
| `tls` | `verify: true` | `verify: false` turns verification off; `ca_file` (must exist, needs `verify: true`) trusts only that CA. Default trust: certifi, or `SSL_CERT_FILE` / `SSL_CERT_DIR`. No client certificates. |
| `limits.max_series` | `100` | Series (and alerts) shown per response (1 to 10000); only these series are parsed, the others are counted. |
| `limits.max_values` | `500` | Metric names and label values shown per response. |
| `limits.max_points` | `1000` | Points per series in `prom_query_range` (10 to 11000); a step that needs more is refused with the smallest step that fits. |
| `limits.max_range` | `31d` | Longest window for range queries and for name/value listings (at least `1m`). |
| `limits.max_query_length` | `20000` | Characters of PromQL or of a `match` selector. |
| `limits.max_response_bytes` | `65536` | Text returned to Claude (at least 1024). |
| `limits.max_body_bytes` | `8388608` | Bytes read from Prometheus per request (8 MiB; at least 65536); a larger answer is refused with a hint to narrow the query. Memory: while an answer is decoded the call holds about 10 times this (about 80 MiB at the default, for each call running at the same time); decoding the JSON briefly holds up the server (about 20 ms per MiB, so up to about 170 ms at the default). Lower it on small or busy hosts. |

Requests ask for an uncompressed answer (`Accept-Encoding: identity`) so `max_body_bytes` counts what is decoded. A
server that compresses anyway (`gzip`, `deflate`) is decoded step by step within the cap; other encodings are refused.

Outgoing HTTP (OIDC issuer, Prometheus, Loki) honours `HTTPS_PROXY` / `HTTP_PROXY`; put in-cluster hosts in
`NO_PROXY`.
`check-config` shows each Prometheus connection's auth type and number of extra headers, never the URL, token or
header values.

**Compatible servers.** Mimir/Cortex: `url: https://mimir.example.com/prometheus`, tenant in
`headers: {X-Scope-OrgID: ...}`. Thanos Query: `prom_alerts` needs the rules API (Ruler or sidecar); metadata may be
partial. VictoriaMetrics: metadata may be empty (names are still listed) and alerts/rule groups need
`-vmalert.proxyURL`; without them `prom_alerts` reports the rule groups as unavailable or fails.
`connection_health` uses `/api/v1/status/buildinfo` and falls back to a trivial query when the server answers 404
there.

### Loki connections

```yaml
connections:
  logs:
    kind: loki
    description: "Production logs"
    url: https://loki.example.com
    tenant: ${LOKI_TENANT}
    auth: { type: basic, username: ${LOKI_USER}, password: ${LOKI_PASSWORD} }
```

| Key | Default | Meaning |
|---|---|---|
| `url` | required | Loki root or its gateway (`http` or `https`); requests go to `<url>/loki/api/v1/...`. No credentials, query string or fragment. Redirects are not followed. |
| `mode` | `read` | Always `read`: every Loki tool is a read, and `mode: write` is rejected. |
| `tenant` | unset | Sent as `X-Scope-OrgID` on every request (multi-tenant Loki, Grafana Enterprise Logs); several tenants for a cross-tenant query: `a\|b` (the server must allow it). Letters, digits and `!-_.*'()`, at most 150 per tenant; the whole value is checked, so a trailing newline (a `${VAR}` from a secret) is refused at load time. `X-Scope-OrgID` under `headers` is refused, so the tenant has one source. The tenant is treated as a secret: it is masked as `<tenant>` in Loki's error texts and warnings. |
| `auth` | `{type: none}` | `none`, `basic` (`username`, `password`; Grafana Cloud: the user ID and an access token) or `bearer` (`token`); secrets via `${VAR}` / `${file:...}`, never empty; the same character rules as for Prometheus. |
| `headers` | `{}` | Extra request headers; values are treated as secrets and follow the same character rules as for Prometheus. The same headers as for Prometheus are refused, plus `X-Scope-OrgID`. |
| `timeout` | `30s` | 1s to 10m. Each tool call, `connection_health` included (it sends two requests), has one deadline for all its requests, `timeout` + 5s. Loki's own `query_timeout` still applies on the server. |
| `tls` | `verify: true` | As for Prometheus: `verify: false`, or `ca_file` to trust only that CA. No client certificates. |
| `limits.max_lines` | `500` | Highest `limit` a `loki_query` may ask for (1 to 5000, Loki's own default ceiling); the default `limit` is 100 (or `max_lines` if lower). A higher `limit` is refused. |
| `limits.max_line_bytes` | `2048` | Each log line is cut to this many bytes (64 to 65536) and marked `… [cut: N bytes]`. At most a quarter of `max_response_bytes` (16384 at the default), so several lines fit in one answer; a first line that still does not fit (a multi-line entry is indented under its timestamp, which makes it larger) is cut to the room left, so an answer always shows at least one line. |
| `limits.max_range` | `24h` | Longest window for `loki_query`, `loki_labels` and `loki_label_values` (at least `1m`); a longer one is refused before any request. |
| `limits.max_series` | `100` | Series shown for a metric query (1 to 10000). |
| `limits.max_points` | `1000` | Points per series in a metric query (10 to 11000); a `step` that needs more is refused with the smallest step that fits. |
| `limits.max_values` | `500` | Label names and values shown per response. |
| `limits.max_query_length` | `20000` | Characters of LogQL or of a `selector`. |
| `limits.max_response_bytes` | `65536` | Text returned to Claude (at least 1024). Below 8192, also lower `max_line_bytes` (at most a quarter of this). |
| `limits.max_body_bytes` | `8388608` | Bytes read from Loki per request (8 MiB; at least 65536); a larger answer is refused with a hint to lower `limit` or narrow the query. Memory and decoding cost as for Prometheus. |

`check-config` shows each Loki connection's auth type, whether a tenant is set and the number of extra headers, never
the URL, tenant, token or header values. Tested with Loki 3.7; `selector` on `loki_labels` and `loki_label_values`
needs a server that supports the `query` parameter of those endpoints (older ones may ignore it).
`connection_health` lists the labels of the last minute (that checks credentials and tenant) and then reads the version
from `/loki/api/v1/status/buildinfo` ("Loki API" when the server does not offer it).

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

## Security model

Effective access is `min(max(grants of your groups), connection.mode)`; no grant means no access. Over stdio you
act as a member of `server.stdio_role`; over HTTP your groups come from your local user entry or the OIDC
`groups` claim.

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

### Prometheus connections

- Read-only by design: Ratatoskr calls only the query, query_range, label values, metadata, alerts, rules and
  buildinfo endpoints, never the admin or write APIs, whatever flags the server runs with.
- **PromQL is not restricted.** Anyone with read access to the connection can run any query, including expensive
  ones. Ratatoskr limits the window (`max_range`), the points per series (`max_points`), sends the evaluation
  `timeout` to Prometheus and enforces its own deadline, caps what it reads (`max_body_bytes`) and what it returns.
  Keep Prometheus' own `--query.timeout`, `--query.max-samples` and `--query.max-concurrency` (or the Mimir/Thanos
  per-tenant limits) in place, and give each connection a credential or tenant that only sees what its users may see.
- Credentials (`auth`, header values) never appear in errors, logs or `check-config` output. A failed request is
  logged without a traceback: by exception class and message, with every configured credential and header value
  masked, and by class only when the HTTP library refused the request before sending it (its message quotes header
  values). Error texts, warnings and
  rule errors from the server are passed on with URLs, IP addresses (IPv4, IPv6 with or without brackets),
  `host:port` pairs (also single-label hosts such as `prometheus-0:10901`), names under `svc`, `cluster.local`,
  `internal`, `local`, `lan` or `corp`, and other names of three or more labels (`ingester-7.ingester.mimir`; a
  dotted name on its own in double quotes, such as a UTF-8 metric name, is kept) removed (best effort), and with
  secrets masked like any error text; each is cut to 1000 characters. At most 5 warnings and infos are shown per
  answer (the rest are counted). Query results are returned unchanged. Answers that are not the Prometheus API
  (401/403, 404, 429, redirects, 5xx, HTML login pages) get fixed wording; details go to the log. `serve` and `check-config` warn when
  `auth` credentials would go over plain `http` to a host other than loopback.
- At `log_level: INFO` httpx's request lines (which carry internal hosts and label matchers) are not logged.

### Loki connections

- Read-only by design: Ratatoskr calls only the query_range, labels, label values and buildinfo endpoints, never push,
  tail, delete, rules or admin endpoints.
- **LogQL is not restricted.** Anyone with read access to the connection can run any query over the tenant's logs.
  Ratatoskr refuses windows longer than `max_range` and limits above `max_lines` before sending anything, caps the
  points of metric queries, enforces its deadline, caps what it reads (`max_body_bytes`) and what it returns. Keep
  Loki's own per-tenant limits (`query_timeout`, `max_query_length`, `max_query_series`,
  `max_entries_limit_per_query`) in place, and give each connection a tenant and credential that only see what its
  users may see.
- Log lines are the user's data: they are cut to `max_line_bytes` but never masked, so a secret written into a log
  line is shown as it is. Every line break inside a log line (`\n`, `\r`, `\v`, `\f`, U+0085, U+2028, U+2029 and
  the other breaks Python's `str.splitlines` knows) becomes an indented continuation line, and label values show
  them escaped, so a log line cannot pose as a stream header or a timestamp of its own. When a server sends more
  lines than the requested `limit`, only the first `limit` are read and the answer says how many it sent. Loki's
  error texts (which can echo the query) and warnings go through the same address removal and secret masking as
  Prometheus messages, and the configured tenant IDs are shown as `<tenant>`; 401/403, 404, 429, redirects, 5xx and
  HTML pages get fixed wording, a multi-tenant server without a tenant gets a hint to set `tenant`, and HTTP 504 is
  reported as a timeout.
- `tenant`, credentials and header values never appear in errors, logs or `check-config` output (failed requests are
  logged as for Prometheus); `serve` and `check-config` warn when `auth` credentials would go over plain `http` to a
  host other than loopback.

### HTTP transport

- `serve` refuses `streamable-http` without an `auth` section, without a `secret_key` of at least 32 characters, or
  with a non-https `public_url` (except `--insecure-dev` on loopback). `check-config` runs the same checks.
- OAuth: dynamic client registration only for redirect URIs on `allowed_redirect_hosts`, for confidential
  (`client_secret_post`, `client_secret_basic`) and public (`none`) clients; authorization code with PKCE S256 only;
  the only scope is `mcp` (`scopes_supported`): whatever scope a client registers or requests (`claudeai`,
  `openid profile`, ...) is replaced by `mcp` rather than refused, at most 4 distinct names per request. The
  authorization server metadata comes from the MCP SDK, which lists only `client_secret_post` and
  `client_secret_basic` under `token_endpoint_auth_methods_supported`; public clients work anyway; codes are single use and live 5 minutes; tokens are opaque random values stored as SHA-256
  hashes and bound to `<public_url>/mcp`. Each refresh rotates the refresh token; presenting a used one revokes the
  whole session (`token_reuse_detected`), except a retry within 5 seconds, which is refused but keeps the session.
  So `/revoke` with the old refresh token within those 5 seconds does not end the session; use the current one.
- OIDC users are re-checked at the issuer on every refresh (at most `access_token_ttl` apart): group changes apply
  then, and a user the issuer refuses loses the session. Upstream refresh tokens are stored sealed (AES-GCM).
- Local users: argon2id hashes. All users must share one set of argon2 parameters (`hash-password` always
  produces the same), or the config is refused, so that response times do not reveal which names exist. Changing a
  user's `password_hash` or removing the user (and restarting) ends their sessions: access tokens stop working at
  once, and the next refresh revokes the session (`session_revoked`). The password is fingerprinted when the
  authorization code is exchanged, not when the form is submitted.
- Sign-in is limited to 5 attempts per minute per client IP **and** per user name, then locked for 1 minute,
  doubling up to 1 hour. The per-user limit means anyone who knows a user name can keep that user locked out; that
  is the price of stopping password guessing spread over many IPs. `/register` allows 20 registrations per hour
  and `/authorize` 60 requests per 10 minutes per IP; refused requests there are logged and audited as
  `rate_limited` (`error_class` `rate_limited:register` / `rate_limited:authorize`), at most once a minute per
  client address. Login pages use CSRF tokens, `SameSite=Strict` cookies and a
  CSP with `frame-ancestors 'none'`. Requests whose `Host` is not the `public_url` host are refused.
- Reverse proxy: set **HSTS** there (Ratatoskr does not). Put the proxy's address in `server.trusted_proxies`;
  otherwise every client appears to come from the proxy and shares one rate-limit bucket, so five wrong passwords
  lock everyone out. Do not expose `/healthz` and `/readyz` publicly. `/token`, `/revoke` and `/mcp` have no
  per-IP limit: absorb volumetric abuse at the proxy.
- Rotating `server.secret_key` is the emergency switch: every session ends, registered clients must register again
  and OIDC users sign in again.
- Health: `/healthz` (process is up) and `/readyz` (the state store accepts writes; databases are not checked).
- Sign-ins, refused sign-ins (`login_failed`: `denied`, or `error` with `upstream_unavailable` when the issuer
  could not be reached), rate-limit hits (`login_rate_limited`, `rate_limited`), token reuse, client revocations
  (`token_revoked`), sessions the server ended itself (`session_revoked`, `error_class` `user_removed` or
  `password_changed`) and failed upstream refreshes are audit events next to the tool calls, both in the log and in
  the `audit_events` table.
- On shutdown open `/mcp` event streams are ended cleanly (clients see the stream close and reconnect); there is no
  `ASGI callable returned without completing response.` error per open stream.

### Database roles

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
python -m pytest -m integration -q      # needs Docker: starts PostgreSQL, Prometheus and Loki with testcontainers
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
docker build -t ratatoskr:dev .         # container image (dependencies pinned by constraints.txt)
```

The HTTP tests (OAuth flows against the real Starlette app in process, fake OIDC issuer) are unit tests under
`tests/unit/secure_http/` and need no network.

See [`CLAUDE.md`](CLAUDE.md) for project conventions.

## License

MIT, see [`LICENSE`](LICENSE).
