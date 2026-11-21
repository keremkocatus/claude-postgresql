# Ratatoskr

Ratatoskr is an MCP server that gives Claude (claude.ai, Claude Desktop, Claude Code) controlled access to
**several PostgreSQL databases at once**, with per-group access levels and an audit trail. Prometheus and Loki
backends are planned.

> **Status: 1.0.0.dev0.** Runs locally over **stdio**, or remotely over **streamable HTTP** as a claude.ai custom
> connector: Ratatoskr is its own OAuth 2.1 authorization server, and people sign in with local users or through an
> OIDC provider such as Authentik. The Docker image is built from the [`Dockerfile`](Dockerfile).
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
- Remote use over streamable HTTP with OAuth 2.1 (dynamic client registration, PKCE, rotating refresh tokens with
  reuse detection, revocation), local argon2id users or OIDC (Authentik), rate-limited login pages, and a
  persistent audit trail in SQLite (`/data/state.db`, kept 90 days by default).
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
     trusted_proxies: [172.18.0.0/16]        # your reverse proxy's IP or network
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

   `docker ps` shows `(healthy)` once `/healthz` answers. `docker stop` sends SIGTERM: in-flight requests get a
   few seconds to finish and queued audit events are written before the process exits. Keep the stop grace period
   at **10 s or more** (Docker's default; do not lower it with `docker stop -t` or compose `stop_grace_period`),
   otherwise SIGKILL can cut off the audit flush.

5. Point the reverse proxy at port 8000. In claude.ai open *Settings → Connectors → Add custom connector* and enter
   `https://mcp.example.com/mcp`: claude.ai registers itself, sends you to Ratatoskr's sign-in page and connects.
   Claude Code uses the same URL: `claude mcp add --transport http ratatoskr https://mcp.example.com/mcp`.

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
| `auth.mode` | required for HTTP | `local` (users in the file) or `oidc` (e.g. Authentik). Ignored over stdio. |
| `auth.access_token_ttl` | `1h` | Access token lifetime; also how often an OIDC user is re-checked at the issuer. |
| `auth.refresh_token_ttl` | `30d` | Refresh token lifetime (each refresh rotates it). Must not exceed `session_max_age`. |
| `auth.session_max_age` | `30d` | Absolute lifetime of a sign-in; refreshing never extends it (at least `1d`). |
| `auth.local.users[]` | - | `username`, `password_hash` (argon2id from `ratatoskr hash-password`), `groups`. |
| `auth.oidc` | - | `issuer` (https), `client_id`, `client_secret`, `scopes` (default `openid email profile groups offline_access`), `groups_claim` (`groups`), `subject_claim` (`email`). |
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

### HTTP transport

- `serve` refuses `streamable-http` without an `auth` section, without a `secret_key` of at least 32 characters, or
  with a non-https `public_url` (except `--insecure-dev` on loopback). `check-config` runs the same checks.
- OAuth: dynamic client registration only for redirect URIs on `allowed_redirect_hosts`; authorization code with
  PKCE S256 only; codes are single use and live 5 minutes; tokens are opaque random values stored as SHA-256
  hashes and bound to `<public_url>/mcp`. Each refresh rotates the refresh token; presenting a used one revokes the
  whole session (`token_reuse_detected`), except a retry within 5 seconds, which is refused but keeps the session.
  So `/revoke` with the old refresh token within those 5 seconds does not end the session; use the current one.
- OIDC users are re-checked at the issuer on every refresh (at most `access_token_ttl` apart): group changes apply
  then, and a user the issuer refuses loses the session. Upstream refresh tokens are stored sealed (AES-GCM).
- Local users: argon2id hashes. All users must share one set of argon2 parameters (`hash-password` always
  produces the same), or the config is refused, so that response times do not reveal which names exist. Changing a
  user's `password_hash` or removing the user ends their sessions at the next refresh (the password is
  fingerprinted when the authorization code is exchanged, not when the form is submitted).
- Sign-in is limited to 5 attempts per minute per client IP **and** per user name, then locked for 1 minute,
  doubling up to 1 hour. The per-user limit means anyone who knows a user name can keep that user locked out; that
  is the price of stopping password guessing spread over many IPs. `/register` allows 20 registrations per hour
  and `/authorize` 60 requests per 10 minutes per IP. Login pages use CSRF tokens, `SameSite=Strict` cookies and a
  CSP with `frame-ancestors 'none'`. Requests whose `Host` is not the `public_url` host are refused.
- Reverse proxy: set **HSTS** there (Ratatoskr does not). Put the proxy's address in `server.trusted_proxies`;
  otherwise every client appears to come from the proxy and shares one rate-limit bucket, so five wrong passwords
  lock everyone out. Do not expose `/healthz` and `/readyz` publicly. `/token`, `/revoke` and `/mcp` have no
  per-IP limit: absorb volumetric abuse at the proxy.
- Rotating `server.secret_key` is the emergency switch: every session ends, registered clients must register again
  and OIDC users sign in again.
- Health: `/healthz` (process is up) and `/readyz` (the state store accepts writes; databases are not checked).
- Sign-ins, refused sign-ins, rate-limit hits, token reuse, revocations and failed upstream refreshes are audit
  events next to the tool calls, both in the log and in the `audit_events` table.

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
python -m pytest -m integration -q      # needs Docker: starts PostgreSQL with testcontainers
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src
docker build -t ratatoskr:dev .         # container image
```

The HTTP tests (OAuth flows against the real Starlette app in process, fake OIDC issuer) are unit tests under
`tests/unit/secure_http/` and need no network.

See [`CLAUDE.md`](CLAUDE.md) for project conventions.

## License

MIT, see [`LICENSE`](LICENSE).
