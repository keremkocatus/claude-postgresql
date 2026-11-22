# Security model

What Ratatoskr enforces, and what it leaves to the database roles, the reverse proxy and the servers behind each
connection. To report a vulnerability, see [`SECURITY.md`](../SECURITY.md).

## Access and PostgreSQL reads

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

## Prometheus connections

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

## Loki connections

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

## HTTP transport

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

## Database roles

The recipe for a restricted read role and a separate write role (`write_dsn`), with what each can and cannot do, is
in [PostgreSQL roles](postgres-roles.md).

## Metrics listener

`server.metrics_port` opens a second listener without authentication ([Metrics](configuration.md#metrics)). Its
labels never carry users, queries, secrets or connection names a caller typed, but anyone who reaches it learns the
configured connection names and how they are used: keep it on loopback or an internal network. Caddy in
`compose.yml` hides `/metrics`, `/healthz` and `/readyz` from the internet.
