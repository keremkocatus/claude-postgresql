# Configuration reference

Ratatoskr reads one YAML file: `--config <path>`, else `$RATATOSKR_CONFIG`, else `/config/config.yaml` (the
image sets `RATATOSKR_CONFIG=/config/config.yaml`). Validate it with `ratatoskr check-config` (add `--insecure-dev`
to validate what `serve --insecure-dev` accepts): it prints a summary without any secret and the same warnings
`serve` logs, and exits with code 2 on a config error.

- **Secrets** never go in the file: write `${ENV_VAR}` or `${file:/run/secrets/name}`, alone or inside a longer
  value (`https://${RATATOSKR_DOMAIN}`). A reference to an undefined variable or a missing file is an error, never
  an empty value.
- **Changes need a restart** (`docker compose restart ratatoskr`); there is no reload on SIGHUP. After the restart
  they apply at once to existing sessions too: roles, local users' groups, removed users and changed passwords are
  checked on every request with an access token (OIDC groups follow at the next refresh).
- Annotated examples: [`config.example.yaml`](../config.example.yaml) (stdio, with commented HTTP, Prometheus and
  Loki parts), [`deploy/config.example.yaml`](../deploy/config.example.yaml) (for `compose.yml`) and
  [`dev/ratatoskr/`](../dev/ratatoskr/) (the dev stack).

## Settings

One YAML file; [`config.example.yaml`](../config.example.yaml) is the annotated reference. Durations accept seconds or
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
| `server.metrics_port` | unset | Port of the separate Prometheus `/metrics` listener (1 to 65535; with HTTP it must differ from `server.port`). Unset: no listener. See [Metrics](#metrics). |
| `server.metrics_host` | `127.0.0.1` | Address of the metrics listener; must not be empty (that would mean every interface). It has no authentication: keep it on loopback, or use `0.0.0.0` in a container whose metrics port is reachable only on an internal network. |
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
| `connections.<name>.write_dsn` | unset | PostgreSQL, `mode: write` only: login for the write pool (`pg_execute`, write-level `pg_explain`). Unset: the write pool uses `dsn`. Recommended (see [PostgreSQL roles](postgres-roles.md)). |
| `connections.<name>.description` | `""` | Every kind: shown to Claude in `list_connections`. |
| `connections.<name>.statement_timeout` | `30s` | PostgreSQL: server-side timeout of every statement. |
| `connections.<name>.pool` | `min_size: 1, max_size: 5, write_max_size: 2` | PostgreSQL: read pool; the write pool opens lazily. |
| `connections.<name>.allowed_schemas` | `[]` (all) | PostgreSQL: filters the discovery tools only; not a security boundary (see [the security model](security-model.md)). |
| `connections.<name>.limits` | `max_rows: 500, max_response_bytes: 65536, max_query_length: 20000` | PostgreSQL: response and input limits. |
| `connections.<name>.tls` | unset | PostgreSQL: `mode` (`disable`, `require`, `verify-ca`, `verify-full` = default), `ca_file`, `cert_file` + `key_file`. Unset: the DSN's `sslmode`. |

TLS notes:

- `tls.mode: require` encrypts without verifying and **ignores `ca_file`** (libpq would treat `require` plus a CA
  file as `verify-ca`). Use `verify-ca` or `verify-full` to check the certificate.
- Python 3.13+ enables `VERIFY_X509_STRICT` by default, which rejects internal CA certificates without a
  `keyUsage` extension (libpq accepts them). Reissue the CA, or run on Python 3.12.

## Prometheus connections

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

## Loki connections

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

## Metrics

With `server.metrics_port` set, Ratatoskr serves Prometheus metrics at `http://<metrics_host>:<metrics_port>/metrics`
on a listener of its own, next to the MCP server, over stdio and over HTTP alike. The MCP port never serves
`/metrics`.

```yaml
server:
  metrics_host: 0.0.0.0   # in a container; the default 127.0.0.1 serves this machine only
  metrics_port: 9100
```

| Series | Type | Labels | Meaning |
|---|---|---|---|
| `ratatoskr_tool_calls_total` | counter | `tool`, `connection`, `result` | Tool calls; `result` is the audit result: `ok`, `denied`, `error` or `timeout`. |
| `ratatoskr_tool_duration_seconds` | histogram | `tool`, `connection` | Duration of each tool call (buckets from 10 ms to 120 s). |
| `ratatoskr_backend_up` | gauge | `connection` | 1 when the connection answered its health check, else 0. |
| `ratatoskr_auth_events_total` | counter | `event` | Authentication events (HTTP only): `login_succeeded`, `login_failed`, `login_rate_limited`, `rate_limited`, `token_reuse_detected`, `token_revoked`, `session_revoked`, `refresh_retry_within_grace`, `upstream_refresh_failed`; every one starts at 0. |

Also exported: `process_*` (memory, CPU, open files; Linux only) and `python_info`.

- **Label values are bounded.** `connection` is a configured connection name, `_all` for tools that are not bound
  to one connection (`list_connections`, `connection_health` without a name) or `_unresolved` for a call whose
  connection was unknown, forbidden for the caller or given without an identity. A name someone typed never becomes
  a label value, and forbidden connections are not revealed. No label carries a user, a query or a secret.
- **`ratatoskr_backend_up`** is checked when Prometheus scrapes, at most every 15 seconds (a faster scrape gets the
  cached values): every configured connection is opened if needed (the same lazy open and 10 s retry pause as tool
  calls) and asked for its health with a 5 s limit. The limit never cuts an open short: a connection still opening
  after 5 s (opening a PostgreSQL pool can take 10 s or more) reports 0 for that scrape and finishes opening in the
  background; if the open fails, the usual 10 s retry pause applies. So with metrics on, every connection is opened
  within one scrape of the start, even if no tool used it yet. A connection that keeps failing in the same way is
  logged as a warning once, then at debug level. These checks are not tool calls: they are not audited.
- **The PostgreSQL check uses a read-pool connection** (one `SELECT` in a read-only session), like a tool call. When
  every pool connection is busy (`pool.max_size` long-running queries), the check waits for one and may report 0
  after 5 s although the server is up.
- **At most 16 scrapes are answered at once**; a connection beyond that is closed without an answer.
- **No authentication.** Anyone who reaches the port can read the metrics (tool names, connection names, call
  counts). Keep `metrics_host` on loopback, or in a container on `0.0.0.0` without publishing the port: with
  `compose.yml`, a Prometheus on the same compose network scrapes `ratatoskr:9100`, and Caddy answers `/metrics`
  with 404 on the public side anyway.
- **Over stdio** every process binds the port. Claude Desktop and Claude Code start one process per client; two
  processes with the same config cannot both listen, and the second one exits with
  `cannot listen for metrics on <host>:<port>`. Give each stdio config its own port or leave metrics off there.
- A failed bind stops `serve` (exit code 1) before it serves anything.
- Not counted: arguments that fail a tool's schema are refused by the MCP layer before Ratatoskr runs (they are not
  audited either).

Scrape configuration:

```yaml
scrape_configs:
  - job_name: ratatoskr
    static_configs:
      - targets: ["ratatoskr:9100"]
```

## Running in a container

- The image runs as uid 10001 with a read-only root file system and writes only `/data` (the SQLite state). A new
  named volume on `/data` takes the image's ownership; a bind-mounted host directory must be owned by uid 10001
  (`sudo chown 10001:10001 /srv/ratatoskr-data`), otherwise `check-config` and `serve` stop with
  `server.state_path: ... is not writable by uid 10001`.
- Keep `server.host: 0.0.0.0` and `server.port: 8000`: the image's health check calls
  `http://127.0.0.1:8000/healthz`.
- `docker stop` sends SIGTERM: in-flight requests get a few seconds to finish and queued audit events are written
  before the process exits. Keep the stop grace period at **10 s or more** (`compose.yml` sets 15 s).
- **`server.trusted_proxies`** must hold the address the container sees the reverse proxy connect from; only from
  there is `X-Forwarded-For` honoured. `compose.yml` gives Caddy a fixed address (`RATATOSKR_PROXY_IP`, default
  `10.203.53.10` on the subnet `RATATOSKR_SUBNET`, default `10.203.53.0/24`) and
  `deploy/config.example.yaml` trusts exactly that address. Docker assigns the other containers' addresses only
  from `RATATOSKR_IP_RANGE` (default `10.203.53.128/25`), so none can take Caddy's: keep the range inside the subnet
  and `RATATOSKR_PROXY_IP` outside the range when you change them. With your own proxy on the Docker host and a
  published port, it is the bridge gateway, not `127.0.0.1`:
  `docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}'` (usually `172.17.0.1`). With a wrong
  value every client shares the proxy's rate-limit bucket.
- On a dual-stack host, clients that reach a published port over IPv6 may be forwarded by Docker's userland proxy
  (`docker-proxy`) and then appear (to Caddy, and so to Ratatoskr) with the Docker network's gateway address, all
  sharing one rate-limit bucket; whether this happens depends on the host's Docker and network setup.
- Caddy (`deploy/Caddyfile`) cuts request bodies off after 8 MB (`request_body { max_size 8MB }`, answered with 413).

## Environment variables

| Variable | Meaning |
|---|---|
| `RATATOSKR_CONFIG` | Config file path when `--config` is not given. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Outgoing HTTP (OIDC issuer, Prometheus, Loki) goes through the proxy; list in-cluster hosts in `NO_PROXY`. PostgreSQL connections do not use them. |
| anything referenced as `${NAME}` | Values for the config file. |
