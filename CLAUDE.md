# Ratatoskr: repo conventions

Multi-connection MCP server (`src/ratatoskr`, PyPI `ratatoskr-mcp`, CLI `ratatoskr`). Design:
`docs/superpowers/specs/2026-11-21-multi-backend-redesign-design.md`; shared interfaces for stage 1:
`docs/superpowers/plans/2026-11-21-phase1-interfaces.md` (read its notes sections at the end too).
Current state: stdio (Plan 1a) and secure streamable-HTTP (Plan 1b: OAuth AS, local + OIDC identity, SQLite state,
`Dockerfile`). Stage 2 adds Prometheus connections (`docs/superpowers/plans/2026-11-22-phase2-prometheus.md`),
stage 3 Loki connections (`docs/superpowers/plans/2026-11-22-phase3-loki.md`).
Stage 4 (`docs/superpowers/plans/2026-11-22-phase4-packaging.md`) adds `/metrics` on a separate listener,
`compose.yml` (Ratatoskr + Caddy), `compose.dev.yml` (sample PostgreSQL, Prometheus, Loki), CI and the docs set.

## Commands (Windows, repo root)

- Unit tests (no network, no Docker): `.venv/Scripts/python -m pytest -q`
- Integration tests (Docker Desktop running; testcontainers starts `postgres:17-alpine`,
  `prom/prometheus:v3.16.0` and `grafana/loki:3.7.10`):
  `.venv/Scripts/python -m pytest -m integration -q`
- Lint: `.venv/Scripts/python -m ruff check src tests`
- Types: `.venv/Scripts/python -m mypy src`
- Format check: `.venv/Scripts/python -m ruff format --check src tests`
- Validate a config: `.venv/Scripts/ratatoskr check-config --config config.yaml` (`--insecure-dev` validates what
  `serve --insecure-dev` accepts)
- Image: `docker build -t ratatoskr:dev .` (uid 10001, read-only root, writes only `/data`; local builds only)
- Dev tools at CI's versions: `.venv/Scripts/python -m pip install -c constraints.txt -c constraints-dev.txt -e ".[dev]"`
- Compose files: `docker compose -f compose.yml config --quiet` (needs `.env` and `config.yaml`; copy the
  examples) and `docker compose -f compose.dev.yml config --quiet`; dev stack: `docker compose -f compose.dev.yml up -d`
  (ports on 127.0.0.1 only), `... down -v` to remove it.
- Workflows (cannot run locally): `docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.12`; image scan:
  see `CONTRIBUTING.md` (Trivy).
- Installing packages: pip's extra index on this machine is broken and slow; always pass
  `--index-url https://pypi.org/simple`.

### Runtime constraints (`constraints.txt`)

The image installs `pip install -c constraints.txt .`: exact pins of the runtime dependency closure (no dev tools,
not the project) as last tested. After changing `dependencies` in `pyproject.toml` or upgrading packages in
`.venv`, run the full unit and integration suites, then regenerate the pins from the installed runtime closure
(walk `importlib.metadata` requirements from `ratatoskr-mcp`, skipping extras; equivalent to `pip freeze` filtered
to that closure), keep the `pywin32` line's `sys_platform == "win32"` marker, and rebuild the image. `mcp` is capped
at `<1.31` in `pyproject.toml`: an SDK upgrade must first re-verify the "SDK facts" in
`docs/superpowers/plans/2026-11-21-phase1b-secure-http.md` (handler and client-auth behaviour, scope handling,
metadata, sse-starlette shutdown) and the shims that rely on them (`transport/oauth_compat.py`,
`transport/stream_end.py`, `RegisteredClient` in `auth/oauth_server.py`). The base image is pinned by digest in
the `Dockerfile`; the comment there shows how to move it.

Plain `pytest` skips integration tests (`addopts = -m 'not integration'`); `-m integration` selects them.
Integration tests only ever use the local testcontainers PostgreSQL, Prometheus and Loki (the first run pulls the
Prometheus and Loki images from Docker Hub; the Loki test config turns its usage reports off); never connect to a
remote or production database, Prometheus or Loki.

## Layout (`src/ratatoskr/`)

- `config/` YAML loading (`loader.py`: `${VAR}`, `${file:/path}`), pydantic models (`models.py`), durations,
  `http_models.py` (auth/headers/TLS and the `HttpConnection` base of HTTP kinds), `prometheus_models.py`,
  `loki_models.py`, `shared.py`.
- `auth/` `Principal`, `Policy` (effective access), principal resolvers (`TokenPrincipalResolver` for HTTP);
  OAuth AS provider (`oauth_server.py`), crypto/keys from `server.secret_key`, CSRF, rate limiter, login pages and
  routes (`web.py`), `identity/` (local argon2id, OIDC RP), `password_cli.py` (`hash-password`).
- `state/` SQLite state store (`sqlite.py`, WAL, one connection + lock, `migrations.py`), audit sink, hourly
  cleanup. All OAuth/session state goes through the `Store` protocol; it stores hashes and sealed blobs only.
- `transport/` stdio composition root (`stdio.py`), HTTP composition root (`app.py`), preconditions (same checks
  for `serve` and `check-config`), client IP / trusted proxies, Host check, body and endpoint limits, client
  compatibility rewrites for `/revoke` and `/register` (`oauth_compat.py`), clean end of `/mcp` streams on shutdown
  (`stream_end.py`), uvicorn (`serve.py`).
- `backends/` `Backend` protocol, `BackendRegistry` (lazy open, 10 s retry), user-safe errors, `clamp_text`,
  `timeparse.py` (RFC3339 / unix / `now-15m`, ranges, steps), and what Prometheus and Loki share: `output.py`
  (`BlockWriter`, truncation notes, `with_notes`, `error_note`), `series.py` (results in the Prometheus format, label
  names), `summarize.py` (range summaries).
- `backends/postgres/` pools and execution (`backend.py`), guard pre-checks (`guard.py`), TLS (`tls.py`), catalog
  SQL (`introspection.py`), query/execute/explain (`querying.py`), tool registration (`tools.py`) and tool texts
  (`descriptions.py`).
- `backends/http/` shared by HTTP backends: `client.py` (lazy httpx client, per-request and per-call deadline, safe
  errors), `body.py` (capped body read, bounded gzip/deflate decoding), `options.py` (auth headers, TLS trust),
  `scrub.py` (addresses out of server messages), `envelope.py` (success envelope, notes, `scrub_server_text`, JSON
  decoding off the loop), `health.py` (`timed_health`, under the backend's per-call deadline), `failure.py` (what the
  log may say about a failed request).
- `backends/prometheus/` endpoints and error envelope (`api.py`), backend (`backend.py`), result parsing (`series.py`),
  text (`formatting.py`, `summarize.py`), tool logic (`querying.py`, `discovery.py`, `alerts.py`), registration
  (`tools.py`) and tool texts (`descriptions.py`).
- `backends/loki/` endpoints and error mapping (`api.py`), backend (`backend.py`, tenant header), log streams
  (`streams.py`, `formatting.py`), tool logic (`querying.py`, `discovery.py`), registration (`tools.py`) and tool
  texts (`descriptions.py`).
- `tools/runtime.py` the one wrapper every tool goes through; `tools/common.py` backend-independent tools.
- `observability/` audit events and sinks, JSON logging, secret redaction; metrics: `metrics.py` (series and
  bounded labels), `metrics_sink.py` (audit events -> metrics), `backend_probe.py` (`backend_up`, cached),
  `metrics_http.py` + `metrics_server.py` (the separate listener), `metrics_service.py` (composition).
- `app.py` builds the FastMCP app; `cli.py` is the entry point.
- Tests: `tests/fakes.py` (fake config, backends, clock, audit sink), `tests/unit/`, `tests/integration/`;
  `tests/unit/prom_helpers.py` / `tests/unit/loki_helpers.py` with the `prom_api` / `loki_api` (respx) and
  `prom_backend` / `loki_backend` fixtures in `tests/unit/conftest.py`.
  HTTP tests live in `tests/unit/secure_http/` (fixtures in its `conftest.py`); end-to-end OAuth flows run in process
  against the real Starlette app via `httpx.ASGITransport` in `tests/unit/secure_http/e2e/` (fake OIDC issuer via
  respx): they are unit tests, no network, no Docker.
- `config.example.yaml` is the annotated config reference; `tests/unit/test_example_config.py` keeps it valid.
- Packaging: `compose.yml`, `deploy/` (Caddyfile, compose config template), `compose.dev.yml`, `dev/` (seed SQL,
  Prometheus, Loki, log generator, dev configs), `.github/` (CI, release, Dependabot); static checks in
  `tests/unit/test_deploy_files.py`, `test_dev_stack_files.py`, `test_dockerfile.py`, `test_workflows.py`,
  `test_docs.py`, `test_repo_links.py`.

## Rules

- Tests first: write the failing test, then the code.
- Python 3.12+, `from __future__ import annotations`, full type hints; `ruff` (line length 120) and
  `mypy --strict` must stay clean. One responsibility per file; keep files small.
- Every tool call goes through `ToolRuntime.run` / `run_global`: identity, policy, deadline, clamping and audit
  live there and nowhere else. They return `ToolResult(text, is_error)`; every registered tool returns
  `result.to_call_tool_result()` (an MCP `CallToolResult`, so hosts see `isError=true` on failures). Error texts
  keep the `Error:` prefix.
- Successful tool output is the user's data: it is clamped but never redacted. Error text, logs and the audit
  `query_text` are redacted.
- Unknown and forbidden connections must produce the identical `ConnectionNotFoundError` message.
- No secrets in errors or logs. Text shown to the client may only come from `BackendError` subclasses, policy
  errors or PostgreSQL server messages; anything else becomes a generic message and the details go to the log.
  Never put a DSN, host or password in a message; `observability.redact` is a last line of defence for errors and
  logs, not the mechanism.
- Logs go to **stderr** as JSON (stdout is the MCP stdio channel). Do not move them to stdout. HTTP keeps them there
  too: uvicorn runs with `log_config=None` and `access_log=False` (request lines carry codes), and `aiosqlite` stays
  above DEBUG (it logs statement parameters). Counts whose names look like secrets (`tokens`) go in the message,
  not in `extra=` (the formatter masks such keys). A failed HTTP backend request is logged through
  `describe_failure` without `exc_info`: h11 quotes a refused header value in its error, so a traceback would log
  the tenant or token.
- Whole-value regex checks use `fullmatch` (or `\Z`), never `$`, which also matches before a final `"\n"` (a
  `${VAR}` from a secret); `tests/unit/test_regex_anchors.py` refuses `$` anywhere in `src/`. Header values, bearer
  tokens, basic credentials and the tenant are checked at config load, with messages that never echo the value.
- HTTP: OAuth, session and rate-limit state lives in the SQLite store (single replica); tokens are
  stored as SHA-256 hashes, client and upstream secrets sealed with keys derived from `server.secret_key`. Text shown
  in browser pages and OAuth errors is fixed wording; details go to the log. No private SDK attribute access.
- PostgreSQL read path: user SQL only through the read pool, inside `ReadSession` (READ ONLY transaction, always
  rolled back) and only via the extended protocol (`fetch`, `prepare`, cursors). Never pass user SQL to
  `connection.execute(sql)` without arguments: that is the simple protocol and accepts several statements.
  Session settings that must survive the pool's `RESET ALL` go in `server_settings`, not in `SET`. The pool's
  reset query also restores role/authorization and drops prepared statements, temp tables and sequence state;
  keep it that way. Catalog queries pin `search_path` to `pg_catalog`.
- The write pool is only for `mode: write` connections and only used by `pg_execute` and write-level
  `pg_explain(analyze=true)` (always rolled back). It logs in with `write_dsn` when set (else `dsn`); the read
  pool always uses `dsn`. Never use the write pool (or `write_dsn`) for a read-level call. `guard.py` is an early, readable check, not the security
  boundary: the DB role's GRANTs are.
- Prometheus: only the read endpoints in `backends/prometheus/api.py` (query, query_range, label values, metadata,
  alerts, rules, buildinfo); never admin or write APIs; `mode` is always `read`. Server messages (errors, warnings,
  rule errors) go through `PrometheusApi.scrub` (`scrub_upstream_text` + `redact`); successful output is not
  scrubbed. Never put the URL, a header value or a credential into a message. Prometheus tools pass `kind=` and
  `truncation_hint=` to `ToolRuntime.run`, and every call runs under one `PrometheusBackend.deadline()`.
- Loki: only the read endpoints in `backends/loki/api.py` (query_range, labels, label values, buildinfo); `mode` is
  always `read`. `tenant` is the only source of `X-Scope-OrgID` (refused under `headers`). Error texts and warnings go
  through `LokiApi.scrub` (which also masks the tenant IDs); log lines are user data: cut to `max_line_bytes`
  (marked, at most a quarter of `max_response_bytes`), never scrubbed or redacted, but every `str.splitlines` break
  in them is indented (and escaped in label values) so a line cannot forge a stream header.
  Window (`max_range`), `limit` (`max_lines`) and step (`max_points`) are checked before any request. Loki tools pass
  `kind=` and `truncation_hint=` and run under one `LokiBackend.deadline()`; stream parsing runs in
  `asyncio.to_thread` and builds at most `limit` lines.
- Server text can echo user input of any length: every pattern in `scrub.py` must stay linear (match only at the
  start of a run of its characters, possessive quantifiers) and keep its timing test in `test_http_scrub.py`.
  Decoding (`json.loads`) and result parsing of up to `max_body_bytes` run in `asyncio.to_thread` (parsing then
  really runs off the loop; the C JSON decoder holds the GIL, so `max_body_bytes` also bounds that stall); parse only the
  series that can be shown (`parse_result(..., max_series=)`). Server notes go through `with_notes` (bounded) and
  errors shown inside a successful answer through `error_note` (redacted, bounded).
- Time arguments are parsed only by `backends/timeparse.py` (errors are `InvalidRequestError`); HTTP backends talk to
  their servers only through `backends/http/client.py`.
- Minimum supported PostgreSQL is 12; catalog SQL must work there.
- Tool descriptions in `descriptions.py` / `tools/common.py` are product UX for the LLM: short, say what comes
  back, when to use the tool, the limits, and that `connection` comes from `list_connections`.
- Tests: unit tests must not touch the network or Docker (use `tests/fakes.py`). Anything that needs a real
  PostgreSQL goes in `tests/integration/` with `pytestmark = pytest.mark.integration`.
- Docs must describe what the code does now; do not document unimplemented config as working. Settings are
  documented once, in `docs/configuration.md` (`tests/unit/test_docs.py` checks every model field is there and
  that links resolve); the README links to it.
- Metrics: every count comes from the audit event (`MetricsAuditSink`); never call `Metrics` from tools. Labels
  are bounded: `connection` only through `Metrics.connection_label` (configured names, `_all`, `_unresolved`),
  never a subject, query, secret or a name a caller typed. `/metrics` never goes on the MCP port.
- GitHub: actions pinned by commit SHA with a `# vX.Y.Z` comment, `permissions: contents: read` at the top, only
  `GITHUB_TOKEN`. Repository links use the one slug in `tests/unit/test_repo_links.py`.
- Commits: imperative subject line; end the message with the agreed `Co-Authored-By` trailer.
