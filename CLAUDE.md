# Ratatoskr: repo conventions

Multi-connection MCP server (`src/ratatoskr`, PyPI `ratatoskr-mcp`, CLI `ratatoskr`). Design:
`docs/superpowers/specs/2026-11-21-multi-backend-redesign-design.md`; shared interfaces for stage 1:
`docs/superpowers/plans/2026-11-21-phase1-interfaces.md` (read its notes sections at the end too).
Current state: stdio only (Plan 1a). HTTP transport, OAuth and the new Docker image are Plan 1b; `Dockerfile` and
`docker-compose.yml` are still the old ones until then.

## Commands (Windows, repo root)

- Unit tests (no network, no Docker): `.venv/Scripts/python -m pytest -q`
- Integration tests (Docker Desktop running; testcontainers starts `postgres:17`):
  `.venv/Scripts/python -m pytest -m integration -q`
- Lint: `.venv/Scripts/python -m ruff check src tests`
- Types: `.venv/Scripts/python -m mypy src`
- Validate a config: `.venv/Scripts/ratatoskr check-config --config config.yaml`
- Installing packages: pip's extra index on this machine is broken and slow; always pass
  `--index-url https://pypi.org/simple`.

Plain `pytest` skips integration tests (`addopts = -m 'not integration'`); `-m integration` selects them.
Integration tests only ever use the local testcontainers PostgreSQL; never connect to a remote or production
database.

## Layout (`src/ratatoskr/`)

- `config/` YAML loading (`loader.py`: `${VAR}`, `${file:/path}`), pydantic models (`models.py`), durations.
- `auth/` `Principal`, `Policy` (effective access), principal resolvers.
- `backends/` `Backend` protocol, `BackendRegistry` (lazy open, 10 s retry), user-safe errors, `clamp_text`.
- `backends/postgres/` pools and execution (`backend.py`), guard pre-checks (`guard.py`), TLS (`tls.py`), catalog
  SQL (`introspection.py`), query/execute/explain (`querying.py`), tool registration (`tools.py`) and tool texts
  (`descriptions.py`).
- `tools/runtime.py` the one wrapper every tool goes through; `tools/common.py` backend-independent tools.
- `observability/` audit events and sinks, JSON logging, secret redaction.
- `app.py` builds the FastMCP app; `cli.py` is the entry point.
- Tests: `tests/fakes.py` (fake config, backends, clock, audit sink), `tests/unit/`, `tests/integration/`.
- `config.example.yaml` is the annotated config reference; `tests/unit/test_example_config.py` keeps it valid.

## Rules

- Tests first: write the failing test, then the code.
- Python 3.12+, `from __future__ import annotations`, full type hints; `ruff` (line length 120) and
  `mypy --strict` must stay clean. One responsibility per file; keep files small.
- Every tool call goes through `ToolRuntime.run` / `run_global`: identity, policy, deadline, clamping and audit
  live there and nowhere else.
- Unknown and forbidden connections must produce the identical `ConnectionNotFoundError` message.
- No secrets in errors or logs. Text shown to the client may only come from `BackendError` subclasses, policy
  errors or PostgreSQL server messages; anything else becomes a generic message and the details go to the log.
  Never put a DSN, host or password in a message; `observability.redact` is a last line of defence, not the
  mechanism.
- Logs go to **stderr** as JSON (stdout is the MCP stdio channel). Do not move them to stdout.
- PostgreSQL read path: user SQL only through the read pool, inside `ReadSession` (READ ONLY transaction, always
  rolled back) and only via the extended protocol (`fetch`, `prepare`, cursors). Never pass user SQL to
  `connection.execute(sql)` without arguments: that is the simple protocol and accepts several statements.
  Session settings that must survive the pool's `RESET ALL` go in `server_settings`, not in `SET`. The pool's
  reset query also restores role/authorization and drops prepared statements, temp tables and sequence state;
  keep it that way. Catalog queries pin `search_path` to `pg_catalog`.
- The write pool is only for `mode: write` connections and only used by `pg_execute` and write-level
  `pg_explain(analyze=true)` (always rolled back). `guard.py` is an early, readable check, not the security
  boundary: the DB role's GRANTs are.
- Minimum supported PostgreSQL is 12; catalog SQL must work there.
- Tool descriptions in `descriptions.py` / `tools/common.py` are product UX for the LLM: short, say what comes
  back, when to use the tool, the limits, and that `connection` comes from `list_connections`.
- Tests: unit tests must not touch the network or Docker (use `tests/fakes.py`). Anything that needs a real
  PostgreSQL goes in `tests/integration/` with `pytestmark = pytest.mark.integration`.
- Docs must describe what the code does now; do not document unimplemented config as working.
- Commits: imperative subject line; end the message with the agreed `Co-Authored-By` trailer.
