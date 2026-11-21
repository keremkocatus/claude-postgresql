# Phase 1a: Core + multi-PostgreSQL over stdio — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `ratatoskr serve --config config.yaml` runs over stdio with several PostgreSQL connections, policy-based
access, 11 tools (`list_connections`, `connection_health` and the 9 `pg_*` tools of spec §6.2), an audit event
per call written to the log, and `ratatoskr check-config`; the old `claude_postgresql` package is gone.

**Architecture:** One FastMCP app (`app.py`) whose tools all go through `ToolRuntime.run` (resolve principal →
`Policy.authorize` → `BackendRegistry.get` (lazy open) → deadline → clamp → audit). The PostgreSQL backend
keeps a read pool whose sessions start with `default_transaction_read_only=on` and `statement_timeout` as
startup parameters, sends user SQL only through the extended protocol inside `BEGIN READ ONLY … ROLLBACK`, and
opens a small lazy write pool only on `mode: write` connections for `pg_execute` and write-level
`pg_explain(analyze=true)` (always rolled back). Config is one YAML file with `${VAR}` / `${file:…}`
interpolation, validated by pydantic models.

**Tech Stack:** Python 3.12+, `mcp` 1.30 (FastMCP), asyncpg 0.32, pydantic 2, PyYAML 6, pytest +
pytest-asyncio (auto mode), testcontainers 4 (`postgres:17`), ruff, mypy strict.

**Spec:** `docs/superpowers/specs/2026-11-21-multi-backend-redesign-design.md` (stage 1, the 1a half).
**Shared contract:** `docs/superpowers/plans/2026-11-21-phase1-interfaces.md` — every name in it is used
verbatim here. Plan 1b (secure HTTP) builds on this plan; nothing from 1b is implemented here.

---

## Ground rules for every task

- Work from the repo root `c:\projects\claude-postgresql` in Git Bash. Branch: `design/multi-backend-redesign`.
- Read first: `docs/superpowers/plans/2026-11-21-phase1-interfaces.md`, spec §3, §4, §5.1, §6, §10.
  From Task 22 on, also the repo `CLAUDE.md` this plan creates.
- Commands:
  - unit tests: `.venv/Scripts/python -m pytest tests/unit -q`
  - integration tests (Docker Desktop must be running): `.venv/Scripts/python -m pytest -m integration -q`
  - lint: `.venv/Scripts/python -m ruff check <paths>`; types: `.venv/Scripts/python -m mypy src/ratatoskr`
- Until Task 23 the old `src/claude_postgresql` package and the old `tests/test_*.py` files still exist and are
  **not** ruff/mypy clean; that is expected. Lint only the paths given in each task. Do not edit old files
  before Task 23.
- The editable install already puts `src/` on `sys.path`, so `import ratatoskr` works as soon as
  `src/ratatoskr/__init__.py` exists. The `ratatoskr` console script appears after the reinstall in Task 18.
- Installing packages: always `.venv/Scripts/python -m pip install --index-url https://pypi.org/simple ...`
  (the machine's extra index is broken). No new third-party dependency is needed: `pyyaml` and
  `testcontainers` are already in `.venv`.
- Never connect to a remote or production database. Integration tests only use the local testcontainers
  PostgreSQL.
- Do not touch `Dockerfile`, `docker-compose.yml` or `docs/superpowers/**` (1b and stage 4 own them).
- Performance expectations: no per-call pool creation (pools live for the process); discovery tools use one
  READ ONLY transaction per call; `pg_query` reads at most `max_rows + 1` rows through a cursor instead of
  fetching everything; registry construction does no I/O.

## Contract notes (additions that stay compatible with the interfaces file)

These are deliberate, additive extensions. Plan 1b can rely on them.

1. `BackendRegistry.__init__(config, *, factory=default_factory, clock=time.monotonic)` — keyword-only test
   seams. Extra methods: `describe(name) -> ConnectionInfo` (no I/O, for `list_connections`) and
   `max_response_bytes(name | None) -> int` (per-connection clamp, default 65536).
2. `ToolRuntime` exposes `policy` and `registry` attributes and adds
   `run_global(*, tool, call: Callable[[Principal], Awaitable[ToolOutput]], timeout=None) -> str` for tools that
   are not bound to one connection (`list_connections`, `connection_health()` without argument). Connection
   tools use `run` exactly as specified.
3. `load_config(path, env=None, *, insecure_dev=False)` — the flag is passed to model validation as pydantic
   context `{"insecure_dev": bool}`. Interpretation of spec §4: `--insecure-dev` only relaxes the https
   requirement of `public_url`; `auth` and `secret_key` stay mandatory, and the flag is rejected unless
   `server.host` is `127.0.0.1`, `localhost` or `::1`.
4. `ConnectionNotFoundError(connection)` / `InsufficientAccessError(connection)` take the connection name; the
   messages are exactly the contract's.
5. New helper modules: `backends/errors.py` (`BackendError` hierarchy: the only exception messages that reach
   the client), `observability/redact.py`, `observability/logging.py` (JSON to stderr, DSN/password masking),
   and `observability/audit.build_event(...)` (4096-char truncation + SHA-256).
6. `build_app` creates the `BackendRegistry` itself (the runtime needs it when tools are registered); the
   FastMCP lifespan yields `AppState(registry, runtime)` and calls `registry.close_all()` on exit.
7. `server.stdio_role`, when set, must name a group under `roles` (validation error otherwise).
8. Heads-up for Plan 1b (verified in mcp 1.30): the low-level `Server.run` enters the FastMCP lifespan once per
   session, and `StreamableHTTPSessionManager` calls it for every HTTP session. Over stdio there is exactly one
   session, so closing the registry there is correct; for streamable-http, 1b must move `close_all()` to the
   process-level (Starlette) lifespan, otherwise the end of one HTTP session closes pools other sessions use.
9. Tool errors are returned as normal text content starting with `Error:` (the contract's `run(...) -> str`),
   not as MCP `isError` results.

## File structure

Created (`src/ratatoskr/`):

| File | Responsibility |
|---|---|
| `__init__.py` | Package marker, `__version__ = "1.0.0.dev0"` |
| `__main__.py` | `python -m ratatoskr` → `cli.main()` |
| `cli.py` | argparse: `serve [--config] [--insecure-dev]`, `check-config [--config]`; config path precedence |
| `app.py` | `build_app(...)`: FastMCP, instructions, lifespan, tool registration |
| `config/__init__.py` | Package marker |
| `config/durations.py` | `parse_duration("30s" / "5m" / "1h" / "30d" / number)` |
| `config/models.py` | Pydantic models, `Access`, `GrantLevel`, all cross-field validation of spec §4 |
| `config/loader.py` | YAML read, `${VAR}` / `${file:/path}` interpolation, `ConfigError` with secret-free messages |
| `auth/__init__.py` | Package marker |
| `auth/principal.py` | `Principal` dataclass |
| `auth/policy.py` | `Policy`, `ConnectionNotFoundError`, `InsufficientAccessError` |
| `auth/resolver.py` | `PrincipalResolver` protocol, `StdioPrincipalResolver` |
| `observability/__init__.py` | Package marker |
| `observability/redact.py` | Mask PostgreSQL URLs and `password=` pairs |
| `observability/logging.py` | `JsonFormatter`, `setup_logging` (stderr) |
| `observability/audit.py` | `AuditEvent`, `build_event`, `AuditSink`, `LogAuditSink`, `CompositeAuditSink` |
| `backends/__init__.py` | Package marker |
| `backends/base.py` | `Backend` protocol, `HealthResult`, `ConnectionInfo` |
| `backends/errors.py` | User-safe error hierarchy |
| `backends/limits.py` | `Truncated`, `clamp_text` |
| `backends/registry.py` | `BackendRegistry`: lazy open, 10 s retry back-off, close_all |
| `backends/postgres/__init__.py` | Package marker |
| `backends/postgres/formatting.py` | Cell formatting and Markdown tables (adapted from old `formatters.py`) |
| `backends/postgres/guard.py` | Early checks: empty/length, dangerous functions and transaction control for writes |
| `backends/postgres/tls.py` | `tls:` settings → asyncpg `ssl` argument |
| `backends/postgres/backend.py` | `PostgresBackend`: pools, `ReadSession`, read/execute/explain, error translation |
| `backends/postgres/introspection.py` | Catalog SQL (adapted from old `tools/schema.py`, `admin.py`, `database_info.py`) |
| `backends/postgres/querying.py` | `run_query`, `run_execute`, `run_explain` |
| `backends/postgres/descriptions.py` | LLM-facing tool and argument descriptions |
| `backends/postgres/tools.py` | `register_postgres_tools(mcp, runtime)` with annotations |
| `tools/__init__.py` | Package marker |
| `tools/runtime.py` | `ToolRuntime`, `ToolOutput` |
| `tools/common.py` | `register_common_tools`: `list_connections`, `connection_health` |

Created (tests and repo files):

| File | Responsibility |
|---|---|
| `tests/fakes.py` | `make_config`, `FakeBackend`, `FakeFactory`, `RecordingSink`, `FakeClock`, `LEAKY_MESSAGE` |
| `tests/unit/__init__.py`, `tests/integration/__init__.py` | Package markers (tests import `tests.fakes`) |
| `tests/unit/conftest.py` | Restores the `ratatoskr` logger after each test |
| `tests/unit/test_*.py` | One file per module (listed in the tasks) |
| `tests/integration/helpers.py` | Seed SQL, `make_pg_config`, `ToolHarness` (real stack behind an in-process FastMCP) |
| `tests/integration/conftest.py` | Session PostgreSQL container, `seeded`, `make_harness` fixtures |
| `tests/integration/test_pg_read_guard.py` | Spec §10 read-mode rejections, explain, timeout, session tricks |
| `tests/integration/test_pg_write.py` | Atomic `pg_execute`, write-level explain leaves data unchanged |
| `tests/integration/test_pg_discovery.py` | Catalog tools, health, unreachable connection |
| `config.example.yaml` | Replaces `.env.example` |
| `CLAUDE.md` | Repo conventions and commands |

Modified: `pyproject.toml` (rename, deps, tool config), `README.md` (stdio quick start).

Deleted: `src/claude_postgresql/**`, `tests/conftest.py`, `tests/test_auth.py`, `tests/test_config.py`,
`tests/test_formatters.py`, `tests/test_security.py`, `.env.example`, `railway.json`.

---

### Task 1: Project scaffolding and pyproject

**Files:**
- Modify: `pyproject.toml` (full replacement)
- Create: `src/ratatoskr/__init__.py`
- Create: `tests/unit/__init__.py`, `tests/integration/__init__.py` (empty)
- Create: `tests/unit/conftest.py`
- Test: `tests/unit/test_package.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_package.py`:

```python
import ratatoskr


def test_version() -> None:
    assert ratatoskr.__version__ == "1.0.0.dev0"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_package.py -q`
Expected: FAIL — collection error `ModuleNotFoundError: No module named 'ratatoskr'`

- [ ] **Step 3: Write the implementation**

Replace `pyproject.toml` completely. It renames the project, requires Python 3.12, drops `pydantic-settings` and `python-dotenv`, adds `pyyaml` and `testcontainers` (dev), registers the `integration` marker and excludes it by default, and teaches ruff/mypy about the src layout and the untyped `asyncpg`/`yaml` modules. First create the two empty package markers:

```bash
mkdir -p tests/integration
touch tests/unit/__init__.py tests/integration/__init__.py
```

Replace `pyproject.toml`:

```toml
[project]
name = "ratatoskr-mcp"
version = "1.0.0.dev0"
description = "Ratatoskr: a secure, multi-connection MCP server that lets Claude query PostgreSQL."
readme = "README.md"
license = { text = "MIT" }
requires-python = ">=3.12"
dependencies = [
    "mcp[cli]>=1.28.0,<2",
    "asyncpg>=0.30.0",
    "pydantic>=2.0",
    "pyyaml>=6.0",
]

[project.scripts]
ratatoskr = "ratatoskr.cli:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/ratatoskr"]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24.0",
    "ruff>=0.4.0",
    "mypy>=1.10",
    "testcontainers>=4.0",
]

[tool.ruff]
target-version = "py312"
line-length = 120
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E", "F", "W", "I", "N", "UP", "B", "SIM"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
asyncio_default_fixture_loop_scope = "function"
testpaths = ["tests"]
addopts = "-m 'not integration'"
markers = ["integration: needs Docker; starts a PostgreSQL container via testcontainers"]

[tool.mypy]
python_version = "3.12"
strict = true

[[tool.mypy.overrides]]
module = ["asyncpg", "asyncpg.*", "yaml"]
ignore_missing_imports = true
```

Create `src/ratatoskr/__init__.py`:

```python
"""Ratatoskr: a secure, multi-connection MCP server."""

__version__ = "1.0.0.dev0"
```

Create `tests/unit/conftest.py`:

```python
import logging
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _reset_ratatoskr_logger() -> Iterator[None]:
    """setup_logging() detaches the 'ratatoskr' logger from the root; undo that so caplog keeps working."""
    yield
    logger = logging.getLogger("ratatoskr")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    logger.propagate = True
    logger.setLevel(logging.NOTSET)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_package.py -q`
Expected: PASS — `1 passed`

Run: `.venv/Scripts/python -m pytest -q`
Expected: the old suite (`tests/test_*.py`) still passes (64 tests) plus `test_package.py`; the new pytest options must not break it.

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/ratatoskr/__init__.py tests/unit tests/integration
git commit -m "Scaffold the ratatoskr package and rename the project" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: Duration parsing

**Files:**
- Create: `src/ratatoskr/config/__init__.py`, `src/ratatoskr/config/durations.py`
- Test: `tests/unit/test_durations.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_durations.py`:

```python
from datetime import timedelta

import pytest

from ratatoskr.config.durations import parse_duration


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("30s", timedelta(seconds=30)),
        ("5m", timedelta(minutes=5)),
        ("1h", timedelta(hours=1)),
        ("30d", timedelta(days=30)),
        (" 1.5s ", timedelta(seconds=1.5)),
        (45, timedelta(seconds=45)),
        (0.25, timedelta(seconds=0.25)),
        (timedelta(minutes=2), timedelta(minutes=2)),
    ],
)
def test_parses_supported_forms(value: object, expected: timedelta) -> None:
    assert parse_duration(value) == expected  # type: ignore[arg-type]


@pytest.mark.parametrize("value", ["", "30", "5 minutes", "1w", "-5s", "s"])
def test_rejects_bad_strings(value: str) -> None:
    with pytest.raises(ValueError):
        parse_duration(value)


def test_rejects_bool_and_negative_numbers() -> None:
    with pytest.raises(ValueError):
        parse_duration(True)
    with pytest.raises(ValueError):
        parse_duration(-1)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_durations.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.config'`

- [ ] **Step 3: Write the implementation**

Create `src/ratatoskr/config/__init__.py`:

```python
"""Configuration: YAML loading, interpolation and validation."""
```

Create `src/ratatoskr/config/durations.py`:

```python
"""Parse human-friendly durations such as ``30s``, ``5m``, ``1h`` and ``30d``."""

from __future__ import annotations

import re
from datetime import timedelta

_DURATION_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd])\s*$")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: str | int | float | timedelta) -> timedelta:
    """Return *value* as a timedelta. Plain numbers are seconds; strings need a unit (s, m, h, d)."""
    if isinstance(value, timedelta):
        result = value
    elif isinstance(value, bool):
        raise ValueError("duration must be a number of seconds or a string like '30s', '5m', '1h', '30d'")
    elif isinstance(value, int | float):
        result = timedelta(seconds=value)
    elif isinstance(value, str):
        match = _DURATION_RE.match(value)
        if match is None:
            raise ValueError(f"invalid duration {value!r}: use a number with a unit, e.g. '30s', '5m', '1h', '30d'")
        result = timedelta(seconds=float(match.group(1)) * _UNIT_SECONDS[match.group(2)])
    else:
        raise ValueError(f"invalid duration type: {type(value).__name__}")
    if result < timedelta(0):
        raise ValueError("duration must not be negative")
    return result
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_durations.py -q`
Expected: PASS — `15 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/config tests/unit/test_durations.py
git commit -m "Add duration parsing for config values" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: Config models and validation rules

**Files:**
- Create: `src/ratatoskr/config/models.py`
- Test: `tests/unit/test_config_models.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_config_models.py`:

```python
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ratatoskr.config.models import Access, RatatoskrConfig


def _config(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"connections": {"main": {"kind": "postgres", "dsn": "postgresql://u:p@h/db"}}}
    data.update(overrides)
    return data


def _http(**server: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "transport": "streamable-http",
        "public_url": "https://mcp.example.com",
        "secret_key": "k" * 32,
    }
    base.update(server)
    auth = {"mode": "local", "local": {"users": [{"username": "kerem", "password_hash": "x"}]}}
    return _config(server=base, auth=auth)


def test_defaults() -> None:
    config = RatatoskrConfig.model_validate(_config())
    connection = config.connections["main"]
    assert config.server.transport == "stdio"
    assert connection.mode == "read"
    assert connection.statement_timeout == timedelta(seconds=30)
    assert connection.limits.max_rows == 500
    assert connection.limits.max_response_bytes == 65536
    assert connection.pool.write_max_size == 2
    assert connection.tls is None


def test_access_order() -> None:
    assert Access.NONE < Access.READ < Access.WRITE


def test_duration_strings_are_parsed() -> None:
    data = _config()
    data["connections"]["main"]["statement_timeout"] = "5m"
    config = RatatoskrConfig.model_validate(data)
    assert config.connections["main"].statement_timeout == timedelta(minutes=5)


@pytest.mark.parametrize("name", ["Prod", "-x", "has space", "a" * 64, "dot.name"])
def test_rejects_bad_connection_names(name: str) -> None:
    data = _config(connections={name: {"kind": "postgres", "dsn": "postgresql://h/db"}})
    with pytest.raises(ValidationError, match="invalid connection name"):
        RatatoskrConfig.model_validate(data)


@pytest.mark.parametrize("name", ["prod-pg", "staging_pg", "0db", "a" * 63])
def test_accepts_good_connection_names(name: str) -> None:
    RatatoskrConfig.model_validate(_config(connections={name: {"kind": "postgres", "dsn": "postgresql://h/db"}}))


def test_roles_must_reference_known_connections() -> None:
    with pytest.raises(ValidationError, match="roles.devops references unknown connection"):
        RatatoskrConfig.model_validate(_config(roles={"devops": {"main": "read", "ghost": "write"}}))


def test_roles_accept_wildcard() -> None:
    config = RatatoskrConfig.model_validate(_config(roles={"admins": {"*": "write"}}))
    assert config.roles == {"admins": {"*": "write"}}


def test_roles_reject_unknown_level() -> None:
    with pytest.raises(ValidationError):
        RatatoskrConfig.model_validate(_config(roles={"admins": {"*": "admin"}}))


def test_stdio_role_must_be_defined() -> None:
    with pytest.raises(ValidationError, match="stdio_role 'ops' is not defined"):
        RatatoskrConfig.model_validate(_config(server={"stdio_role": "ops"}))


def test_unknown_keys_are_rejected() -> None:
    data = _config()
    data["connections"]["main"]["passwrd"] = "typo"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RatatoskrConfig.model_validate(data)


def test_unknown_connection_kind_is_rejected() -> None:
    with pytest.raises(ValidationError, match="does not match any of the expected tags"):
        RatatoskrConfig.model_validate(_config(connections={"m": {"kind": "mysql", "dsn": "x"}}))


def test_pool_min_cannot_exceed_max() -> None:
    data = _config()
    data["connections"]["main"]["pool"] = {"min_size": 6, "max_size": 5}
    with pytest.raises(ValidationError, match="cannot exceed"):
        RatatoskrConfig.model_validate(data)


def test_tls_files_must_exist(tmp_path: Path) -> None:
    data = _config()
    data["connections"]["main"]["tls"] = {"mode": "verify-full", "ca_file": str(tmp_path / "missing.pem")}
    with pytest.raises(ValidationError, match="tls.ca_file does not exist"):
        RatatoskrConfig.model_validate(data)


def test_http_transport_valid_config() -> None:
    config = RatatoskrConfig.model_validate(_http())
    assert config.server.transport == "streamable-http"


def test_http_transport_requires_auth_secret_and_url() -> None:
    data = _config(server={"transport": "streamable-http"})
    with pytest.raises(ValidationError) as excinfo:
        RatatoskrConfig.model_validate(data)
    message = str(excinfo.value)
    assert "an auth section is required" in message
    assert "server.secret_key is required" in message
    assert "server.public_url is required" in message


def test_http_transport_requires_https() -> None:
    with pytest.raises(ValidationError, match="must use https"):
        RatatoskrConfig.model_validate(_http(public_url="http://mcp.example.com"))


def test_insecure_dev_allows_http_on_loopback() -> None:
    data = _http(public_url="http://localhost:8000", host="127.0.0.1")
    config = RatatoskrConfig.model_validate(data, context={"insecure_dev": True})
    assert str(config.server.public_url).startswith("http://localhost")


def test_insecure_dev_rejected_on_public_bind() -> None:
    data = _http(public_url="http://localhost:8000", host="0.0.0.0")
    with pytest.raises(ValidationError, match="only allowed when server.host is"):
        RatatoskrConfig.model_validate(data, context={"insecure_dev": True})


def test_local_auth_needs_users() -> None:
    data = _http()
    data["auth"] = {"mode": "local", "local": {"users": []}}
    with pytest.raises(ValidationError, match="at least one user"):
        RatatoskrConfig.model_validate(data)


def test_oidc_auth_needs_oidc_block() -> None:
    data = _http()
    data["auth"] = {"mode": "oidc"}
    with pytest.raises(ValidationError, match="needs auth.oidc"):
        RatatoskrConfig.model_validate(data)


def test_auth_ttls_accept_durations() -> None:
    data = _http()
    data["auth"]["access_token_ttl"] = "15m"
    config = RatatoskrConfig.model_validate(data)
    assert config.auth is not None
    assert config.auth.access_token_ttl == timedelta(minutes=15)


def test_log_level_is_normalised() -> None:
    config = RatatoskrConfig.model_validate(_config(server={"log_level": "debug"}))
    assert config.server.log_level == "DEBUG"
    with pytest.raises(ValidationError, match="log_level"):
        RatatoskrConfig.model_validate(_config(server={"log_level": "LOUD"}))
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_models.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.config.models'`

- [ ] **Step 3: Write the implementation**

Field names, types and defaults are the contract's. Validators cover spec §4: connection-name regex, roles only reference `*` or defined connections, `stdio_role` must exist, streamable-http needs `auth` + `secret_key` + https `public_url` (http only with the `insecure_dev` validation context, and that flag only on a loopback host), local auth needs users, oidc needs its block, durations via `parse_duration`. `ConnectionConfig` is a one-member discriminated union so stages 2/3 can add kinds.

Create `src/ratatoskr/config/models.py`:

```python
"""Pydantic models for the Ratatoskr YAML configuration (spec section 4)."""

from __future__ import annotations

import enum
import re
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)

from ratatoskr.config.durations import parse_duration

CONNECTION_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


class Access(enum.IntEnum):
    NONE = 0
    READ = 1
    WRITE = 2


GrantLevel = Literal["read", "write"]


def _duration(value: Any) -> timedelta:
    if isinstance(value, str | int | float | timedelta):
        return parse_duration(value)
    raise ValueError("duration must be a number of seconds or a string like '30s', '5m', '1h', '30d'")


class ServerSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    transport: Literal["stdio", "streamable-http"] = "stdio"
    public_url: AnyHttpUrl | None = None
    host: str = "127.0.0.1"
    port: int = 8000
    metrics_port: int | None = None
    state_path: Path = Path("/data/state.db")
    secret_key: SecretStr | None = None
    allowed_redirect_hosts: list[str] = ["claude.ai", "claude.com", "localhost", "127.0.0.1"]
    stdio_role: str | None = None
    log_level: str = "INFO"

    @field_validator("log_level")
    @classmethod
    def _check_log_level(cls, value: str) -> str:
        level = value.upper()
        if level not in _LOG_LEVELS:
            raise ValueError(f"log_level must be one of {sorted(_LOG_LEVELS)}")
        return level


class LocalUser(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password_hash: SecretStr
    groups: list[str] = []


class LocalAuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: list[LocalUser]


class OidcSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    issuer: AnyHttpUrl
    client_id: str
    client_secret: SecretStr
    scopes: list[str] = ["openid", "email", "profile", "groups", "offline_access"]
    groups_claim: str = "groups"
    subject_claim: str = "email"


class AuthSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["local", "oidc"]
    access_token_ttl: timedelta = timedelta(hours=1)
    refresh_token_ttl: timedelta = timedelta(days=30)
    local: LocalAuthSettings | None = None
    oidc: OidcSettings | None = None

    @field_validator("access_token_ttl", "refresh_token_ttl", mode="before")
    @classmethod
    def _parse_ttl(cls, value: Any) -> timedelta:
        return _duration(value)

    @model_validator(mode="after")
    def _check_mode(self) -> Self:
        if self.mode == "local" and (self.local is None or not self.local.users):
            raise ValueError("auth.mode 'local' needs at least one user under auth.local.users")
        if self.mode == "oidc" and self.oidc is None:
            raise ValueError("auth.mode 'oidc' needs auth.oidc with issuer, client_id and client_secret")
        return self


class PoolSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    min_size: int = Field(default=1, ge=0)
    max_size: int = Field(default=5, ge=1)
    write_max_size: int = Field(default=2, ge=1)

    @model_validator(mode="after")
    def _check_sizes(self) -> Self:
        if self.min_size > self.max_size:
            raise ValueError(f"pool.min_size ({self.min_size}) cannot exceed pool.max_size ({self.max_size})")
        return self


class PgTlsSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["disable", "require", "verify-ca", "verify-full"] = "verify-full"
    ca_file: Path | None = None
    cert_file: Path | None = None
    key_file: Path | None = None

    @model_validator(mode="after")
    def _check_files(self) -> Self:
        for label, path in (("ca_file", self.ca_file), ("cert_file", self.cert_file), ("key_file", self.key_file)):
            if path is not None and not path.is_file():
                raise ValueError(f"tls.{label} does not exist: {path}")
        if (self.cert_file is None) != (self.key_file is None):
            raise ValueError("tls.cert_file and tls.key_file must be set together")
        return self


class PgLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_rows: int = Field(default=500, ge=1)
    max_response_bytes: int = Field(default=65536, ge=1024)
    max_query_length: int = Field(default=20000, ge=1)


class PostgresConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["postgres"]
    description: str = ""
    mode: GrantLevel = "read"
    dsn: SecretStr
    pool: PoolSettings = PoolSettings()
    statement_timeout: timedelta = timedelta(seconds=30)
    allowed_schemas: list[str] = []
    tls: PgTlsSettings | None = None
    limits: PgLimits = PgLimits()

    @field_validator("statement_timeout", mode="before")
    @classmethod
    def _parse_timeout(cls, value: Any) -> timedelta:
        return _duration(value)

    @field_validator("statement_timeout")
    @classmethod
    def _check_timeout(cls, value: timedelta) -> timedelta:
        if value < timedelta(milliseconds=1):
            raise ValueError("statement_timeout must be greater than zero")
        return value


ConnectionConfig = Annotated[PostgresConnection, Field(discriminator="kind")]
# Stage 2/3 extend this union with PrometheusConnection / LokiConnection.


class RatatoskrConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    server: ServerSettings = ServerSettings()
    auth: AuthSettings | None = None
    roles: dict[str, dict[str, GrantLevel]] = {}
    connections: dict[str, ConnectionConfig]

    @model_validator(mode="after")
    def _check_connection_names(self) -> Self:
        bad = [name for name in self.connections if not CONNECTION_NAME_RE.match(name)]
        if bad:
            raise ValueError(
                f"invalid connection name(s) {bad}: use lowercase letters, digits, '_' or '-' "
                "(start with a letter or digit, at most 63 characters)"
            )
        return self

    @model_validator(mode="after")
    def _check_roles(self) -> Self:
        for role, grants in self.roles.items():
            unknown = sorted(name for name in grants if name != "*" and name not in self.connections)
            if unknown:
                raise ValueError(f"roles.{role} references unknown connection(s): {', '.join(unknown)}")
        stdio_role = self.server.stdio_role
        if stdio_role is not None and stdio_role not in self.roles:
            raise ValueError(f"server.stdio_role '{stdio_role}' is not defined under roles")
        return self

    @model_validator(mode="after")
    def _check_transport(self, info: ValidationInfo) -> Self:
        context = info.context if isinstance(info.context, dict) else {}
        insecure_dev = bool(context.get("insecure_dev", False))
        server = self.server
        if insecure_dev and server.host not in LOOPBACK_HOSTS:
            raise ValueError("--insecure-dev is only allowed when server.host is 127.0.0.1, localhost or ::1")
        if server.transport != "streamable-http":
            return self
        problems: list[str] = []
        if self.auth is None:
            problems.append("an auth section is required")
        if server.secret_key is None:
            problems.append("server.secret_key is required")
        if server.public_url is None:
            problems.append("server.public_url is required")
        elif server.public_url.scheme != "https" and not insecure_dev:
            problems.append("server.public_url must use https (plain http is allowed only with --insecure-dev)")
        if problems:
            raise ValueError("transport streamable-http: " + "; ".join(problems))
        return self
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_models.py -q`
Expected: PASS — `29 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/config/models.py tests/unit/test_config_models.py
git commit -m "Add config models with spec section 4 validation" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: Config loader with interpolation

**Files:**
- Create: `src/ratatoskr/config/loader.py`
- Test: `tests/unit/test_config_loader.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_config_loader.py`:

```python
from pathlib import Path

import pytest

from ratatoskr.config.loader import ConfigError, load_config

BASE = """
server:
  stdio_role: admins
roles:
  admins: {"*": write}
connections:
  main:
    kind: postgres
    mode: write
    dsn: ${MAIN_DSN}
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_env_interpolation(tmp_path: Path) -> None:
    config = load_config(_write(tmp_path, BASE), env={"MAIN_DSN": "postgresql://u:pw@db/app"})
    assert config.connections["main"].dsn.get_secret_value() == "postgresql://u:pw@db/app"


def test_interpolation_inside_a_longer_string(tmp_path: Path) -> None:
    text = BASE.replace("${MAIN_DSN}", "postgresql://app:${PG_PASSWORD}@db/app")
    config = load_config(_write(tmp_path, text), env={"PG_PASSWORD": "s3cret"})
    assert config.connections["main"].dsn.get_secret_value() == "postgresql://app:s3cret@db/app"


def test_file_interpolation_strips_trailing_newline(tmp_path: Path) -> None:
    secret = tmp_path / "dsn.txt"
    secret.write_text("postgresql://u:filepw@db/app\n", encoding="utf-8")
    text = BASE.replace("${MAIN_DSN}", "${file:" + secret.as_posix() + "}")
    config = load_config(_write(tmp_path, text), env={})
    assert config.connections["main"].dsn.get_secret_value() == "postgresql://u:filepw@db/app"


def test_undefined_variable_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="connections.main.dsn: environment variable 'MAIN_DSN' is not defined"):
        load_config(_write(tmp_path, BASE), env={})


def test_missing_secret_file_is_an_error(tmp_path: Path) -> None:
    text = BASE.replace("${MAIN_DSN}", "${file:" + (tmp_path / "nope").as_posix() + "}")
    with pytest.raises(ConfigError, match="cannot read secret file"):
        load_config(_write(tmp_path, text), env={})


def test_invalid_reference_syntax(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="invalid reference"):
        load_config(_write(tmp_path, BASE.replace("${MAIN_DSN}", "${not valid}")), env={})


def test_empty_variable_value_is_allowed(tmp_path: Path) -> None:
    text = BASE.replace("dsn: ${MAIN_DSN}", "dsn: postgresql://db/app\n    description: '${DESC}'")
    config = load_config(_write(tmp_path, text), env={"DESC": ""})
    assert config.connections["main"].description == ""


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_config(tmp_path / "absent.yaml", env={})


def test_invalid_yaml(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not valid YAML"):
        load_config(_write(tmp_path, "connections: [unclosed"), env={})


def test_top_level_must_be_mapping(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="mapping at the top level"):
        load_config(_write(tmp_path, "- a\n- b\n"), env={})


def test_validation_errors_are_readable_and_hide_secrets(tmp_path: Path) -> None:
    text = BASE.replace("mode: write", "mode: admin")
    with pytest.raises(ConfigError) as excinfo:
        load_config(_write(tmp_path, text), env={"MAIN_DSN": "postgresql://u:topsecret@db/app"})
    message = str(excinfo.value)
    assert "connections.main.mode" in message
    assert "topsecret" not in message


def test_unknown_role_connection_is_reported(tmp_path: Path) -> None:
    text = BASE.replace('admins: {"*": write}', "admins: {ghost: read}")
    with pytest.raises(ConfigError, match="roles.admins references unknown connection"):
        load_config(_write(tmp_path, text), env={"MAIN_DSN": "postgresql://db/app"})


def test_insecure_dev_is_passed_to_validation(tmp_path: Path) -> None:
    text = BASE.replace("server:\n", "server:\n  host: 0.0.0.0\n")
    with pytest.raises(ConfigError, match="--insecure-dev is only allowed"):
        load_config(_write(tmp_path, text), env={"MAIN_DSN": "postgresql://db/app"}, insecure_dev=True)


def test_uses_os_environ_by_default(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://env@db/app")
    config = load_config(_write(tmp_path, BASE))
    assert config.connections["main"].dsn.get_secret_value() == "postgresql://env@db/app"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_loader.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.config.loader'`

- [ ] **Step 3: Write the implementation**

Interpolation runs on the parsed YAML tree (strings only), so a secret can never change the YAML structure. Validation errors are rebuilt from `loc` + `msg` with `include_input=False`, so secret values never appear in a `ConfigError`. `from None` drops the pydantic exception (which would carry input values) from the chain.

Create `src/ratatoskr/config/loader.py`:

```python
"""Load the YAML config file, resolve ``${VAR}`` / ``${file:/path}`` references and validate it."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from ratatoskr.config.models import RatatoskrConfig

_REFERENCE_RE = re.compile(r"\$\{([^}]*)\}")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KIND_TAGS = frozenset({"postgres"})


class ConfigError(Exception):
    """The configuration file is missing, malformed or invalid. The message never contains secret values."""


def load_config(path: Path, env: Mapping[str, str] | None = None, *, insecure_dev: bool = False) -> RatatoskrConfig:
    """Read *path*, interpolate references from *env* (default ``os.environ``) and validate the result."""
    environment = os.environ if env is None else env
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror or exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"config file {path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config file {path} must contain a mapping at the top level")
    resolved = _interpolate(raw, environment, "")
    try:
        return RatatoskrConfig.model_validate(resolved, context={"insecure_dev": insecure_dev})
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(path, exc)) from None


def _interpolate(value: Any, env: Mapping[str, str], where: str) -> Any:
    if isinstance(value, dict):
        return {key: _interpolate(item, env, f"{where}.{key}" if where else str(key)) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate(item, env, f"{where}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, str):
        return _REFERENCE_RE.sub(lambda match: _resolve(match.group(1).strip(), env, where), value)
    return value


def _resolve(reference: str, env: Mapping[str, str], where: str) -> str:
    if reference.startswith("file:"):
        file_path = Path(reference[len("file:") :])
        try:
            return file_path.read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise ConfigError(f"{where}: cannot read secret file {file_path}: {exc.strerror or exc}") from None
    if not _ENV_NAME_RE.match(reference):
        raise ConfigError(f"{where}: invalid reference '${{{reference}}}'; use ${{VAR_NAME}} or ${{file:/path}}")
    if reference not in env:
        raise ConfigError(f"{where}: environment variable '{reference}' is not defined")
    return env[reference]


def _format_validation_error(path: Path, exc: ValidationError) -> str:
    lines = [f"config file {path} is invalid:"]
    for error in exc.errors(include_input=False, include_url=False):
        location = [str(part) for part in error["loc"]]
        if len(location) >= 3 and location[0] == "connections" and location[2] in _KIND_TAGS:
            del location[2]
        message = str(error["msg"]).removeprefix("Value error, ")
        lines.append(f"  - {'.'.join(location) or '<root>'}: {message}")
    return "\n".join(lines)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_loader.py -q`
Expected: PASS — `14 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/config/loader.py tests/unit/test_config_loader.py
git commit -m "Load YAML config with env and file interpolation" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5: Observability: redaction, JSON logging, audit

**Files:**
- Create: `src/ratatoskr/observability/__init__.py`, `redact.py`, `logging.py`, `audit.py`
- Test: `tests/unit/test_redact_and_logging.py`, `tests/unit/test_audit.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_redact_and_logging.py`:

```python
import io
import json
import logging

from ratatoskr.observability.logging import JsonFormatter, setup_logging
from ratatoskr.observability.redact import redact


def test_redacts_urls() -> None:
    text = "failed: postgresql://admin:hunter2@db.internal:5432/app?sslmode=require and postgres://x@y/z"
    result = redact(text)
    assert "hunter2" not in result
    assert "db.internal" not in result
    assert result == "failed: postgresql://*** and postgres://***"


def test_redacts_key_value_passwords() -> None:
    assert redact("host=db password=hunter2 user=app") == "host=db password=*** user=app"
    assert redact("PASSWORD = 'a b c'") == "PASSWORD=***"


def test_leaves_plain_text_alone() -> None:
    assert redact('relation "users" does not exist') == 'relation "users" does not exist'


def test_json_formatter_includes_extra_and_masks() -> None:
    record = logging.LogRecord("ratatoskr.x", logging.INFO, __file__, 1, "dsn %s", ("postgresql://u:p@h/d",), None)
    record.__dict__["connection"] = "main"
    record.__dict__["query_text"] = "SELECT dblink('postgresql://u:pw@h/d', 'x')"
    entry = json.loads(JsonFormatter().format(record))
    assert entry["level"] == "INFO"
    assert entry["logger"] == "ratatoskr.x"
    assert entry["msg"] == "dsn postgresql://***"
    assert entry["connection"] == "main"
    assert "pw@" not in entry["query_text"]
    assert "ts" in entry


def test_setup_logging_writes_json_to_stream() -> None:
    stream = io.StringIO()
    setup_logging("INFO", stream=stream)
    logging.getLogger("ratatoskr.test").info("hello", extra={"tool": "pg_query"})
    entry = json.loads(stream.getvalue().strip().splitlines()[-1])
    assert entry["msg"] == "hello"
    assert entry["tool"] == "pg_query"
```

Create `tests/unit/test_audit.py`:

```python
import hashlib
import logging
from datetime import UTC, datetime

import pytest

from ratatoskr.observability.audit import (
    MAX_AUDIT_QUERY_CHARS,
    AuditEvent,
    CompositeAuditSink,
    LogAuditSink,
    build_event,
)


def _event(**overrides: object) -> AuditEvent:
    values: dict[str, object] = {
        "subject": "stdio",
        "auth_source": "stdio",
        "connection": "main",
        "tool": "pg_query",
        "query_text": "SELECT 1",
        "duration_ms": 1.234,
        "rows": 1,
        "result": "ok",
        "error_class": None,
    }
    values.update(overrides)
    return build_event(**values)  # type: ignore[arg-type]


def test_build_event_hashes_full_text_and_truncates() -> None:
    long_query = "SELECT " + "x" * 10000
    event = _event(query_text=long_query)
    assert event.query_text is not None
    assert len(event.query_text) == MAX_AUDIT_QUERY_CHARS
    assert event.query_sha256 == hashlib.sha256(long_query.encode()).hexdigest()
    assert event.duration_ms == 1.23
    assert event.ts.tzinfo is UTC


def test_build_event_without_query() -> None:
    event = _event(query_text=None)
    assert event.query_text is None
    assert event.query_sha256 is None


def test_build_event_uses_given_timestamp() -> None:
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    assert _event(ts=ts).ts == ts


def test_log_sink_writes_audit_record(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO, logger="ratatoskr.audit"):
        LogAuditSink().record(_event())
    record = caplog.records[-1]
    assert record.name == "ratatoskr.audit"
    assert record.__dict__["event"] == "audit"
    assert record.__dict__["tool"] == "pg_query"
    assert record.__dict__["result"] == "ok"
    assert record.__dict__["connection"] == "main"


class _Recorder:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class _Exploding:
    def record(self, event: AuditEvent) -> None:
        raise RuntimeError("boom")


def test_composite_sink_isolates_failures() -> None:
    recorder = _Recorder()
    CompositeAuditSink([_Exploding(), recorder]).record(_event())
    assert len(recorder.events) == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_redact_and_logging.py tests/unit/test_audit.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.observability'`

- [ ] **Step 3: Write the implementation**

Logs go to stderr because stdout carries the stdio MCP protocol. `LogAuditSink` writes the event fields as `extra=` (the audit timestamp is `audit_ts` so it does not collide with the log line's `ts`). Sinks swallow their own exceptions: an audit failure must never fail a tool call.

Create `src/ratatoskr/observability/__init__.py`:

```python
"""Audit trail and logging."""
```

Create `src/ratatoskr/observability/redact.py`:

```python
"""Mask connection strings and passwords before text leaves the process (tool output, logs)."""

from __future__ import annotations

import re

_URL_RE = re.compile(r"\b(postgres(?:ql)?)://[^\s'\"<>]+", re.IGNORECASE)
_KEYVALUE_RE = re.compile(r"\b(password|passwd|pwd)\s*=\s*('[^']*'|\"[^\"]*\"|[^\s,;]+)", re.IGNORECASE)


def redact(text: str) -> str:
    """Replace PostgreSQL URLs and ``password=...`` pairs with ``***``."""
    text = _URL_RE.sub(lambda match: f"{match.group(1)}://***", text)
    return _KEYVALUE_RE.sub(lambda match: f"{match.group(1)}=***", text)
```

Create `src/ratatoskr/observability/logging.py`:

```python
"""JSON logging to stderr (stdout belongs to the stdio MCP transport)."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any, TextIO

from ratatoskr.observability.redact import redact

_STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """One JSON object per line: ts, level, logger, msg plus any ``extra=`` fields, with secrets masked."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": redact(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                entry[key] = redact(value) if isinstance(value, str) else value
        if record.exc_info and record.exc_info[0] is not None:
            entry["exc"] = redact(self.formatException(record.exc_info))
        return json.dumps(entry, ensure_ascii=False, default=str)


def setup_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    """Send the ``ratatoskr`` logger tree to *stream* (default stderr) as JSON."""
    logger = logging.getLogger("ratatoskr")
    logger.setLevel(level.upper())
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
```

Create `src/ratatoskr/observability/audit.py`:

```python
"""Audit events: one per tool call. Sinks never block and never raise."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

AuditResult = Literal["ok", "denied", "error", "timeout"]

MAX_AUDIT_QUERY_CHARS = 4096

_logger = logging.getLogger("ratatoskr.audit")
_internal_logger = logging.getLogger("ratatoskr.observability")


@dataclass(frozen=True)
class AuditEvent:
    ts: datetime
    subject: str
    auth_source: str
    connection: str | None
    tool: str
    query_text: str | None
    query_sha256: str | None
    duration_ms: float
    rows: int | None
    result: AuditResult
    error_class: str | None


def build_event(
    *,
    subject: str,
    auth_source: str,
    connection: str | None,
    tool: str,
    query_text: str | None,
    duration_ms: float,
    rows: int | None,
    result: AuditResult,
    error_class: str | None,
    ts: datetime | None = None,
) -> AuditEvent:
    """Create an event, hashing the full query text and keeping at most 4096 characters of it."""
    return AuditEvent(
        ts=ts or datetime.now(UTC),
        subject=subject,
        auth_source=auth_source,
        connection=connection,
        tool=tool,
        query_text=None if query_text is None else query_text[:MAX_AUDIT_QUERY_CHARS],
        query_sha256=None if query_text is None else hashlib.sha256(query_text.encode("utf-8")).hexdigest(),
        duration_ms=round(duration_ms, 2),
        rows=rows,
        result=result,
        error_class=error_class,
    )


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None:
        """Accept an event without blocking and without raising."""
        ...


class LogAuditSink:
    """Writes each event to the ``ratatoskr.audit`` logger with ``event="audit"``."""

    def record(self, event: AuditEvent) -> None:
        try:
            _logger.info(
                "audit",
                extra={
                    "event": "audit",
                    "audit_ts": event.ts.isoformat(),
                    "subject": event.subject,
                    "auth_source": event.auth_source,
                    "connection": event.connection,
                    "tool": event.tool,
                    "query_text": event.query_text,
                    "query_sha256": event.query_sha256,
                    "duration_ms": event.duration_ms,
                    "rows": event.rows,
                    "result": event.result,
                    "error_class": event.error_class,
                },
            )
        except Exception:  # an audit sink must never break a tool call
            _internal_logger.debug("LogAuditSink failed", exc_info=True)


class CompositeAuditSink:
    """Fans an event out to several sinks; one failing sink does not affect the others."""

    def __init__(self, sinks: Sequence[AuditSink]) -> None:
        self._sinks = tuple(sinks)

    def record(self, event: AuditEvent) -> None:
        for sink in self._sinks:
            try:
                sink.record(event)
            except Exception:  # an audit sink must never break a tool call
                _internal_logger.debug("audit sink %r failed", sink, exc_info=True)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_redact_and_logging.py tests/unit/test_audit.py -q`
Expected: PASS — `10 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/observability tests/unit/test_redact_and_logging.py tests/unit/test_audit.py
git commit -m "Add audit events, JSON logging and secret redaction" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 6: Backend protocol, user-safe errors, response clamping, test fakes

**Files:**
- Create: `src/ratatoskr/backends/__init__.py`, `base.py`, `errors.py`, `limits.py`
- Create: `tests/fakes.py`
- Test: `tests/unit/test_limits.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_limits.py`:

```python
from ratatoskr.backends.limits import clamp_text


def test_short_text_is_untouched() -> None:
    result = clamp_text("hello", 100, "hint")
    assert result.text == "hello"
    assert result.truncated is False


def test_long_text_is_cut_with_note_within_budget() -> None:
    result = clamp_text("x" * 5000, 1024, "Add a LIMIT.")
    assert result.truncated is True
    assert len(result.text.encode("utf-8")) <= 1024
    assert result.text.endswith("[Response truncated: it exceeded 1024 bytes. Add a LIMIT.]")


def test_cut_respects_utf8_boundaries() -> None:
    result = clamp_text("ğ" * 2000, 1024, "hint")
    result.text.encode("utf-8")  # must not raise
    assert result.truncated is True
    assert len(result.text.encode("utf-8")) <= 1024
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_limits.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.backends'`

- [ ] **Step 3: Write the implementation**

`tests/fakes.py` is used by most later unit tests: `make_config` builds a valid `RatatoskrConfig` (every DSN contains a fake password and host so leak tests can look for them), `FakeBackend` / `FakeFactory` replace PostgreSQL in registry and runtime tests, `RecordingSink` captures audit events.

Create `src/ratatoskr/backends/__init__.py`:

```python
"""Backend protocol, registry and implementations."""
```

Create `src/ratatoskr/backends/base.py`:

```python
"""The protocol every backend kind (postgres, later prometheus and loki) implements."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Protocol

from ratatoskr.config.models import GrantLevel


@dataclass(frozen=True)
class HealthResult:
    ok: bool
    latency_ms: float | None
    version: str | None
    error: str | None


@dataclass(frozen=True)
class ConnectionInfo:
    name: str
    kind: str
    description: str
    mode: GrantLevel


class Backend(Protocol):
    kind: ClassVar[str]
    name: str

    async def open(self) -> None: ...

    async def close(self) -> None: ...

    async def health(self) -> HealthResult: ...

    def describe(self) -> ConnectionInfo: ...
```

Create `src/ratatoskr/backends/errors.py`:

```python
"""Errors whose message is safe to show to the MCP client (no DSN, host or password)."""

from __future__ import annotations


class BackendError(Exception):
    """Base class: ``str(error)`` is shown to the user as-is."""


class InvalidRequestError(BackendError):
    """The tool arguments were rejected before reaching the backend."""


class BackendQueryError(BackendError):
    """The backend rejected the request (e.g. a PostgreSQL error)."""


class BackendTimeoutError(BackendError):
    """The backend or the client-side deadline cancelled the request."""


class BackendUnavailableError(BackendError):
    """The backend could not be opened; the registry retries at most every 10 seconds."""
```

Create `src/ratatoskr/backends/limits.py`:

```python
"""Clamp tool responses to a byte budget and say so explicitly."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Truncated:
    text: str
    truncated: bool


def clamp_text(text: str, max_bytes: int, hint: str) -> Truncated:
    """Return *text* unchanged if it fits in *max_bytes* (UTF-8), else cut it and append a truncation note."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return Truncated(text=text, truncated=False)
    note = f"\n\n[Response truncated: it exceeded {max_bytes} bytes. {hint}]"
    budget = max(0, max_bytes - len(note.encode("utf-8")))
    head = encoded[:budget].decode("utf-8", errors="ignore")
    return Truncated(text=head + note, truncated=True)
```

Create `tests/fakes.py`:

```python
"""Test doubles shared by unit tests. No network, no database."""

from __future__ import annotations

from typing import Any, ClassVar

from ratatoskr.backends.base import ConnectionInfo, HealthResult
from ratatoskr.config.models import ConnectionConfig, RatatoskrConfig
from ratatoskr.observability.audit import AuditEvent

LEAKY_MESSAGE = "could not connect to postgresql://admin:hunter2@db.internal:5432/app (host db.internal)"


def make_config(
    connections: dict[str, dict[str, Any]] | None = None,
    roles: dict[str, dict[str, str]] | None = None,
    **server: Any,
) -> RatatoskrConfig:
    """A valid config; connections default to one read-mode 'main' connection."""
    if connections is None:
        connections = {"main": {"mode": "read"}}
    data: dict[str, Any] = {
        "server": server,
        "roles": roles or {},
        "connections": {
            name: {"kind": "postgres", "dsn": f"postgresql://u:secret@db.internal/{name}", **values}
            for name, values in connections.items()
        },
    }
    return RatatoskrConfig.model_validate(data)


class FakeBackend:
    kind: ClassVar[str] = "postgres"

    def __init__(self, name: str, config: ConnectionConfig) -> None:
        self.name = name
        self.config = config
        self.open_calls = 0
        self.close_calls = 0
        self.fail_open: Exception | None = None
        self.health_result = HealthResult(ok=True, latency_ms=1.5, version="Fake 1.0", error=None)

    async def open(self) -> None:
        self.open_calls += 1
        if self.fail_open is not None:
            raise self.fail_open

    async def close(self) -> None:
        self.close_calls += 1

    async def health(self) -> HealthResult:
        return self.health_result

    def describe(self) -> ConnectionInfo:
        return ConnectionInfo(
            name=self.name, kind=self.kind, description=self.config.description, mode=self.config.mode
        )


class FakeFactory:
    """Pass as ``BackendRegistry(config, factory=FakeFactory())``; keeps the created backends by name."""

    def __init__(self) -> None:
        self.backends: dict[str, FakeBackend] = {}

    def __call__(self, name: str, config: ConnectionConfig) -> FakeBackend:
        backend = FakeBackend(name, config)
        self.backends[name] = backend
        return backend


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


class FakeClock:
    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_limits.py -q`
Expected: PASS — `3 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends tests/fakes.py tests/unit/test_limits.py
git commit -m "Add backend protocol, safe errors and response clamping" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 7: Principal, stdio resolver and policy

**Files:**
- Create: `src/ratatoskr/auth/__init__.py`, `principal.py`, `resolver.py`, `policy.py`
- Test: `tests/unit/test_resolver.py`, `tests/unit/test_policy.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_resolver.py`:

```python
from ratatoskr.auth.resolver import StdioPrincipalResolver


def test_stdio_principal_with_role() -> None:
    principal = StdioPrincipalResolver("admins").resolve()
    assert principal.subject == "stdio"
    assert principal.display_name == "local stdio user"
    assert principal.groups == frozenset({"admins"})
    assert principal.auth_source == "stdio"


def test_stdio_principal_without_role_has_no_groups() -> None:
    assert StdioPrincipalResolver(None).resolve().groups == frozenset()
```

Create `tests/unit/test_policy.py`:

```python
import pytest

from ratatoskr.auth.policy import ConnectionNotFoundError, InsufficientAccessError, Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import Access
from tests.fakes import make_config

CONFIG = make_config(
    connections={
        "prod": {"mode": "read"},
        "staging": {"mode": "write"},
        "scratch": {"mode": "write"},
    },
    roles={
        "admins": {"*": "write"},
        "devops": {"prod": "read", "staging": "write"},
        "analyst": {"prod": "read"},
        "readers": {"*": "read"},
        "mixed": {"*": "read", "scratch": "write"},
    },
)
POLICY = Policy(CONFIG)


def _user(*groups: str) -> Principal:
    return Principal(subject="u", display_name="U", groups=frozenset(groups), auth_source="local")


@pytest.mark.parametrize(
    ("groups", "connection", "expected"),
    [
        (("admins",), "prod", Access.READ),  # mode: read caps even admins
        (("admins",), "staging", Access.WRITE),
        (("devops",), "prod", Access.READ),
        (("devops",), "staging", Access.WRITE),
        (("devops",), "scratch", Access.NONE),  # no grant -> deny by default
        (("analyst",), "staging", Access.NONE),
        (("readers",), "staging", Access.READ),  # wildcard
        (("mixed",), "scratch", Access.WRITE),  # max(wildcard read, explicit write)
        (("mixed",), "staging", Access.READ),
        (("analyst", "devops"), "staging", Access.WRITE),  # max over groups
        (("nobody",), "prod", Access.NONE),
        ((), "prod", Access.NONE),
        (("admins",), "ghost", Access.NONE),  # unknown connection
    ],
)
def test_effective_access_matrix(groups: tuple[str, ...], connection: str, expected: Access) -> None:
    assert POLICY.effective_access(_user(*groups), connection) == expected


def test_visible_connections_sorted_and_filtered() -> None:
    assert POLICY.visible_connections(_user("devops")) == [("prod", Access.READ), ("staging", Access.WRITE)]
    assert POLICY.visible_connections(_user("nobody")) == []


def test_authorize_returns_effective_access() -> None:
    assert POLICY.authorize(_user("devops"), "staging", Access.READ) == Access.WRITE


def test_unknown_and_forbidden_give_identical_error() -> None:
    with pytest.raises(ConnectionNotFoundError) as unknown:
        POLICY.authorize(_user("analyst"), "ghost", Access.READ)
    with pytest.raises(ConnectionNotFoundError) as forbidden:
        POLICY.authorize(_user("analyst"), "staging", Access.READ)
    assert str(unknown.value) == "Connection 'ghost' not found."
    assert str(forbidden.value) == "Connection 'staging' not found."
    assert type(unknown.value) is type(forbidden.value)


def test_write_needed_on_read_grant() -> None:
    with pytest.raises(InsufficientAccessError, match="Write access required on connection 'prod'."):
        POLICY.authorize(_user("admins"), "prod", Access.WRITE)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_resolver.py tests/unit/test_policy.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.auth'`

- [ ] **Step 3: Write the implementation**

Effective access = `min(max(grants of all groups for the connection or '*'), connection.mode)`, computed on every call from the config (never cached in a token). `NONE` and unknown connections both raise `ConnectionNotFoundError` with the same text.

Create `src/ratatoskr/auth/__init__.py`:

```python
"""Identity and authorization."""
```

Create `src/ratatoskr/auth/principal.py`:

```python
"""The identity a tool call runs as."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Principal:
    subject: str
    display_name: str
    groups: frozenset[str]
    auth_source: Literal["stdio", "local", "oidc"]
```

Create `src/ratatoskr/auth/resolver.py`:

```python
"""Resolve the principal of the current tool call."""

from __future__ import annotations

from typing import Protocol

from ratatoskr.auth.principal import Principal


class PrincipalResolver(Protocol):
    def resolve(self) -> Principal:
        """Return the identity of the current request; raise PermissionError when there is none."""
        ...


class StdioPrincipalResolver:
    """stdio has no authentication: the local user acts as a member of ``server.stdio_role``."""

    def __init__(self, role: str | None) -> None:
        self._principal = Principal(
            subject="stdio",
            display_name="local stdio user",
            groups=frozenset({role}) if role else frozenset(),
            auth_source="stdio",
        )

    def resolve(self) -> Principal:
        return self._principal
```

Create `src/ratatoskr/auth/policy.py`:

```python
"""Effective access: min(max(grants of the principal's groups), connection.mode). Deny by default."""

from __future__ import annotations

from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import Access, GrantLevel, RatatoskrConfig

_LEVELS: dict[GrantLevel, Access] = {"read": Access.READ, "write": Access.WRITE}


class ConnectionNotFoundError(Exception):
    """Raised for unknown connections and for connections the principal may not see (same message)."""

    def __init__(self, connection: str) -> None:
        super().__init__(f"Connection '{connection}' not found.")
        self.connection = connection


class InsufficientAccessError(Exception):
    """Raised when the principal can read a connection but the tool needs write access."""

    def __init__(self, connection: str) -> None:
        super().__init__(f"Write access required on connection '{connection}'.")
        self.connection = connection


class Policy:
    def __init__(self, config: RatatoskrConfig) -> None:
        self._roles = config.roles
        self._modes = {name: _LEVELS[connection.mode] for name, connection in config.connections.items()}

    def effective_access(self, principal: Principal, connection: str) -> Access:
        ceiling = self._modes.get(connection)
        if ceiling is None:
            return Access.NONE
        granted = Access.NONE
        for group in principal.groups:
            grants = self._roles.get(group, {})
            for key in (connection, "*"):
                level = grants.get(key)
                if level is not None:
                    granted = max(granted, _LEVELS[level])
        return min(granted, ceiling)

    def visible_connections(self, principal: Principal) -> list[tuple[str, Access]]:
        visible: list[tuple[str, Access]] = []
        for name in sorted(self._modes):
            access = self.effective_access(principal, name)
            if access > Access.NONE:
                visible.append((name, access))
        return visible

    def authorize(self, principal: Principal, connection: str, need: Access) -> Access:
        access = self.effective_access(principal, connection)
        if access == Access.NONE:
            raise ConnectionNotFoundError(connection)
        if access < need:
            raise InsufficientAccessError(connection)
        return access
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_resolver.py tests/unit/test_policy.py -q`
Expected: PASS — `19 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/auth tests/unit/test_resolver.py tests/unit/test_policy.py
git commit -m "Add principal, stdio resolver and connection policy" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8: PostgreSQL value formatting

**Files:**
- Create: `src/ratatoskr/backends/postgres/__init__.py`, `src/ratatoskr/backends/postgres/formatting.py`
- Test: `tests/unit/test_pg_formatting.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_pg_formatting.py`:

```python
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from uuid import UUID

from ratatoskr.backends.postgres.formatting import format_cell, key_value_list, markdown_table, records_table


def test_format_cell_types() -> None:
    assert format_cell(None) == "NULL"
    assert format_cell(True) == "true"
    assert format_cell(3) == "3"
    assert format_cell(Decimal("12.3400")) == "12.3400"
    assert format_cell(UUID("12345678-1234-5678-1234-567812345678")) == "12345678-1234-5678-1234-567812345678"
    assert format_cell(datetime(2024, 1, 15, 10, 30)) == "2024-01-15T10:30:00"
    assert format_cell(date(2024, 1, 15)) == "2024-01-15"
    assert format_cell(time(10, 30)) == "10:30:00"
    assert format_cell(timedelta(hours=2, minutes=30)) == "2:30:00"
    assert format_cell(b"\xde\xad") == "\\xdead"
    assert format_cell([1, "a", None]) == '[1, "a", null]'
    assert format_cell({"k": Decimal("1.5")}) == '{"k": "1.5"}'


def test_markdown_table() -> None:
    table = markdown_table(["id", "name"], [(1, "Alice"), (2, None)])
    assert table.splitlines() == ["| id | name |", "| --- | --- |", "| 1 | Alice |", "| 2 | NULL |"]


def test_markdown_table_escapes_pipes_and_newlines() -> None:
    table = markdown_table(["note"], [("a|b\nc",)])
    assert table.splitlines()[-1] == "| a\\|b\\nc |"


def test_markdown_table_empty() -> None:
    assert markdown_table(["id"], []) == "_No rows._"


def test_records_table_uses_first_row_keys() -> None:
    assert records_table([{"a": 1, "b": 2}]).splitlines()[0] == "| a | b |"
    assert records_table([]) == "_No rows._"


def test_key_value_list() -> None:
    assert key_value_list({"version": "17", "size": None}) == "- **version:** 17\n- **size:** NULL"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_formatting.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.backends.postgres'`

- [ ] **Step 3: Write the implementation**

Adapted from `src/claude_postgresql/formatters.py`: values are rendered straight to cell strings (decimals stay exact instead of becoming floats, NULL is explicit), and `|` / newlines are escaped so a cell can never break the table. `format_json` and `format_query_result` are not carried over.

Create `src/ratatoskr/backends/postgres/__init__.py`:

```python
"""PostgreSQL backend."""
```

Create `src/ratatoskr/backends/postgres/formatting.py`:

```python
"""Render PostgreSQL values and rows as compact Markdown for an LLM reader."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID


def format_cell(value: Any) -> str:
    """One table cell: NULL for None, ISO dates, exact decimals, hex bytes, JSON for arrays and objects."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, datetime | date | time):
        return value.isoformat()
    if isinstance(value, timedelta | Decimal | UUID):
        return str(value)
    if isinstance(value, bytes | bytearray | memoryview):
        return "\\x" + bytes(value).hex()
    if isinstance(value, list | tuple | dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    return str(value)


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", "").replace("\n", "\\n")


def markdown_table(columns: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Render *rows* (one value per column) as a Markdown table; ``_No rows._`` when empty."""
    if not rows:
        return "_No rows._"
    header = "| " + " | ".join(_escape(column) for column in columns) + " |"
    separator = "|" + "|".join(" --- " for _ in columns) + "|"
    body = ["| " + " | ".join(_escape(format_cell(value)) for value in row) + " |" for row in rows]
    return "\n".join([header, separator, *body])


def records_table(records: Sequence[Mapping[str, Any]]) -> str:
    """Render dict-like rows; columns come from the first row."""
    if not records:
        return "_No rows._"
    columns = list(records[0].keys())
    return markdown_table(columns, [[record[column] for column in columns] for record in records])


def key_value_list(record: Mapping[str, Any]) -> str:
    """Render one row vertically as ``- **key:** value`` lines."""
    return "\n".join(f"- **{key}:** {format_cell(value)}" for key, value in record.items())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_formatting.py -q`
Expected: PASS — `6 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/postgres tests/unit/test_pg_formatting.py
git commit -m "Add PostgreSQL value and table formatting" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 9: PostgreSQL guard pre-checks

**Files:**
- Create: `src/ratatoskr/backends/postgres/guard.py`
- Test: `tests/unit/test_pg_guard.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_pg_guard.py`:

```python
import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres.guard import check_explain_target, check_sql, check_write_sql


@pytest.mark.parametrize("sql", ["", "   ", "-- only a comment", "/* nothing */"])
def test_empty_is_rejected(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="empty"):
        check_sql(sql, max_length=100)


def test_length_limit() -> None:
    with pytest.raises(InvalidRequestError, match="limit is 10"):
        check_sql("SELECT 1 + 1 + 1", max_length=10)
    check_sql("SELECT 1", max_length=10)


@pytest.mark.parametrize(
    "sql",
    [
        "DROP DATABASE prod",
        "ALTER SYSTEM SET work_mem = '1GB'",
        "COPY t TO PROGRAM 'rm -rf /'",
        "COPY t FROM PROGRAM 'curl x'",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_write_file('/tmp/x', 'y')",
        "SELECT lo_import('/etc/passwd')",
        "CREATE EXTENSION dblink",
    ],
)
def test_dangerous_write_statements(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="Blocked operation"):
        check_write_sql(sql, max_length=1000)


@pytest.mark.parametrize(
    "sql",
    ["COMMIT", "begin", "ROLLBACK", "  -- note\nCOMMIT", "/* x */ SAVEPOINT a", "START TRANSACTION", "END"],
)
def test_transaction_control_is_rejected_for_writes(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="Transaction control"):
        check_write_sql(sql, max_length=1000)


def test_normal_write_passes() -> None:
    check_write_sql("UPDATE accounts SET note = 'copy program' WHERE id = $1", max_length=1000)
    check_write_sql("-- comment\nINSERT INTO t VALUES (1)", max_length=1000)


def test_explain_prefix_rejected() -> None:
    with pytest.raises(InvalidRequestError, match="without EXPLAIN"):
        check_explain_target("EXPLAIN SELECT 1", max_length=1000)
    check_explain_target("SELECT 1", max_length=1000)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_guard.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.backends.postgres.guard'`

- [ ] **Step 3: Write the implementation**

Spec §6.2 item 5: only early, readable errors — not the security boundary. The dangerous-function list comes from the old `security.py` and applies to the write path only. Transaction-control statements are rejected for `pg_execute` because a `COMMIT` inside the batch would break its atomicity.

Create `src/ratatoskr/backends/postgres/guard.py`:

```python
"""Early, readable rejections. NOT the security boundary: that is the read-only pool, single-statement
prepared statements, READ ONLY transactions and, above all, a restricted database role (spec 6.2)."""

from __future__ import annotations

import re

from ratatoskr.backends.errors import InvalidRequestError

_LEADING_NOISE_RE = re.compile(r"\A(?:\s+|--[^\n]*(?:\n|\Z)|/\*.*?\*/)*", re.DOTALL)

_DANGEROUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("DROP DATABASE", re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE)),
    ("ALTER SYSTEM", re.compile(r"\bALTER\s+SYSTEM\b", re.IGNORECASE)),
    ("COPY ... PROGRAM", re.compile(r"\bCOPY\b.*\b(?:TO|FROM)\s+PROGRAM\b", re.IGNORECASE | re.DOTALL)),
    ("pg_read_file", re.compile(r"\bpg_read_file\b", re.IGNORECASE)),
    ("pg_read_binary_file", re.compile(r"\bpg_read_binary_file\b", re.IGNORECASE)),
    ("pg_write_file", re.compile(r"\bpg_write_file\b", re.IGNORECASE)),
    ("lo_import", re.compile(r"\blo_import\b", re.IGNORECASE)),
    ("lo_export", re.compile(r"\blo_export\b", re.IGNORECASE)),
    ("CREATE EXTENSION", re.compile(r"\bCREATE\s+EXTENSION\b", re.IGNORECASE)),
)

_TRANSACTION_CONTROL_RE = re.compile(
    r"\A(?:BEGIN|START\s+TRANSACTION|COMMIT|END|ROLLBACK|ABORT|SAVEPOINT|RELEASE|PREPARE\s+TRANSACTION)\b",
    re.IGNORECASE,
)
_EXPLAIN_RE = re.compile(r"\AEXPLAIN\b", re.IGNORECASE)


def _body(sql: str) -> str:
    """The statement with leading whitespace and comments removed."""
    return _LEADING_NOISE_RE.sub("", sql, count=1)


def check_sql(sql: str, *, max_length: int) -> None:
    """Reject empty and over-long statements."""
    if not sql or not _body(sql).strip():
        raise InvalidRequestError("The SQL statement is empty.")
    if len(sql) > max_length:
        raise InvalidRequestError(f"The SQL statement is {len(sql)} characters long; the limit is {max_length}.")


def check_write_sql(sql: str, *, max_length: int) -> None:
    """Extra checks for statements that run on the write pool (pg_execute, write-level EXPLAIN ANALYZE)."""
    check_sql(sql, max_length=max_length)
    for label, pattern in _DANGEROUS_PATTERNS:
        if pattern.search(sql):
            raise InvalidRequestError(f"Blocked operation: {label} is not allowed through this server.")
    if _TRANSACTION_CONTROL_RE.match(_body(sql)):
        raise InvalidRequestError(
            "Transaction control statements (BEGIN, COMMIT, ROLLBACK, SAVEPOINT, ...) are not allowed: "
            "pg_execute already runs all statements in one transaction."
        )


def check_explain_target(sql: str, *, max_length: int) -> None:
    """pg_explain takes the bare statement; EXPLAIN options come from its arguments."""
    check_sql(sql, max_length=max_length)
    if _EXPLAIN_RE.match(_body(sql)):
        raise InvalidRequestError("Pass the statement without EXPLAIN; use the analyze and buffers arguments.")
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_guard.py -q`
Expected: PASS — `22 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/postgres/guard.py tests/unit/test_pg_guard.py
git commit -m "Add PostgreSQL guard pre-checks" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 10: PostgreSQL TLS settings

**Files:**
- Create: `src/ratatoskr/backends/postgres/tls.py`
- Test: `tests/unit/test_pg_tls.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_pg_tls.py`:

```python
import ssl

from ratatoskr.backends.postgres.tls import build_ssl
from ratatoskr.config.models import PgTlsSettings


def test_no_tls_section_keeps_asyncpg_default() -> None:
    assert build_ssl(None) is None


def test_disable() -> None:
    assert build_ssl(PgTlsSettings(mode="disable")) == "disable"


def test_require_does_not_verify() -> None:
    context = build_ssl(PgTlsSettings(mode="require"))
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_verify_ca_checks_chain_not_hostname() -> None:
    context = build_ssl(PgTlsSettings(mode="verify-ca"))
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is False


def test_verify_full_checks_everything() -> None:
    context = build_ssl(PgTlsSettings(mode="verify-full"))
    assert isinstance(context, ssl.SSLContext)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_tls.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.backends.postgres.tls'`

- [ ] **Step 3: Write the implementation**

asyncpg accepts an `ssl.SSLContext` or an sslmode string; no `tls:` section keeps the DSN's sslmode.

Create `src/ratatoskr/backends/postgres/tls.py`:

```python
"""Translate ``tls:`` settings into the ``ssl`` argument of asyncpg."""

from __future__ import annotations

import ssl

from ratatoskr.config.models import PgTlsSettings


def build_ssl(tls: PgTlsSettings | None) -> ssl.SSLContext | str | None:
    """None keeps asyncpg's default (the DSN's sslmode, else 'prefer'); 'disable' turns TLS off."""
    if tls is None:
        return None
    if tls.mode == "disable":
        return "disable"
    context = ssl.create_default_context(cafile=str(tls.ca_file) if tls.ca_file else None)
    if tls.mode == "require":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif tls.mode == "verify-ca":
        context.check_hostname = False
    if tls.cert_file is not None and tls.key_file is not None:
        context.load_cert_chain(certfile=str(tls.cert_file), keyfile=str(tls.key_file))
    return context
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_tls.py -q`
Expected: PASS — `5 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/postgres/tls.py tests/unit/test_pg_tls.py
git commit -m "Map PostgreSQL TLS settings to asyncpg" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 11: PostgresBackend: pools, read sessions, execute, explain

**Files:**
- Create: `src/ratatoskr/backends/postgres/backend.py`
- Test: `tests/unit/test_pg_backend.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_pg_backend.py`:

```python
import asyncpg
import pytest

from ratatoskr.backends.errors import (
    BackendQueryError,
    BackendTimeoutError,
    BackendUnavailableError,
    InvalidRequestError,
)
from ratatoskr.backends.postgres.backend import PostgresBackend, translate_error
from tests.fakes import make_config


def _backend(**values: object) -> PostgresBackend:
    config = make_config(connections={"main": {"statement_timeout": "2s", **values}})
    return PostgresBackend("main", config.connections["main"])


def test_read_pool_settings_survive_reset_all() -> None:
    kwargs = _backend()._pool_kwargs(read_only=True)
    assert kwargs["server_settings"] == {
        "statement_timeout": "2000",
        "application_name": "ratatoskr",
        "default_transaction_read_only": "on",
    }
    assert kwargs["dsn"] == "postgresql://u:secret@db.internal/main"
    assert "ssl" not in kwargs


def test_write_pool_settings_are_not_read_only() -> None:
    kwargs = _backend(mode="write")._pool_kwargs(read_only=False)
    assert "default_transaction_read_only" not in kwargs["server_settings"]
    assert kwargs["server_settings"]["statement_timeout"] == "2000"


def test_tls_is_passed_as_ssl() -> None:
    assert _backend(tls={"mode": "disable"})._pool_kwargs(read_only=True)["ssl"] == "disable"


def test_describe_does_not_open() -> None:
    info = _backend(description="Main DB", mode="write").describe()
    assert (info.name, info.kind, info.description, info.mode) == ("main", "postgres", "Main DB", "write")


async def test_write_pool_refused_on_read_mode() -> None:
    with pytest.raises(InvalidRequestError, match="configured read-only"):
        await _backend(mode="read").execute([("DELETE FROM t", [])], max_rows=10)


async def test_read_before_open_is_unavailable() -> None:
    with pytest.raises(BackendUnavailableError, match="not open"):
        await _backend().fetch_rows("SELECT 1", [], 10)


async def test_health_before_open_reports_error() -> None:
    health = await _backend().health()
    assert health.ok is False
    assert health.error is not None and "not open" in health.error


def test_translate_read_only_violation_adds_hint() -> None:
    exc = asyncpg.exceptions.ReadOnlySQLTransactionError("cannot execute DELETE in a read-only transaction")
    translated = translate_error(exc)
    assert isinstance(translated, BackendQueryError)
    assert "PostgreSQL error 25006: cannot execute DELETE in a read-only transaction" in str(translated)
    assert "pg_execute" in str(translated)


def test_translate_statement_timeout() -> None:
    translated = translate_error(asyncpg.QueryCanceledError("canceling statement due to statement timeout"))
    assert isinstance(translated, BackendTimeoutError)
    assert "statement timeout" in str(translated)


def test_translate_unknown_error_returns_none() -> None:
    assert translate_error(OSError("connect to db.internal failed")) is None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_backend.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.backends.postgres.backend'`

- [ ] **Step 3: Write the implementation**

Verified against asyncpg 0.32 and PostgreSQL 17:

- The pool's release runs `RESET ALL` (`asyncpg/pool.py`), which would undo a `SET` issued in `init`. Startup parameters (`server_settings`) become the session's reset values, so `default_transaction_read_only=on` and `statement_timeout` survive every release.
- `Connection.fetch`/`prepare` always use the extended protocol; a second statement fails with `cannot insert multiple commands into a prepared statement`. `Connection.execute(sql)` without arguments uses the simple protocol and is never called with user SQL.
- `ReadSession.fetch_limited` uses a cursor and reads `max_rows + 1` rows, so huge results are not materialised. `str(asyncpg.PostgresError)` already includes DETAIL and HINT.
- `_guarded` adds a client-side deadline of `statement_timeout + 5s` and turns asyncpg errors into `BackendError`s; any other exception propagates (the runtime hides its text).
- `asyncpg` has no type information (mypy override in `pyproject.toml`), hence the `Any` pool fields.

Create `src/ratatoskr/backends/postgres/backend.py`:

```python
"""PostgreSQL backend: a read-only pool for every caller and a lazy write pool for ``mode: write``.

Read enforcement (spec 6.2):
1. The read pool's sessions start with ``default_transaction_read_only=on`` and ``statement_timeout`` as
   startup parameters, so asyncpg's ``RESET ALL`` on release keeps them.
2. User SQL is only ever sent with the extended protocol (prepare/bind), which accepts a single statement.
3. Every read runs inside ``BEGIN READ ONLY`` and is always rolled back.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar

import asyncpg

from ratatoskr.backends.base import ConnectionInfo, HealthResult
from ratatoskr.backends.errors import (
    BackendError,
    BackendQueryError,
    BackendTimeoutError,
    BackendUnavailableError,
    InvalidRequestError,
)
from ratatoskr.backends.postgres.tls import build_ssl
from ratatoskr.config.models import PostgresConnection

CONNECT_TIMEOUT_SECONDS = 10.0
CLIENT_TIMEOUT_GRACE_SECONDS = 5.0
CLOSE_TIMEOUT_SECONDS = 5.0
READ_ONLY_SQLSTATE = "25006"

logger = logging.getLogger("ratatoskr.backends.postgres")


@dataclass(frozen=True)
class RowSet:
    columns: list[str]
    rows: list[tuple[Any, ...]]
    truncated: bool
    elapsed_ms: float


@dataclass(frozen=True)
class StatementResult:
    status: str
    columns: list[str]
    rows: list[tuple[Any, ...]]


def translate_error(exc: BaseException) -> BackendError | None:
    """Map asyncpg errors to user-safe errors; None means "not a query error" (caller hides details)."""
    if isinstance(exc, asyncpg.QueryCanceledError):
        return BackendTimeoutError(f"PostgreSQL cancelled the statement: {exc}.")
    if isinstance(exc, asyncpg.PostgresError):
        message = f"PostgreSQL error {exc.sqlstate}: {exc}"  # str() already carries DETAIL and HINT
        if exc.sqlstate == READ_ONLY_SQLSTATE:
            message += "\nThis tool runs read-only. Use pg_execute on a connection where you have write access."
        return BackendQueryError(message)
    if isinstance(exc, asyncpg.InterfaceError) and isinstance(exc, ValueError):
        return BackendQueryError(f"Invalid query parameters: {exc}")
    return None


class ReadSession:
    """A connection inside a READ ONLY transaction. Every method uses the extended protocol."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        records = await self._connection.fetch(sql, *args)
        return [dict(record) for record in records]

    async def fetch_limited(self, sql: str, args: Sequence[Any], max_rows: int) -> RowSet:
        started = time.perf_counter()
        statement = await self._connection.prepare(sql)
        columns = [attribute.name for attribute in statement.get_attributes()]
        cursor = await statement.cursor(*args)
        records = await cursor.fetch(max_rows + 1)
        elapsed_ms = (time.perf_counter() - started) * 1000
        rows = [tuple(record) for record in records[:max_rows]]
        return RowSet(columns=columns, rows=rows, truncated=len(records) > max_rows, elapsed_ms=elapsed_ms)


class PostgresBackend:
    kind: ClassVar[str] = "postgres"

    def __init__(self, name: str, config: PostgresConnection) -> None:
        self.name = name
        self.config = config
        self._read_pool: Any = None
        self._write_pool: Any = None
        self._write_lock = asyncio.Lock()
        self._client_timeout = config.statement_timeout.total_seconds() + CLIENT_TIMEOUT_GRACE_SECONDS

    # -- lifecycle ---------------------------------------------------------

    def _pool_kwargs(self, *, read_only: bool) -> dict[str, Any]:
        timeout_ms = max(1, int(self.config.statement_timeout.total_seconds() * 1000))
        server_settings = {"statement_timeout": str(timeout_ms), "application_name": "ratatoskr"}
        if read_only:
            server_settings["default_transaction_read_only"] = "on"
        kwargs: dict[str, Any] = {
            "dsn": self.config.dsn.get_secret_value(),
            "server_settings": server_settings,
            "timeout": CONNECT_TIMEOUT_SECONDS,
        }
        ssl = build_ssl(self.config.tls)
        if ssl is not None:
            kwargs["ssl"] = ssl
        return kwargs

    async def open(self) -> None:
        if self._read_pool is not None:
            return
        self._read_pool = await asyncpg.create_pool(
            min_size=self.config.pool.min_size,
            max_size=self.config.pool.max_size,
            **self._pool_kwargs(read_only=True),
        )

    async def close(self) -> None:
        pools = [pool for pool in (self._write_pool, self._read_pool) if pool is not None]
        self._read_pool = None
        self._write_pool = None
        for pool in pools:
            try:
                await asyncio.wait_for(pool.close(), CLOSE_TIMEOUT_SECONDS)
            except TimeoutError:
                pool.terminate()

    async def health(self) -> HealthResult:
        started = time.perf_counter()
        try:
            async with self.read_session() as session:
                rows = await session.fetch("SELECT current_setting('server_version') AS version")
        except BackendError as exc:
            return HealthResult(ok=False, latency_ms=None, version=None, error=str(exc))
        except Exception as exc:
            logger.warning("health check of %s failed", self.name, exc_info=True)
            return HealthResult(ok=False, latency_ms=None, version=None, error=type(exc).__name__)
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        return HealthResult(ok=True, latency_ms=latency_ms, version=f"PostgreSQL {rows[0]['version']}", error=None)

    def describe(self) -> ConnectionInfo:
        return ConnectionInfo(
            name=self.name, kind=self.kind, description=self.config.description, mode=self.config.mode
        )

    # -- guarded execution -------------------------------------------------

    @contextlib.asynccontextmanager
    async def _guarded(self) -> AsyncIterator[None]:
        """Client-side deadline plus translation of asyncpg errors into user-safe errors."""
        try:
            async with asyncio.timeout(self._client_timeout):
                yield
        except BackendError:
            raise
        except TimeoutError:
            raise BackendTimeoutError(
                f"Connection '{self.name}' did not answer within {self._client_timeout:.0f}s."
            ) from None
        except Exception as exc:
            translated = translate_error(exc)
            if translated is None:
                raise
            raise translated from exc

    @contextlib.asynccontextmanager
    async def read_session(self) -> AsyncIterator[ReadSession]:
        """Yield a session on the read pool inside ``BEGIN READ ONLY``; always rolled back."""
        if self._read_pool is None:
            raise BackendUnavailableError(f"Connection '{self.name}' is not open.")
        async with self._guarded(), self._read_pool.acquire() as connection:
            transaction = connection.transaction(readonly=True)
            await transaction.start()
            try:
                yield ReadSession(connection)
            finally:
                await _rollback_quietly(transaction)

    async def _ensure_write_pool(self) -> Any:
        if self.config.mode != "write":
            raise InvalidRequestError(f"Connection '{self.name}' is configured read-only (mode: read).")
        async with self._write_lock:
            if self._write_pool is None:
                self._write_pool = await asyncpg.create_pool(
                    min_size=0,
                    max_size=self.config.pool.write_max_size,
                    **self._pool_kwargs(read_only=False),
                )
        return self._write_pool

    # -- operations --------------------------------------------------------

    async def fetch_rows(self, sql: str, args: Sequence[Any], max_rows: int) -> RowSet:
        async with self.read_session() as session:
            return await session.fetch_limited(sql, args, max_rows)

    async def execute(self, statements: Sequence[tuple[str, Sequence[Any]]], max_rows: int) -> list[StatementResult]:
        """Run *statements* in one transaction on the write pool; any failure rolls back all of them."""
        results: list[StatementResult] = []
        total = len(statements)
        async with self._guarded():
            pool = await self._ensure_write_pool()
            async with pool.acquire() as connection, connection.transaction():
                for index, (sql, args) in enumerate(statements, start=1):
                    try:
                        statement = await connection.prepare(sql)
                        records = await statement.fetch(*args)
                    except Exception as exc:
                        translated = translate_error(exc)
                        if translated is None:
                            raise
                        raise type(translated)(
                            f"Statement {index} of {total} failed, so the transaction was rolled back and nothing "
                            f"was changed.\n{translated}"
                        ) from exc
                    columns = [attribute.name for attribute in statement.get_attributes()]
                    rows = [tuple(record) for record in records[:max_rows]]
                    results.append(StatementResult(status=statement.get_statusmsg(), columns=columns, rows=rows))
        return results

    async def explain(
        self, sql: str, args: Sequence[Any], *, analyze: bool, buffers: bool, use_write_pool: bool
    ) -> list[str]:
        """EXPLAIN *sql*. With ``use_write_pool`` the statement runs in a transaction that is always rolled back."""
        options: list[str] = []
        if analyze:
            options.append("ANALYZE")
            if buffers:
                options.append("BUFFERS")
        options.append("FORMAT TEXT")
        explain_sql = f"EXPLAIN ({', '.join(options)}) {sql}"
        if not use_write_pool:
            async with self.read_session() as session:
                rows = await session.fetch(explain_sql, *args)
            return [str(row["QUERY PLAN"]) for row in rows]
        async with self._guarded():
            pool = await self._ensure_write_pool()
            async with pool.acquire() as connection:
                transaction = connection.transaction()
                await transaction.start()
                try:
                    records = await connection.fetch(explain_sql, *args)
                finally:
                    await _rollback_quietly(transaction)
        return [str(record["QUERY PLAN"]) for record in records]


async def _rollback_quietly(transaction: Any) -> None:
    """Roll back; if that fails the pool's reset on release cleans the connection up."""
    try:
        await transaction.rollback()
    except Exception:
        logger.debug("rollback failed; the pool will reset the connection", exc_info=True)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_backend.py -q`
Expected: PASS — `10 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/postgres/backend.py tests/unit/test_pg_backend.py
git commit -m "Add PostgreSQL backend with read-only pool and lazy write pool" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 12: Backend registry

**Files:**
- Create: `src/ratatoskr/backends/registry.py`
- Test: `tests/unit/test_registry.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_registry.py`:

```python
import pytest

from ratatoskr.auth.policy import ConnectionNotFoundError
from ratatoskr.backends.errors import BackendUnavailableError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.registry import BackendRegistry
from tests.fakes import LEAKY_MESSAGE, FakeClock, FakeFactory, make_config

CONFIG = make_config(connections={"a": {"description": "A"}, "b": {"limits": {"max_response_bytes": 2048}}})


def _registry() -> tuple[BackendRegistry, FakeFactory, FakeClock]:
    factory, clock = FakeFactory(), FakeClock()
    return BackendRegistry(CONFIG, factory=factory, clock=clock), factory, clock


def test_default_factory_builds_postgres_backends() -> None:
    registry = BackendRegistry(CONFIG)
    assert registry.names() == ["a", "b"]
    assert registry.describe("a").kind == PostgresBackend.kind


def test_describe_and_limits_without_opening() -> None:
    registry, factory, _ = _registry()
    assert registry.describe("a").description == "A"
    assert registry.max_response_bytes("b") == 2048
    assert registry.max_response_bytes("a") == 65536
    assert registry.max_response_bytes(None) == 65536
    assert factory.backends["a"].open_calls == 0


async def test_opens_lazily_once() -> None:
    registry, factory, _ = _registry()
    first = await registry.get("a")
    second = await registry.get("a")
    assert first is second
    assert factory.backends["a"].open_calls == 1
    assert factory.backends["b"].open_calls == 0


async def test_unknown_connection() -> None:
    registry, _, _ = _registry()
    with pytest.raises(ConnectionNotFoundError, match="Connection 'ghost' not found."):
        await registry.get("ghost")


async def test_failed_open_is_retried_after_ten_seconds() -> None:
    registry, factory, clock = _registry()
    factory.backends["a"].fail_open = OSError(LEAKY_MESSAGE)
    with pytest.raises(BackendUnavailableError) as first:
        await registry.get("a")
    assert "hunter2" not in str(first.value)
    assert "db.internal" not in str(first.value)
    assert "OSError" in str(first.value)

    clock.now += 5
    with pytest.raises(BackendUnavailableError, match="Retry in 5s"):
        await registry.get("a")
    assert factory.backends["a"].open_calls == 1  # throttled: no new attempt

    clock.now += 5
    factory.backends["a"].fail_open = None
    assert await registry.get("a") is factory.backends["a"]
    assert factory.backends["a"].open_calls == 2


async def test_close_all_closes_opened_and_allows_reopen() -> None:
    registry, factory, _ = _registry()
    await registry.get("a")
    await registry.close_all()
    assert factory.backends["a"].close_calls == 1
    assert factory.backends["b"].close_calls == 0
    await registry.get("a")
    assert factory.backends["a"].open_calls == 2
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_registry.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.backends.registry'`

- [ ] **Step 3: Write the implementation**

Spec §3.4: lazy open, per-connection failure state, at most one attempt per 10 s, `close_all` at shutdown. The user-facing message names only the exception class; the full exception goes to the log (masked by the JSON formatter). Backends are constructed in `__init__` (no I/O) so `describe` works without opening anything.

Create `src/ratatoskr/backends/registry.py`:

```python
"""Config -> backend instances. Backends open lazily; a failed open is retried at most every 10 seconds."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from ratatoskr.auth.policy import ConnectionNotFoundError
from ratatoskr.backends.base import Backend, ConnectionInfo
from ratatoskr.backends.errors import BackendUnavailableError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.config.models import ConnectionConfig, RatatoskrConfig

RETRY_INTERVAL_SECONDS = 10.0
DEFAULT_MAX_RESPONSE_BYTES = 65536

BackendFactory = Callable[[str, ConnectionConfig], Backend]

logger = logging.getLogger("ratatoskr.backends")


def default_factory(name: str, config: ConnectionConfig) -> Backend:
    return PostgresBackend(name, config)


class BackendRegistry:
    def __init__(
        self,
        config: RatatoskrConfig,
        *,
        factory: BackendFactory = default_factory,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._configs = dict(config.connections)
        self._backends: dict[str, Backend] = {name: factory(name, cfg) for name, cfg in self._configs.items()}
        self._clock = clock
        self._opened: set[str] = set()
        self._failed_at: dict[str, tuple[float, str]] = {}
        self._locks: dict[str, asyncio.Lock] = {name: asyncio.Lock() for name in self._backends}

    def names(self) -> list[str]:
        return sorted(self._backends)

    def describe(self, name: str) -> ConnectionInfo:
        backend = self._backends.get(name)
        if backend is None:
            raise ConnectionNotFoundError(name)
        return backend.describe()

    def max_response_bytes(self, name: str | None) -> int:
        config = self._configs.get(name) if name is not None else None
        return config.limits.max_response_bytes if config is not None else DEFAULT_MAX_RESPONSE_BYTES

    async def get(self, name: str) -> Backend:
        backend = self._backends.get(name)
        if backend is None:
            raise ConnectionNotFoundError(name)
        if name in self._opened:
            return backend
        async with self._locks[name]:
            if name in self._opened:
                return backend
            self._raise_if_backing_off(name)
            try:
                await backend.open()
            except Exception as exc:
                self._failed_at[name] = (self._clock(), type(exc).__name__)
                logger.warning("opening connection %s failed", name, exc_info=True)
                raise BackendUnavailableError(
                    f"Connection '{name}' is unavailable: opening it failed ({type(exc).__name__}). "
                    f"It will be retried in {RETRY_INTERVAL_SECONDS:.0f}s; details are in the server log."
                ) from None
            self._failed_at.pop(name, None)
            self._opened.add(name)
            return backend

    def _raise_if_backing_off(self, name: str) -> None:
        failure = self._failed_at.get(name)
        if failure is None:
            return
        failed_at, error_class = failure
        wait = RETRY_INTERVAL_SECONDS - (self._clock() - failed_at)
        if wait > 0:
            raise BackendUnavailableError(
                f"Connection '{name}' is unavailable: the last attempt failed ({error_class}). Retry in {wait:.0f}s."
            )

    async def close_all(self) -> None:
        for name in sorted(self._opened):
            try:
                await self._backends[name].close()
            except Exception:
                logger.warning("closing connection %s failed", name, exc_info=True)
        self._opened.clear()
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_registry.py -q`
Expected: PASS — `6 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/registry.py tests/unit/test_registry.py
git commit -m "Add backend registry with lazy open and retry back-off" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 13: ToolRuntime

**Files:**
- Create: `src/ratatoskr/tools/__init__.py`, `src/ratatoskr/tools/runtime.py`
- Test: `tests/unit/test_runtime.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_runtime.py`:

```python
import asyncio

import pytest

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.errors import BackendQueryError, BackendTimeoutError
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime
from tests.fakes import LEAKY_MESSAGE, FakeFactory, RecordingSink, make_config

CONFIG = make_config(
    connections={"prod": {"mode": "read", "limits": {"max_response_bytes": 1024}}, "dev": {"mode": "write"}},
    roles={"team": {"prod": "read", "dev": "write"}},
)


class _NoIdentity:
    def resolve(self) -> Principal:
        raise PermissionError("no authenticated user")


def _runtime(role: str | None = "team") -> tuple[ToolRuntime, RecordingSink, FakeFactory]:
    sink, factory = RecordingSink(), FakeFactory()
    registry = BackendRegistry(CONFIG, factory=factory)
    return ToolRuntime(Policy(CONFIG), registry, StdioPrincipalResolver(role), sink), sink, factory


async def _ok(backend: Backend, access: Access) -> ToolOutput:
    return ToolOutput(text=f"{backend.name}:{access.name}", rows=3)


async def test_success_passes_access_and_audits() -> None:
    runtime, sink, _ = _runtime()
    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok, query_text="SELECT 1")
    assert text == "dev:WRITE"
    [event] = sink.events
    assert (event.tool, event.connection, event.result, event.rows) == ("pg_query", "dev", "ok", 3)
    assert event.subject == "stdio"
    assert event.auth_source == "stdio"
    assert event.query_text == "SELECT 1"
    assert event.query_sha256 is not None
    assert event.error_class is None


async def test_unknown_and_forbidden_look_the_same() -> None:
    runtime, sink, factory = _runtime(role=None)
    unknown = await runtime.run(tool="pg_query", connection="ghost", need=Access.READ, call=_ok)
    forbidden = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=_ok)
    assert unknown == "Error: Connection 'ghost' not found."
    assert forbidden == "Error: Connection 'prod' not found."
    assert [event.result for event in sink.events] == ["denied", "denied"]
    assert factory.backends["prod"].open_calls == 0


async def test_write_on_read_connection_is_denied() -> None:
    runtime, sink, _ = _runtime()
    text = await runtime.run(tool="pg_execute", connection="prod", need=Access.WRITE, call=_ok)
    assert text == "Error: Write access required on connection 'prod'."
    assert sink.events[0].result == "denied"
    assert sink.events[0].error_class == "InsufficientAccessError"


async def test_missing_identity_is_denied() -> None:
    sink = RecordingSink()
    runtime = ToolRuntime(Policy(CONFIG), BackendRegistry(CONFIG, factory=FakeFactory()), _NoIdentity(), sink)
    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok)
    assert text == "Error: no authenticated user"
    assert sink.events[0].result == "denied"
    assert sink.events[0].subject == "anonymous"


async def test_backend_error_message_is_shown() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendQueryError('PostgreSQL error 42P01: relation "nope" does not exist')

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert text == 'Error: PostgreSQL error 42P01: relation "nope" does not exist'
    assert sink.events[0].result == "error"
    assert sink.events[0].error_class == "BackendQueryError"


async def test_unexpected_error_hides_details() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise OSError(LEAKY_MESSAGE)

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert "hunter2" not in text
    assert "db.internal" not in text
    assert text == "Error: pg_query failed on connection 'dev' (OSError). Details are in the server log."
    assert sink.events[0].result == "error"


async def test_open_failure_hides_details() -> None:
    runtime, sink, factory = _runtime()
    factory.backends["dev"].fail_open = OSError(LEAKY_MESSAGE)
    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok)
    assert "hunter2" not in text
    assert "db.internal" not in text
    assert "Connection 'dev' is unavailable" in text
    assert sink.events[0].result == "error"
    assert sink.events[0].error_class == "BackendUnavailableError"


async def test_dsn_inside_backend_error_is_redacted() -> None:
    runtime, _, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendQueryError("PostgreSQL error 08001: could not connect using postgresql://a:hunter2@h/db")

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert "hunter2" not in text
    assert "postgresql://***" in text


async def test_client_timeout() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        await asyncio.sleep(5)
        return ToolOutput(text="late")

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call, timeout=0.05)
    assert text == "Error: pg_query timed out."
    assert sink.events[0].result == "timeout"


async def test_backend_timeout_is_audited_as_timeout() -> None:
    runtime, sink, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        raise BackendTimeoutError("PostgreSQL cancelled the statement: canceling statement due to statement timeout.")

    text = await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=call)
    assert "statement timeout" in text
    assert sink.events[0].result == "timeout"


async def test_response_is_clamped_to_connection_limit() -> None:
    runtime, _, _ = _runtime()

    async def call(backend: Backend, access: Access) -> ToolOutput:
        return ToolOutput(text="y" * 10_000, rows=1)

    text = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=call)
    assert len(text.encode("utf-8")) <= 1024
    assert "[Response truncated: it exceeded 1024 bytes." in text


async def test_run_global_audits_without_connection() -> None:
    runtime, sink, _ = _runtime()

    async def call(principal: Principal) -> ToolOutput:
        return ToolOutput(text=f"hi {principal.subject}", rows=0)

    assert await runtime.run_global(tool="list_connections", call=call) == "hi stdio"
    assert sink.events[0].connection is None
    assert sink.events[0].result == "ok"


async def test_audit_sink_failure_does_not_break_the_call() -> None:
    class Exploding:
        def record(self, event: object) -> None:
            raise RuntimeError("boom")

    registry = BackendRegistry(CONFIG, factory=FakeFactory())
    runtime = ToolRuntime(Policy(CONFIG), registry, StdioPrincipalResolver("team"), Exploding())
    assert await runtime.run(tool="pg_query", connection="dev", need=Access.READ, call=_ok) == "dev:WRITE"


@pytest.mark.parametrize("tool", ["pg_query", "pg_execute"])
async def test_every_call_is_audited_once(tool: str) -> None:
    runtime, sink, _ = _runtime()
    await runtime.run(tool=tool, connection="dev", need=Access.READ, call=_ok)
    assert len(sink.events) == 1
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_runtime.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.tools'`

- [ ] **Step 3: Write the implementation**

Result mapping for the audit event: policy errors and `PermissionError` → `denied`; `BackendTimeoutError` and `TimeoutError` → `timeout`; everything else → `error`. Only `BackendError` and policy messages are shown verbatim; any other exception becomes `Error: <tool> failed on connection '<name>' (<Class>). Details are in the server log.` Every returned text passes through `redact` as a last line of defence. Exactly one audit event per call.

Create `src/ratatoskr/tools/__init__.py`:

```python
"""MCP tool runtime and backend-independent tools."""
```

Create `src/ratatoskr/tools/runtime.py`:

```python
"""The single wrapper every tool call goes through: identity, policy, backend, deadline, clamp, audit."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ratatoskr.auth.policy import ConnectionNotFoundError, InsufficientAccessError, Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.auth.resolver import PrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.errors import BackendError, BackendTimeoutError
from ratatoskr.backends.limits import clamp_text
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import Access
from ratatoskr.observability.audit import AuditResult, AuditSink, build_event
from ratatoskr.observability.redact import redact

TRUNCATION_HINT = "Narrow the request: add WHERE/LIMIT, select fewer columns, or ask for one table or schema."

logger = logging.getLogger("ratatoskr.tools")


@dataclass(frozen=True)
class ToolOutput:
    text: str
    rows: int | None = None


@dataclass
class _Outcome:
    result: AuditResult = "ok"
    error_class: str | None = None
    rows: int | None = None


class ToolRuntime:
    def __init__(
        self, policy: Policy, registry: BackendRegistry, resolver: PrincipalResolver, audit: AuditSink
    ) -> None:
        self.policy = policy
        self.registry = registry
        self._resolver = resolver
        self._audit = audit

    async def run(
        self,
        *,
        tool: str,
        connection: str,
        need: Access,
        call: Callable[[Backend, Access], Awaitable[ToolOutput]],
        query_text: str | None = None,
        timeout: float | None = None,
    ) -> str:
        """resolve -> authorize -> registry.get -> deadline -> clamp -> audit; errors become safe text."""
        started = time.perf_counter()
        outcome = _Outcome()
        principal: Principal | None = None
        try:
            principal = self._resolver.resolve()
            access = self.policy.authorize(principal, connection, need)
            async with asyncio.timeout(timeout):
                backend = await self.registry.get(connection)
                output = await call(backend, access)
            outcome.rows = output.rows
            text = clamp_text(output.text, self.registry.max_response_bytes(connection), TRUNCATION_HINT).text
        except Exception as exc:
            text = self._error_text(exc, tool=tool, connection=connection, outcome=outcome)
        self._record(tool, connection, principal, query_text, started, outcome)
        return redact(text)

    async def run_global(
        self,
        *,
        tool: str,
        call: Callable[[Principal], Awaitable[ToolOutput]],
        timeout: float | None = None,
    ) -> str:
        """Same wrapper for tools that are not bound to one connection (list_connections, health of all)."""
        started = time.perf_counter()
        outcome = _Outcome()
        principal: Principal | None = None
        try:
            principal = self._resolver.resolve()
            async with asyncio.timeout(timeout):
                output = await call(principal)
            outcome.rows = output.rows
            text = clamp_text(output.text, self.registry.max_response_bytes(None), TRUNCATION_HINT).text
        except Exception as exc:
            text = self._error_text(exc, tool=tool, connection=None, outcome=outcome)
        self._record(tool, None, principal, None, started, outcome)
        return redact(text)

    @staticmethod
    def _error_text(exc: Exception, *, tool: str, connection: str | None, outcome: _Outcome) -> str:
        outcome.error_class = type(exc).__name__
        if isinstance(exc, ConnectionNotFoundError | InsufficientAccessError | PermissionError):
            outcome.result = "denied"
            return f"Error: {exc}"
        if isinstance(exc, BackendTimeoutError):
            outcome.result = "timeout"
            return f"Error: {exc}"
        if isinstance(exc, TimeoutError):
            outcome.result = "timeout"
            return f"Error: {tool} timed out."
        outcome.result = "error"
        if isinstance(exc, BackendError):
            return f"Error: {exc}"
        logger.error("tool %s failed on connection %s", tool, connection, exc_info=exc)
        where = f" on connection '{connection}'" if connection else ""
        return f"Error: {tool} failed{where} ({type(exc).__name__}). Details are in the server log."

    def _record(
        self,
        tool: str,
        connection: str | None,
        principal: Principal | None,
        query_text: str | None,
        started: float,
        outcome: _Outcome,
    ) -> None:
        try:
            self._audit.record(
                build_event(
                    subject=principal.subject if principal else "anonymous",
                    auth_source=principal.auth_source if principal else "none",
                    connection=connection,
                    tool=tool,
                    query_text=query_text,
                    duration_ms=(time.perf_counter() - started) * 1000,
                    rows=outcome.rows,
                    result=outcome.result,
                    error_class=outcome.error_class,
                )
            )
        except Exception:
            logger.debug("audit sink raised", exc_info=True)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_runtime.py -q`
Expected: PASS — `15 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/tools tests/unit/test_runtime.py
git commit -m "Add ToolRuntime: policy, deadline, clamping and audit per call" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 14: PostgreSQL querying and introspection operations

**Files:**
- Create: `src/ratatoskr/backends/postgres/querying.py`, `src/ratatoskr/backends/postgres/introspection.py`
- Test: `tests/unit/test_pg_querying.py`, `tests/unit/test_pg_introspection.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_pg_querying.py`:

```python
import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.postgres.querying import affected_rows, run_execute, run_explain, run_query
from ratatoskr.config.models import Access
from tests.fakes import make_config


def _backend(mode: str = "write") -> PostgresBackend:
    config = make_config(connections={"main": {"mode": mode, "limits": {"max_query_length": 50}}})
    return PostgresBackend("main", config.connections["main"])


@pytest.mark.parametrize(
    ("status", "expected"), [("UPDATE 3", 3), ("INSERT 0 1", 1), ("DELETE 0", 0), ("CREATE TABLE", 0)]
)
def test_affected_rows(status: str, expected: int) -> None:
    assert affected_rows(status) == expected


async def test_query_guard_runs_before_database() -> None:
    with pytest.raises(InvalidRequestError, match="empty"):
        await run_query(_backend(), "  ", [])
    with pytest.raises(InvalidRequestError, match="limit is 50"):
        await run_query(_backend(), "SELECT " + "1," * 40 + "1", [])


async def test_execute_guard_runs_before_database() -> None:
    with pytest.raises(InvalidRequestError, match="Transaction control"):
        await run_execute(_backend(), [("UPDATE t SET a = 1", []), ("COMMIT", [])])


async def test_execute_with_no_statements() -> None:
    output = await run_execute(_backend(), [])
    assert output.text == "Nothing to do: `statements` is empty."


async def test_explain_rejects_explain_prefix() -> None:
    with pytest.raises(InvalidRequestError, match="without EXPLAIN"):
        await run_explain(_backend(), Access.READ, "EXPLAIN SELECT 1", [], analyze=False, buffers=False)


async def test_write_level_explain_analyze_applies_write_guard() -> None:
    with pytest.raises(InvalidRequestError, match="Blocked operation"):
        await run_explain(_backend(), Access.WRITE, "SELECT pg_read_file('/x')", [], analyze=True, buffers=False)
```

Create `tests/unit/test_pg_introspection.py`:

```python
import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres import introspection
from ratatoskr.backends.postgres.backend import PostgresBackend
from tests.fakes import make_config


def _backend(allowed: list[str]) -> PostgresBackend:
    config = make_config(connections={"main": {"allowed_schemas": allowed}})
    return PostgresBackend("main", config.connections["main"])


def test_any_schema_when_not_restricted() -> None:
    introspection.check_schema_allowed(_backend([]), "anything")


def test_restricted_schema_is_rejected_with_the_allowed_list() -> None:
    with pytest.raises(InvalidRequestError, match="limited to: public, sales"):
        introspection.check_schema_allowed(_backend(["public", "sales"]), "hr")


@pytest.mark.parametrize("call", ["list_tables", "table_stats"])
async def test_tools_check_schema_before_touching_the_database(call: str) -> None:
    backend = _backend(["public"])
    with pytest.raises(InvalidRequestError, match="not available"):
        if call == "list_tables":
            await introspection.list_tables(backend, "hr")
        else:
            await introspection.table_stats(backend, "hr", None)


async def test_describe_checks_schema_first() -> None:
    with pytest.raises(InvalidRequestError, match="not available"):
        await introspection.describe_table(_backend(["public"]), "hr", "staff")
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_querying.py tests/unit/test_pg_introspection.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.backends.postgres.querying'`

- [ ] **Step 3: Write the implementation**

The unit tests only prove that guard and schema checks run before any database access (the backend is never opened). The SQL itself is exercised by the integration tests in Tasks 19–21.

`introspection.py` adapts the old `tools/schema.py` (columns, PK/FK, indexes, constraints → one `pg_describe_table` call on `pg_catalog`, plus incoming foreign keys), `tools/admin.py` (running queries + locks → `pg_activity`, table stats → `pg_table_stats`) and `tools/database_info.py` (databases, sizes → `pg_server_info`, `pg_table_stats`). All user input travels as `$n` parameters, so the old `sanitize_identifier` is gone. `pg_explain` decides the pool from the *effective* access: `analyze=True` with WRITE uses the write pool (always rolled back) and also applies the write guard.

Create `src/ratatoskr/backends/postgres/querying.py`:

```python
"""pg_query, pg_execute and pg_explain: guard checks, pool choice and result rendering."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.postgres.formatting import markdown_table
from ratatoskr.backends.postgres.guard import check_explain_target, check_sql, check_write_sql
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput


def affected_rows(status: str) -> int:
    """Rows affected according to a command tag such as ``UPDATE 3`` or ``INSERT 0 1``."""
    last = status.rsplit(" ", 1)[-1]
    return int(last) if last.isdigit() else 0


async def run_query(backend: PostgresBackend, sql: str, params: Sequence[Any]) -> ToolOutput:
    limits = backend.config.limits
    check_sql(sql, max_length=limits.max_query_length)
    result = await backend.fetch_rows(sql, params, limits.max_rows)
    header = f"{len(result.rows)} row(s) in {result.elapsed_ms:.1f} ms."
    if result.truncated:
        header = (
            f"Showing the first {len(result.rows)} rows; the query returned more "
            f"(limit {limits.max_rows}). Add WHERE, LIMIT or aggregation to narrow it."
        )
    if not result.columns:
        return ToolOutput(text=f"{header}\nThe statement returned no columns.", rows=0)
    return ToolOutput(text=f"{header}\n\n{markdown_table(result.columns, result.rows)}", rows=len(result.rows))


async def run_execute(backend: PostgresBackend, statements: Sequence[tuple[str, Sequence[Any]]]) -> ToolOutput:
    limits = backend.config.limits
    if not statements:
        return ToolOutput(text="Nothing to do: `statements` is empty.", rows=0)
    for sql, _ in statements:
        check_write_sql(sql, max_length=limits.max_query_length)
    results = await backend.execute(statements, limits.max_rows)
    lines = [f"Transaction committed ({len(results)} statement(s))."]
    total = 0
    for index, result in enumerate(results, start=1):
        total += affected_rows(result.status)
        lines.append(f"{index}. {result.status}")
        if result.columns and result.rows:
            lines += ["", markdown_table(result.columns, result.rows), ""]
    return ToolOutput(text="\n".join(lines), rows=total)


async def run_explain(
    backend: PostgresBackend, access: Access, sql: str, params: Sequence[Any], *, analyze: bool, buffers: bool
) -> ToolOutput:
    limits = backend.config.limits
    check_explain_target(sql, max_length=limits.max_query_length)
    use_write_pool = analyze and access >= Access.WRITE
    if use_write_pool:
        check_write_sql(sql, max_length=limits.max_query_length)
    plan = await backend.explain(sql, params, analyze=analyze, buffers=buffers, use_write_pool=use_write_pool)
    if not analyze:
        note = "Estimated plan (the statement was not executed)."
    elif use_write_pool:
        note = "EXPLAIN ANALYZE ran the statement in a transaction that was rolled back; no data was changed."
    else:
        note = "EXPLAIN ANALYZE ran the statement in a READ ONLY transaction that was rolled back."
    return ToolOutput(text=note + "\n\n```\n" + "\n".join(plan) + "\n```", rows=len(plan))
```

Create `src/ratatoskr/backends/postgres/introspection.py`:

```python
"""Catalog queries for discovery and monitoring tools. All SQL is fixed; user input only travels as $n."""

from __future__ import annotations

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.backends.postgres.formatting import key_value_list, records_table
from ratatoskr.tools.runtime import ToolOutput

LIST_SCHEMAS_SQL = """
SELECT n.nspname AS schema,
       pg_get_userbyid(n.nspowner) AS owner,
       count(c.oid) FILTER (WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')) AS relations,
       obj_description(n.oid, 'pg_namespace') AS comment
FROM pg_namespace n
LEFT JOIN pg_class c ON c.relnamespace = n.oid
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
  AND n.nspname NOT LIKE 'pg_temp_%' AND n.nspname NOT LIKE 'pg_toast_temp_%'
GROUP BY n.oid, n.nspname, n.nspowner
ORDER BY n.nspname
"""

LIST_TABLES_SQL = """
SELECT c.relname AS name,
       CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned table' WHEN 'v' THEN 'view'
                      WHEN 'm' THEN 'materialized view' WHEN 'f' THEN 'foreign table' END AS type,
       CASE WHEN c.reltuples < 0 THEN NULL ELSE c.reltuples::bigint END AS estimated_rows,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size,
       obj_description(c.oid, 'pg_class') AS comment
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY c.relname
"""

FIND_RELATION_SQL = """
SELECT c.oid, c.relkind::text AS relkind
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
"""

COLUMNS_SQL = """
SELECT a.attname AS column,
       format_type(a.atttypid, a.atttypmod) AS type,
       CASE WHEN a.attnotnull THEN 'no' ELSE 'yes' END AS nullable,
       pg_get_expr(d.adbin, d.adrelid) AS default,
       col_description(a.attrelid, a.attnum) AS comment
FROM pg_attribute a
LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum
"""

CONSTRAINTS_SQL = """
SELECT conname AS name,
       CASE contype WHEN 'p' THEN 'PRIMARY KEY' WHEN 'f' THEN 'FOREIGN KEY' WHEN 'u' THEN 'UNIQUE'
                    WHEN 'c' THEN 'CHECK' WHEN 'x' THEN 'EXCLUDE' ELSE contype::text END AS type,
       pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE conrelid = $1
ORDER BY CASE contype WHEN 'p' THEN 0 WHEN 'f' THEN 1 WHEN 'u' THEN 2 ELSE 3 END, conname
"""

REFERENCED_BY_SQL = """
SELECT conrelid::regclass::text AS from_table, conname AS name, pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE confrelid = $1 AND contype = 'f'
ORDER BY 1, 2
"""

INDEXES_SQL = """
SELECT i.relname AS name, pg_get_indexdef(x.indexrelid) AS definition
FROM pg_index x
JOIN pg_class i ON i.oid = x.indexrelid
WHERE x.indrelid = $1
ORDER BY i.relname
"""

TABLE_STATS_SQL = """
SELECT s.relname AS table,
       pg_size_pretty(pg_total_relation_size(s.relid)) AS total_size,
       pg_size_pretty(pg_relation_size(s.relid)) AS table_size,
       pg_size_pretty(pg_indexes_size(s.relid)) AS index_size,
       s.n_live_tup AS live_rows,
       s.n_dead_tup AS dead_rows,
       s.seq_scan,
       s.idx_scan,
       s.n_tup_ins AS inserts,
       s.n_tup_upd AS updates,
       s.n_tup_del AS deletes,
       s.last_vacuum,
       s.last_autovacuum,
       s.last_analyze,
       s.last_autoanalyze
FROM pg_stat_user_tables s
WHERE s.schemaname = $1 AND ($2::text IS NULL OR s.relname::text = $2::text)
ORDER BY pg_total_relation_size(s.relid) DESC, s.relname
"""

SCHEMA_STATS_COLUMNS = ("table", "total_size", "live_rows", "dead_rows", "seq_scan", "idx_scan", "last_autovacuum")

ACTIVITY_SQL = """
SELECT a.pid,
       a.usename AS user,
       a.datname AS database,
       a.state,
       a.wait_event_type,
       a.wait_event,
       date_trunc('second', now() - a.query_start) AS running_for,
       pg_blocking_pids(a.pid) AS blocked_by,
       left(a.query, 300) AS query
FROM pg_stat_activity a
WHERE a.state IS DISTINCT FROM 'idle' AND a.pid <> pg_backend_pid() AND a.backend_type = 'client backend'
ORDER BY a.query_start NULLS LAST
LIMIT 200
"""

WAITING_LOCKS_SQL = """
SELECT l.pid,
       l.locktype,
       l.mode,
       l.relation::regclass::text AS relation,
       date_trunc('second', now() - a.query_start) AS waiting_for,
       left(a.query, 200) AS query
FROM pg_locks l
JOIN pg_stat_activity a ON a.pid = l.pid
WHERE NOT l.granted
ORDER BY a.query_start NULLS LAST
LIMIT 200
"""

SERVER_INFO_SQL = """
SELECT version() AS version,
       current_database() AS current_database,
       current_user AS current_user,
       pg_size_pretty(pg_database_size(current_database())) AS current_database_size,
       date_trunc('second', now() - pg_postmaster_start_time()) AS uptime,
       current_setting('max_connections') AS max_connections,
       current_setting('TimeZone') AS timezone
"""

DATABASES_SQL = """
SELECT datname AS database,
       pg_get_userbyid(datdba) AS owner,
       pg_encoding_to_char(encoding) AS encoding,
       CASE WHEN has_database_privilege(datname, 'CONNECT') THEN pg_size_pretty(pg_database_size(datname)) END AS size
FROM pg_database
WHERE NOT datistemplate
ORDER BY datname
"""


def check_schema_allowed(backend: PostgresBackend, schema: str) -> None:
    allowed = backend.config.allowed_schemas
    if allowed and schema not in allowed:
        raise InvalidRequestError(
            f"Schema '{schema}' is not available on connection '{backend.name}'. "
            f"Discovery tools are limited to: {', '.join(allowed)}."
        )


async def list_schemas(backend: PostgresBackend) -> ToolOutput:
    async with backend.read_session() as session:
        rows = await session.fetch(LIST_SCHEMAS_SQL)
    allowed = backend.config.allowed_schemas
    if allowed:
        rows = [row for row in rows if row["schema"] in allowed]
    return ToolOutput(text=f"Schemas on '{backend.name}':\n\n{records_table(rows)}", rows=len(rows))


async def list_tables(backend: PostgresBackend, schema: str) -> ToolOutput:
    check_schema_allowed(backend, schema)
    async with backend.read_session() as session:
        rows = await session.fetch(LIST_TABLES_SQL, schema)
    if not rows:
        return ToolOutput(text=f"No tables or views in schema '{schema}' on '{backend.name}'.", rows=0)
    return ToolOutput(text=f"Relations in '{schema}' on '{backend.name}':\n\n{records_table(rows)}", rows=len(rows))


async def describe_table(backend: PostgresBackend, schema: str, table: str) -> ToolOutput:
    check_schema_allowed(backend, schema)
    async with backend.read_session() as session:
        found = await session.fetch(FIND_RELATION_SQL, schema, table)
        if not found:
            raise InvalidRequestError(
                f"Table '{schema}.{table}' not found on '{backend.name}'. Use pg_list_tables to see what exists."
            )
        oid = found[0]["oid"]
        columns = await session.fetch(COLUMNS_SQL, oid)
        constraints = await session.fetch(CONSTRAINTS_SQL, oid)
        referenced_by = await session.fetch(REFERENCED_BY_SQL, oid)
        indexes = await session.fetch(INDEXES_SQL, oid)
    parts = [f"## {schema}.{table}", "", "### Columns", "", records_table(columns)]
    if constraints:
        parts += ["", "### Constraints (primary key, foreign keys, unique, check)", "", records_table(constraints)]
    if referenced_by:
        parts += ["", "### Referenced by", "", records_table(referenced_by)]
    if indexes:
        parts += ["", "### Indexes", "", records_table(indexes)]
    return ToolOutput(text="\n".join(parts), rows=len(columns))


async def table_stats(backend: PostgresBackend, schema: str, table: str | None) -> ToolOutput:
    check_schema_allowed(backend, schema)
    async with backend.read_session() as session:
        rows = await session.fetch(TABLE_STATS_SQL, schema, table)
    if not rows:
        target = f"table '{schema}.{table}'" if table else f"schema '{schema}'"
        return ToolOutput(text=f"No statistics for {target} on '{backend.name}'.", rows=0)
    if table is not None:
        return ToolOutput(text=f"## Statistics: {schema}.{table}\n\n{key_value_list(rows[0])}", rows=1)
    summary = [{column: row[column] for column in SCHEMA_STATS_COLUMNS} for row in rows]
    text = (
        f"Table statistics for schema '{schema}' on '{backend.name}' (largest first). "
        f"Pass `table` for the full set of counters.\n\n{records_table(summary)}"
    )
    return ToolOutput(text=text, rows=len(rows))


async def activity(backend: PostgresBackend) -> ToolOutput:
    async with backend.read_session() as session:
        sessions = await session.fetch(ACTIVITY_SQL)
        locks = await session.fetch(WAITING_LOCKS_SQL)
    parts = [f"## Active sessions on '{backend.name}' ({len(sessions)})", "", records_table(sessions)]
    parts += ["", f"## Waiting locks ({len(locks)})", "", records_table(locks)]
    return ToolOutput(text="\n".join(parts), rows=len(sessions))


async def server_info(backend: PostgresBackend) -> ToolOutput:
    async with backend.read_session() as session:
        info = await session.fetch(SERVER_INFO_SQL)
        databases = await session.fetch(DATABASES_SQL)
    parts = [f"## Server: {backend.name}", "", key_value_list(info[0])]
    parts += ["", "## Databases", "", records_table(databases)]
    return ToolOutput(text="\n".join(parts), rows=len(databases))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_querying.py tests/unit/test_pg_introspection.py -q`
Expected: PASS — `14 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/postgres/querying.py src/ratatoskr/backends/postgres/introspection.py tests/unit/test_pg_querying.py tests/unit/test_pg_introspection.py
git commit -m "Add PostgreSQL query, execute, explain and catalog operations" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 15: PostgreSQL tool registration and descriptions

**Files:**
- Create: `src/ratatoskr/backends/postgres/descriptions.py`, `src/ratatoskr/backends/postgres/tools.py`
- Test: `tests/unit/test_pg_tools.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_pg_tools.py`:

```python
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.postgres.tools import register_postgres_tools
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.tools.runtime import ToolRuntime
from tests.fakes import FakeFactory, RecordingSink, make_config

PG_TOOLS = [
    "pg_list_schemas",
    "pg_list_tables",
    "pg_describe_table",
    "pg_query",
    "pg_execute",
    "pg_explain",
    "pg_activity",
    "pg_table_stats",
    "pg_server_info",
]
CONFIG = make_config(connections={"main": {"mode": "write"}}, roles={"admins": {"*": "write"}})


def _mcp() -> FastMCP[Any]:
    registry = BackendRegistry(CONFIG, factory=FakeFactory())
    runtime = ToolRuntime(Policy(CONFIG), registry, StdioPrincipalResolver("admins"), RecordingSink())
    mcp: FastMCP[Any] = FastMCP("test")
    register_postgres_tools(mcp, runtime)
    return mcp


async def test_registers_the_nine_tools_in_spec_order() -> None:
    assert [tool.name for tool in await _mcp().list_tools()] == PG_TOOLS


async def test_annotations() -> None:
    for tool in await _mcp().list_tools():
        assert tool.annotations is not None, tool.name
        assert tool.annotations.title, tool.name
        if tool.name == "pg_execute":
            assert tool.annotations.readOnlyHint is False
            assert tool.annotations.destructiveHint is True
        else:
            assert tool.annotations.readOnlyHint is True, tool.name
            assert tool.annotations.destructiveHint is False, tool.name


@pytest.mark.parametrize("name", PG_TOOLS)
async def test_connection_is_the_first_required_argument(name: str) -> None:
    tools = {tool.name: tool for tool in await _mcp().list_tools()}
    schema = tools[name].inputSchema
    assert next(iter(schema["properties"])) == "connection"
    assert "connection" in schema["required"]
    assert "list_connections" in schema["properties"]["connection"]["description"]
    assert 80 < len(tools[name].description or "") < 700


async def test_pg_execute_statement_schema() -> None:
    tools = {tool.name: tool for tool in await _mcp().list_tools()}
    statement = tools["pg_execute"].inputSchema["$defs"]["Statement"]
    assert statement["required"] == ["sql"]
    assert set(statement["properties"]) == {"sql", "params"}


async def test_non_postgres_backend_is_rejected() -> None:
    result = await _mcp().call_tool("pg_list_schemas", {"connection": "main"})
    assert result[0].text == "Error: Connection 'main' is not a PostgreSQL connection."  # type: ignore[index, union-attr]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_tools.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.backends.postgres.tools'`

- [ ] **Step 3: Write the implementation**

FastMCP API used (mcp 1.30, `mcp/server/fastmcp/server.py`): `FastMCP.add_tool(fn, name=None, title=None, description=None, annotations: ToolAnnotations | None, structured_output: bool | None)`. `structured_output=False` keeps plain text content. The description is used as-is (no dedent), so it is passed explicitly. Argument descriptions come from `Annotated[..., Field(description=...)]` and appear in `inputSchema`. Tools take no `Context`; the runtime is captured by closure, so `FastMCP.call_tool` works in tests without a session.

Create `src/ratatoskr/backends/postgres/descriptions.py`:

```python
"""Tool and argument descriptions for the PostgreSQL tools. They are the product UX for the LLM: keep them short,
say what the tool returns, when to use it, and what the limits are."""

from __future__ import annotations

CONNECTION = (
    "Name of a PostgreSQL connection exactly as returned by list_connections. "
    "Call list_connections first if you do not know the names."
)
SCHEMA = "Schema name (default 'public'). Use pg_list_schemas to see the schemas."
TABLE = "Table, view or materialized view name without the schema prefix."
SQL_READ = "One SQL statement (no trailing second statement). Use $1, $2, ... placeholders for values."
PARAMS = (
    "Values for $1, $2, ... in order, as JSON values. Dates, timestamps and UUIDs can be passed as strings "
    "if the placeholder is cast through text, e.g. $1::text::date."
)

PG_LIST_SCHEMAS = (
    "List the non-system schemas of a PostgreSQL connection with owner and number of relations. "
    "Start here when exploring an unfamiliar database, then call pg_list_tables. If the connection sets "
    "allowed_schemas, only those are listed (this limits discovery tools only, not pg_query)."
)
PG_LIST_TABLES = (
    "List the tables, views, materialized views and foreign tables of one schema with type, estimated row count, "
    "total size and comment. Use it to find table names before pg_describe_table or pg_query."
)
PG_DESCRIBE_TABLE = (
    "Describe one table in a single call: columns (type, nullable, default, comment), constraints (primary key, "
    "foreign keys with their target tables, unique, check), foreign keys from other tables that reference it, "
    "and indexes. Use it before writing joins or filters."
)
PG_QUERY = (
    "Run one read-only SQL statement (SELECT, WITH ... SELECT, SHOW, VALUES, TABLE) and get the rows as a "
    "Markdown table. It always runs in a READ ONLY transaction that is rolled back, so writes, nextval() and "
    "SELECT ... FOR UPDATE fail; use pg_execute to change data. Returns at most the connection's row limit "
    "(default 500): select only the columns you need and add WHERE, LIMIT or aggregation on large tables."
)
PG_EXECUTE = (
    "Change data or schema: run one or more SQL statements (INSERT, UPDATE, DELETE, DDL, ...) in a single "
    "transaction that is committed only if every statement succeeds; any failure rolls back all of them. "
    "Needs write access, which list_connections shows. Do not send BEGIN/COMMIT. Each statement is one "
    "SQL command with optional params; RETURNING rows are shown."
)
PG_EXECUTE_STATEMENTS = (
    "Statements to run in order inside one transaction, e.g. "
    '[{"sql": "UPDATE accounts SET balance = balance - $1 WHERE id = $2", "params": [100, 7]}].'
)
PG_EXPLAIN = (
    "Show the PostgreSQL execution plan of one statement. analyze=false (default) only plans it and never runs "
    "it. analyze=true runs it to get real timings: with read access inside a READ ONLY transaction (so only "
    "read statements work), with write access inside a transaction that is always rolled back, so no data "
    "changes either way. Pass the statement without the EXPLAIN keyword."
)
PG_EXPLAIN_ANALYZE = "Run the statement to measure real row counts and timings (always rolled back)."
PG_EXPLAIN_BUFFERS = "Include buffer usage (only with analyze=true)."
PG_ACTIVITY = (
    "Show what the PostgreSQL server is doing now: active sessions (user, state, wait event, running time, "
    "blocking pids, query text) and lock requests that are waiting. Use it to investigate slow or stuck queries."
)
PG_TABLE_STATS = (
    "Table statistics from pg_stat_user_tables: size (table, indexes, total), live and dead rows, sequential vs "
    "index scans, insert/update/delete counts and last vacuum/analyze times. Without `table`, summarises every "
    "table of the schema, largest first."
)
PG_TABLE_STATS_TABLE = "Optional table name for the full set of counters of one table."
PG_SERVER_INFO = (
    "Show PostgreSQL server facts: version, current database, user and size, uptime, max_connections, "
    "time zone, and the list of databases with owner, encoding and size."
)
```

Create `src/ratatoskr/backends/postgres/tools.py`:

```python
"""Register the nine PostgreSQL tools (spec 6.2). Every tool goes through ToolRuntime.run."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field

from ratatoskr.backends import errors
from ratatoskr.backends.base import Backend
from ratatoskr.backends.postgres import descriptions as d
from ratatoskr.backends.postgres import introspection, querying
from ratatoskr.backends.postgres.backend import PostgresBackend
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime

ConnectionArg = Annotated[str, Field(description=d.CONNECTION)]
SchemaArg = Annotated[str, Field(description=d.SCHEMA)]
TableArg = Annotated[str, Field(description=d.TABLE)]
SqlArg = Annotated[str, Field(description=d.SQL_READ)]
ParamsArg = Annotated[list[Any] | None, Field(description=d.PARAMS)]


class Statement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sql: Annotated[str, Field(description="One SQL statement.")]
    params: Annotated[list[Any], Field(description=d.PARAMS)] = []


def _read_only(title: str) -> ToolAnnotations:
    return ToolAnnotations(title=title, readOnlyHint=True, destructiveHint=False, openWorldHint=False)


def _postgres(backend: Backend) -> PostgresBackend:
    if not isinstance(backend, PostgresBackend):
        raise errors.InvalidRequestError(f"Connection '{backend.name}' is not a PostgreSQL connection.")
    return backend


def register_postgres_tools(mcp: FastMCP[Any], runtime: ToolRuntime) -> None:
    async def pg_list_schemas(connection: ConnectionArg) -> str:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.list_schemas(_postgres(backend))

        return await runtime.run(tool="pg_list_schemas", connection=connection, need=Access.READ, call=call)

    async def pg_list_tables(connection: ConnectionArg, schema: SchemaArg = "public") -> str:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.list_tables(_postgres(backend), schema)

        return await runtime.run(tool="pg_list_tables", connection=connection, need=Access.READ, call=call)

    async def pg_describe_table(connection: ConnectionArg, table: TableArg, schema: SchemaArg = "public") -> str:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.describe_table(_postgres(backend), schema, table)

        return await runtime.run(tool="pg_describe_table", connection=connection, need=Access.READ, call=call)

    async def pg_query(connection: ConnectionArg, sql: SqlArg, params: ParamsArg = None) -> str:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await querying.run_query(_postgres(backend), sql, params or [])

        return await runtime.run(tool="pg_query", connection=connection, need=Access.READ, call=call, query_text=sql)

    async def pg_execute(
        connection: ConnectionArg,
        statements: Annotated[list[Statement], Field(description=d.PG_EXECUTE_STATEMENTS)],
    ) -> str:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            pairs = [(statement.sql, statement.params) for statement in statements]
            return await querying.run_execute(_postgres(backend), pairs)

        query_text = "\n;\n".join(statement.sql for statement in statements)
        return await runtime.run(
            tool="pg_execute", connection=connection, need=Access.WRITE, call=call, query_text=query_text
        )

    async def pg_explain(
        connection: ConnectionArg,
        sql: SqlArg,
        params: ParamsArg = None,
        analyze: Annotated[bool, Field(description=d.PG_EXPLAIN_ANALYZE)] = False,
        buffers: Annotated[bool, Field(description=d.PG_EXPLAIN_BUFFERS)] = False,
    ) -> str:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await querying.run_explain(
                _postgres(backend), access, sql, params or [], analyze=analyze, buffers=buffers
            )

        return await runtime.run(tool="pg_explain", connection=connection, need=Access.READ, call=call, query_text=sql)

    async def pg_activity(connection: ConnectionArg) -> str:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.activity(_postgres(backend))

        return await runtime.run(tool="pg_activity", connection=connection, need=Access.READ, call=call)

    async def pg_table_stats(
        connection: ConnectionArg,
        schema: SchemaArg = "public",
        table: Annotated[str | None, Field(description=d.PG_TABLE_STATS_TABLE)] = None,
    ) -> str:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.table_stats(_postgres(backend), schema, table)

        return await runtime.run(tool="pg_table_stats", connection=connection, need=Access.READ, call=call)

    async def pg_server_info(connection: ConnectionArg) -> str:
        async def call(backend: Backend, access: Access) -> ToolOutput:
            return await introspection.server_info(_postgres(backend))

        return await runtime.run(tool="pg_server_info", connection=connection, need=Access.READ, call=call)

    write = ToolAnnotations(title="Execute SQL (writes)", readOnlyHint=False, destructiveHint=True, openWorldHint=False)
    tools = (
        (pg_list_schemas, d.PG_LIST_SCHEMAS, _read_only("List schemas")),
        (pg_list_tables, d.PG_LIST_TABLES, _read_only("List tables")),
        (pg_describe_table, d.PG_DESCRIBE_TABLE, _read_only("Describe table")),
        (pg_query, d.PG_QUERY, _read_only("Run read-only SQL")),
        (pg_execute, d.PG_EXECUTE, write),
        (pg_explain, d.PG_EXPLAIN, _read_only("Explain query plan")),
        (pg_activity, d.PG_ACTIVITY, _read_only("Server activity and locks")),
        (pg_table_stats, d.PG_TABLE_STATS, _read_only("Table statistics")),
        (pg_server_info, d.PG_SERVER_INFO, _read_only("Server information")),
    )
    for fn, description, hints in tools:
        mcp.add_tool(fn, description=description, annotations=hints, structured_output=False)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_pg_tools.py -q`
Expected: PASS — `13 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/postgres/descriptions.py src/ratatoskr/backends/postgres/tools.py tests/unit/test_pg_tools.py
git commit -m "Register the nine PostgreSQL tools with annotations" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 16: Common tools: list_connections and connection_health

**Files:**
- Create: `src/ratatoskr/tools/common.py`
- Test: `tests/unit/test_common_tools.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_common_tools.py`:

```python
from typing import Any

from mcp.server.fastmcp import FastMCP

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import HealthResult
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.tools.common import register_common_tools
from ratatoskr.tools.runtime import ToolRuntime
from tests.fakes import LEAKY_MESSAGE, FakeFactory, RecordingSink, make_config

CONFIG = make_config(
    connections={
        "prod": {"mode": "read", "description": "Main | prod"},
        "dev": {"mode": "write", "description": "Dev"},
        "secret": {"mode": "write"},
    },
    roles={"team": {"prod": "read", "dev": "write"}, "empty": {}},
)


def _app(role: str | None = "team") -> tuple[FastMCP[Any], FakeFactory, RecordingSink]:
    factory, sink = FakeFactory(), RecordingSink()
    runtime = ToolRuntime(Policy(CONFIG), BackendRegistry(CONFIG, factory=factory), StdioPrincipalResolver(role), sink)
    mcp: FastMCP[Any] = FastMCP("test")
    register_common_tools(mcp, runtime)
    return mcp, factory, sink


async def _call(mcp: FastMCP[Any], name: str, **arguments: Any) -> str:
    result = await mcp.call_tool(name, arguments)
    return result[0].text  # type: ignore[index, union-attr]


async def test_list_connections_shows_only_visible() -> None:
    mcp, factory, sink = _app()
    text = await _call(mcp, "list_connections")
    assert "| dev | postgres | write | Dev |" in text
    assert "| prod | postgres | read | Main \\| prod |" in text
    assert "secret" not in text
    assert all(backend.open_calls == 0 for backend in factory.backends.values())
    assert sink.events[0].tool == "list_connections"


async def test_list_connections_when_nothing_is_granted() -> None:
    mcp, _, _ = _app(role="empty")
    assert "No connections are available to you" in await _call(mcp, "list_connections")


async def test_health_of_all_visible_connections() -> None:
    mcp, factory, _ = _app()
    factory.backends["prod"].fail_open = OSError(LEAKY_MESSAGE)
    text = await _call(mcp, "connection_health")
    assert "| dev | postgres | ok | 1.5 ms | Fake 1.0 |  |" in text
    assert "| prod | postgres | unavailable | - | - |" in text
    assert "secret" not in text
    assert "hunter2" not in text


async def test_health_of_one_connection() -> None:
    mcp, factory, sink = _app()
    factory.backends["dev"].health_result = HealthResult(ok=False, latency_ms=None, version=None, error="down")
    text = await _call(mcp, "connection_health", connection="dev")
    assert "| dev | postgres | unavailable | - | - | down |" in text
    assert sink.events[0].connection == "dev"


async def test_health_of_forbidden_connection_is_not_found() -> None:
    mcp, _, _ = _app()
    assert await _call(mcp, "connection_health", connection="secret") == "Error: Connection 'secret' not found."
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_common_tools.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.tools.common'`

- [ ] **Step 3: Write the implementation**

`list_connections` never opens a backend (it uses `registry.describe`). `connection_health()` without argument checks all visible connections concurrently with a 15 s cap each; with an argument it goes through `runtime.run` with READ, so a forbidden name gets the same `not found` answer.

Create `src/ratatoskr/tools/common.py`:

```python
"""Backend-independent tools: list_connections and connection_health (spec 6.1)."""

from __future__ import annotations

import asyncio
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from ratatoskr.auth.principal import Principal
from ratatoskr.backends.base import Backend, HealthResult
from ratatoskr.backends.errors import BackendError
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime

HEALTH_TIMEOUT_SECONDS = 15.0

LIST_CONNECTIONS = (
    "List the data connections you can use: name, kind (e.g. postgres), description and your access level "
    "(read or write). Call this first: every other tool takes one of these names as its `connection` argument."
)
CONNECTION_HEALTH = (
    "Check whether connections are reachable: status, round-trip latency and server version. Pass a connection "
    "name to check one, or omit it to check every connection you can use."
)
HEALTH_CONNECTION_ARG = "Connection name from list_connections; omit to check all of your connections."


def _health_row(name: str, kind: str, health: HealthResult) -> list[str]:
    latency = f"{health.latency_ms:.1f} ms" if health.latency_ms is not None else "-"
    status = "ok" if health.ok else "unavailable"
    return [name, kind, status, latency, health.version or "-", health.error or ""]


def _health_table(rows: list[list[str]]) -> str:
    lines = ["| connection | kind | status | latency | version | error |", "| --- | --- | --- | --- | --- | --- |"]
    lines += ["| " + " | ".join(cell.replace("|", "\\|").replace("\n", " ") for cell in row) + " |" for row in rows]
    return "\n".join(lines)


async def _check(registry: BackendRegistry, name: str) -> HealthResult:
    try:
        backend: Backend = await registry.get(name)
        async with asyncio.timeout(HEALTH_TIMEOUT_SECONDS):
            return await backend.health()
    except BackendError as exc:
        return HealthResult(ok=False, latency_ms=None, version=None, error=str(exc))
    except TimeoutError:
        error = f"no answer within {HEALTH_TIMEOUT_SECONDS:.0f}s"
        return HealthResult(ok=False, latency_ms=None, version=None, error=error)


def register_common_tools(mcp: FastMCP[Any], runtime: ToolRuntime) -> None:
    async def list_connections() -> str:
        async def call(principal: Principal) -> ToolOutput:
            visible = runtime.policy.visible_connections(principal)
            if not visible:
                return ToolOutput(
                    text=(
                        "No connections are available to you. Ask the server administrator to grant one of your "
                        "groups access under `roles` in the config (for stdio, set `server.stdio_role`)."
                    ),
                    rows=0,
                )
            lines = [
                f"You can use {len(visible)} connection(s). Pass the name as the `connection` argument.",
                "",
                "| name | kind | access | description |",
                "| --- | --- | --- | --- |",
            ]
            for name, access in visible:
                info = runtime.registry.describe(name)
                description = info.description.replace("|", "\\|").replace("\n", " ")
                lines.append(f"| {name} | {info.kind} | {access.name.lower()} | {description} |")
            return ToolOutput(text="\n".join(lines), rows=len(visible))

        return await runtime.run_global(tool="list_connections", call=call)

    async def connection_health(
        connection: Annotated[str | None, Field(description=HEALTH_CONNECTION_ARG)] = None,
    ) -> str:
        if connection is not None:
            name = connection

            async def call_one(backend: Backend, access: Access) -> ToolOutput:
                async with asyncio.timeout(HEALTH_TIMEOUT_SECONDS):
                    health = await backend.health()
                return ToolOutput(text=_health_table([_health_row(name, backend.kind, health)]), rows=1)

            return await runtime.run(tool="connection_health", connection=name, need=Access.READ, call=call_one)

        async def call_all(principal: Principal) -> ToolOutput:
            names = [name for name, _ in runtime.policy.visible_connections(principal)]
            if not names:
                return ToolOutput(text="No connections are available to you.", rows=0)
            results = await asyncio.gather(*(_check(runtime.registry, name) for name in names))
            rows = [
                _health_row(name, runtime.registry.describe(name).kind, health)
                for name, health in zip(names, results, strict=True)
            ]
            return ToolOutput(text=_health_table(rows), rows=len(rows))

        return await runtime.run_global(tool="connection_health", call=call_all)

    read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)
    mcp.add_tool(
        list_connections,
        description=LIST_CONNECTIONS,
        annotations=read_only.model_copy(update={"title": "List connections"}),
        structured_output=False,
    )
    mcp.add_tool(
        connection_health,
        description=CONNECTION_HEALTH,
        annotations=read_only.model_copy(update={"title": "Connection health"}),
        structured_output=False,
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_common_tools.py -q`
Expected: PASS — `5 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/tools/common.py tests/unit/test_common_tools.py
git commit -m "Add list_connections and connection_health tools" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 17: FastMCP application

**Files:**
- Create: `src/ratatoskr/app.py`
- Test: `tests/unit/test_app.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_app.py`:

```python
from typing import Any

from mcp.server.fastmcp import FastMCP

from ratatoskr.app import build_app
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.registry import BackendRegistry
from tests.fakes import RecordingSink, make_config

CONFIG = make_config(connections={"main": {"mode": "write"}}, roles={"admins": {"*": "write"}}, stdio_role="admins")


def _app() -> FastMCP[Any]:
    return build_app(CONFIG, resolver=StdioPrincipalResolver("admins"), audit=RecordingSink())


async def test_registers_eleven_tools() -> None:
    names = [tool.name for tool in await _app().list_tools()]
    assert names[:2] == ["list_connections", "connection_health"]
    assert len(names) == 11
    assert all(name.startswith("pg_") for name in names[2:])


async def test_instructions_point_to_list_connections() -> None:
    app = _app()
    assert app.name == "ratatoskr"
    assert "list_connections" in (app.instructions or "")


async def test_list_connections_works_without_database() -> None:
    result = await _app().call_tool("list_connections", {})
    assert "| main | postgres | write |" in result[0].text  # type: ignore[index, union-attr]


async def test_lifespan_yields_state_and_closes_cleanly() -> None:
    app = _app()
    assert app.settings.lifespan is not None
    async with app.settings.lifespan(app) as state:
        assert state.registry.names() == ["main"]
        assert state.runtime.registry is state.registry


class _ClosingRegistry(BackendRegistry):
    def __init__(self) -> None:
        super().__init__(CONFIG)
        self.closed = 0

    async def close_all(self) -> None:
        self.closed += 1
        await super().close_all()


async def test_injected_registry_is_not_closed_by_session_lifespan() -> None:
    registry = _ClosingRegistry()
    app = build_app(CONFIG, resolver=StdioPrincipalResolver("admins"), audit=RecordingSink(), registry=registry)
    assert app.settings.lifespan is not None
    for _ in range(2):  # two MCP sessions over streamable-http
        async with app.settings.lifespan(app) as state:
            assert state.registry is registry
    assert registry.closed == 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_app.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.app'`

- [ ] **Step 3: Write the implementation**

Signature is the contract's. `auth_server_provider` / `auth_settings` are passed straight to FastMCP (`FastMCP(name, instructions=..., auth_server_provider=..., lifespan=..., auth=...)`); 1a always passes `None`. `FastMCP.settings.lifespan` is the function given here, which the test enters directly.

Create `src/ratatoskr/app.py`:

```python
"""FastMCP application: lifespan, policy, registry, runtime and tool registration."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.provider import OAuthAuthorizationServerProvider
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import PrincipalResolver
from ratatoskr.backends.postgres.tools import register_postgres_tools
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import AuditSink
from ratatoskr.tools.common import register_common_tools
from ratatoskr.tools.runtime import ToolRuntime

INSTRUCTIONS = (
    "Ratatoskr connects you to several named data sources (currently PostgreSQL databases). "
    "Call list_connections first to see which connections you may use and whether you can read or write; "
    "every other tool takes one of those names as its `connection` argument. Explore with pg_list_schemas, "
    "pg_list_tables and pg_describe_table before writing SQL, and prefer pg_query for reads. "
    "pg_execute changes data and needs write access."
)


@dataclass(frozen=True)
class AppState:
    registry: BackendRegistry
    runtime: ToolRuntime


def build_app(
    config: RatatoskrConfig,
    *,
    resolver: PrincipalResolver,
    audit: AuditSink,
    auth_server_provider: OAuthAuthorizationServerProvider[Any, Any, Any] | None = None,
    auth_settings: AuthSettings | None = None,
    registry: BackendRegistry | None = None,
) -> FastMCP[AppState]:
    # Ownership rule: whoever creates the registry closes it. Over stdio the FastMCP lifespan runs once, so
    # build_app owns it. Over streamable-http the SDK enters this lifespan once per MCP session; the HTTP
    # composition root (Plan 1b) then passes its own registry and closes it in the process-level lifespan.
    owns_registry = registry is None
    active_registry = registry if registry is not None else BackendRegistry(config)
    runtime = ToolRuntime(Policy(config), active_registry, resolver, audit)

    @asynccontextmanager
    async def lifespan(_: FastMCP[AppState]) -> AsyncIterator[AppState]:
        try:
            yield AppState(registry=active_registry, runtime=runtime)
        finally:
            if owns_registry:
                await active_registry.close_all()

    mcp: FastMCP[AppState] = FastMCP(
        "ratatoskr",
        instructions=INSTRUCTIONS,
        lifespan=lifespan,
        auth_server_provider=auth_server_provider,
        auth=auth_settings,
    )
    register_common_tools(mcp, runtime)
    register_postgres_tools(mcp, runtime)
    return mcp
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_app.py -q`
Expected: PASS — `5 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/app.py tests/unit/test_app.py
git commit -m "Build the FastMCP app with lifespan and all tools" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 18: CLI: serve and check-config

**Files:**
- Create: `src/ratatoskr/cli.py`, `src/ratatoskr/__main__.py`
- Test: `tests/unit/test_cli.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_cli.py`:

```python
from pathlib import Path
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from ratatoskr.cli import DEFAULT_CONFIG_PATH, main, resolve_config_path

STDIO_CONFIG = """
server:
  stdio_role: admins
roles:
  admins: {"*": write}
connections:
  main:
    kind: postgres
    description: Main database
    dsn: ${MAIN_DSN}
"""

HTTP_CONFIG = """
server:
  transport: streamable-http
  public_url: https://mcp.example.com
  secret_key: ${SECRET}
auth:
  mode: local
  local:
    users:
      - username: kerem
        password_hash: x
connections:
  main:
    kind: postgres
    dsn: ${MAIN_DSN}
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_config_path_precedence() -> None:
    assert resolve_config_path("a.yaml", {"RATATOSKR_CONFIG": "b.yaml"}) == Path("a.yaml")
    assert resolve_config_path(None, {"RATATOSKR_CONFIG": "b.yaml"}) == Path("b.yaml")
    assert resolve_config_path(None, {}) == DEFAULT_CONFIG_PATH


def test_check_config_ok_prints_summary_without_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://u:hunter2@db.internal/app")
    assert main(["check-config", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 0
    out = capsys.readouterr().out
    assert "Config OK" in out
    assert "main: postgres, mode=read  Main database" in out
    assert "stdio_role: admins" in out
    assert "hunter2" not in out
    assert "db.internal" not in out


def test_check_config_error_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("MAIN_DSN", raising=False)
    assert main(["check-config", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 2
    assert "environment variable 'MAIN_DSN' is not defined" in capsys.readouterr().err


def test_check_config_uses_env_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
    monkeypatch.setenv("RATATOSKR_CONFIG", str(_write(tmp_path, STDIO_CONFIG)))
    assert main(["check-config"]) == 0


def test_serve_refuses_http_transport_for_now(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
    monkeypatch.setenv("SECRET", "s" * 32)
    assert main(["serve", "--config", str(_write(tmp_path, HTTP_CONFIG))]) == 2
    assert "'streamable-http' is not available in this version yet" in capsys.readouterr().err


def test_serve_validates_http_rules_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
    monkeypatch.setenv("SECRET", "s" * 32)
    text = HTTP_CONFIG.replace("https://mcp.example.com", "http://mcp.example.com")
    assert main(["serve", "--config", str(_write(tmp_path, text))]) == 2
    assert "must use https" in capsys.readouterr().err


def test_serve_runs_stdio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
    calls: list[str] = []

    def fake_run(self: FastMCP[Any], transport: str = "stdio", mount_path: str | None = None) -> None:
        calls.append(transport)

    monkeypatch.setattr(FastMCP, "run", fake_run)
    assert main(["serve", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 0
    assert calls == ["stdio"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_cli.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'ratatoskr.cli'`

- [ ] **Step 3: Write the implementation**

`serve` validates the whole config first (including the streamable-http rules), then refuses any transport other than stdio with a clear `ConfigError` (exit code 2) until Plan 1b removes that check. `check-config` prints a summary built only from names, kinds, modes and descriptions — never DSNs.

Create `src/ratatoskr/cli.py`:

```python
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
```

Create `src/ratatoskr/__main__.py`:

```python
from ratatoskr.cli import main

raise SystemExit(main())
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_cli.py -q`
Expected: PASS — `7 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Reinstall so the `ratatoskr` console script exists**

```bash
.venv/Scripts/python -m pip uninstall -y claude-postgresql
.venv/Scripts/python -m pip install --index-url https://pypi.org/simple -e ".[dev]"
.venv/Scripts/ratatoskr --version
```

Expected: the last command prints `ratatoskr 1.0.0.dev0`. Then run `.venv/Scripts/python -m pytest -q` — the old suite must still pass (the editable install keeps `src/` on the path).

- [ ] **Step 6: Commit**

```bash
git add src/ratatoskr/cli.py src/ratatoskr/__main__.py tests/unit/test_cli.py
git commit -m "Add ratatoskr serve and check-config commands" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 19: Integration harness and read-mode enforcement tests

**Files:**
- Create: `tests/integration/helpers.py`, `tests/integration/conftest.py`
- Test: `tests/integration/test_pg_read_guard.py`

These tests drive the real stack (ToolRuntime → Policy → BackendRegistry → PostgresBackend) through `FastMCP.call_tool` against a local `postgres:17` container. testcontainers 4.15 exposes `testcontainers.community.postgres.PostgresContainer(image, driver=None)`; `get_connection_url()` then returns a plain `postgresql://test:test@localhost:<port>/test` DSN that asyncpg accepts. Docker Desktop must be running (first run pulls `postgres:17` if it is not cached).

Every case of spec §10 is covered: `COMMIT; DELETE ...`, `WITH x AS (DELETE ...) SELECT`, `nextval()`, a function that inserts, `SELECT ... FOR UPDATE`, DDL, EXPLAIN ANALYZE on DML with read access — each on both a `mode: read` and a `mode: write` connection — plus statement timeout and the `set_config('default_transaction_read_only', 'off', false)` / `COMMIT` session tricks.

- [ ] **Step 1: Write the tests**

Create `tests/integration/helpers.py`:

```python
"""Helpers for integration tests: seed data, config builder and an in-process MCP tool harness."""

from __future__ import annotations

from typing import Any

import asyncpg
from mcp.server.fastmcp import FastMCP

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.postgres.tools import register_postgres_tools
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.tools.common import register_common_tools
from ratatoskr.tools.runtime import ToolRuntime
from tests.fakes import RecordingSink

POSTGRES_IMAGE = "postgres:17"

SEED_SQL = """
DROP TABLE IF EXISTS orders, items CASCADE;
DROP SEQUENCE IF EXISTS ticket_seq;
DROP FUNCTION IF EXISTS add_item();
CREATE TABLE items (id serial PRIMARY KEY, name text NOT NULL UNIQUE, qty int NOT NULL DEFAULT 0);
COMMENT ON TABLE items IS 'Things we sell';
CREATE TABLE orders (id serial PRIMARY KEY, item_id int NOT NULL REFERENCES items(id), amount int CHECK (amount > 0));
CREATE INDEX orders_item_idx ON orders (item_id);
INSERT INTO items (name, qty) VALUES ('apple', 3), ('pear', 5), ('plum', 7);
INSERT INTO orders (item_id, amount) VALUES (1, 2);
CREATE SEQUENCE ticket_seq;
CREATE FUNCTION add_item() RETURNS int LANGUAGE sql AS $$ INSERT INTO items (name) VALUES ('fn') RETURNING id $$;
ANALYZE items;
"""


async def seed(dsn: str) -> None:
    connection = await asyncpg.connect(dsn)
    try:
        await connection.execute(SEED_SQL)
    finally:
        await connection.close()


async def count_items(dsn: str) -> int:
    connection = await asyncpg.connect(dsn)
    try:
        return int(await connection.fetchval("SELECT count(*) FROM items"))
    finally:
        await connection.close()


def make_pg_config(dsn: str, **connection: Any) -> RatatoskrConfig:
    """One connection named 'db' (default mode read, 5s statement timeout); role 'admins' has '*': write."""
    values: dict[str, Any] = {"kind": "postgres", "dsn": dsn, "statement_timeout": "5s"}
    values.update(connection)
    return RatatoskrConfig.model_validate({"roles": {"admins": {"*": "write"}}, "connections": {"db": values}})


class ToolHarness:
    """The real tool stack (runtime, policy, registry, PostgresBackend) behind an in-process FastMCP."""

    def __init__(self, config: RatatoskrConfig, role: str = "admins") -> None:
        self.sink = RecordingSink()
        self.registry = BackendRegistry(config)
        runtime = ToolRuntime(Policy(config), self.registry, StdioPrincipalResolver(role), self.sink)
        self.mcp: FastMCP[Any] = FastMCP("integration")
        register_common_tools(self.mcp, runtime)
        register_postgres_tools(self.mcp, runtime)

    async def call(self, tool: str, **arguments: Any) -> str:
        if tool not in ("list_connections", "connection_health"):
            arguments = {"connection": "db", **arguments}
        result = await self.mcp.call_tool(tool, arguments)
        return result[0].text  # type: ignore[index, union-attr]
```

Create `tests/integration/conftest.py`:

```python
"""A real PostgreSQL in Docker (testcontainers), started once per session; every test reseeds it."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Iterator

import pytest
from testcontainers.community.postgres import PostgresContainer

from ratatoskr.config.models import RatatoskrConfig
from tests.integration.helpers import POSTGRES_IMAGE, ToolHarness, seed


@pytest.fixture(scope="session")
def pg_dsn() -> Iterator[str]:
    with PostgresContainer(POSTGRES_IMAGE, driver=None) as container:
        yield container.get_connection_url()


@pytest.fixture
async def seeded(pg_dsn: str) -> str:
    await seed(pg_dsn)
    return pg_dsn


@pytest.fixture
async def make_harness() -> AsyncIterator[Callable[..., ToolHarness]]:
    created: list[ToolHarness] = []

    def factory(config: RatatoskrConfig, role: str = "admins") -> ToolHarness:
        harness = ToolHarness(config, role)
        created.append(harness)
        return harness

    yield factory
    for harness in created:
        await harness.registry.close_all()
```

Create `tests/integration/test_pg_read_guard.py`:

```python
"""Spec 10: in read mode every one of these must be rejected and the data must stay unchanged."""

from collections.abc import Callable

import pytest

from tests.integration.helpers import ToolHarness, count_items, make_pg_config

pytestmark = pytest.mark.integration

REJECTED_IN_READ_MODE = [
    ("COMMIT; DELETE FROM items", "cannot insert multiple commands into a prepared statement"),
    ("WITH x AS (DELETE FROM items RETURNING *) SELECT * FROM x", "read-only transaction"),
    ("DELETE FROM items", "cannot execute DELETE in a read-only transaction"),
    ("SELECT nextval('ticket_seq')", "cannot execute nextval() in a read-only transaction"),
    ("SELECT add_item()", "cannot execute INSERT in a read-only transaction"),
    ("SELECT * FROM items FOR UPDATE", "cannot execute SELECT FOR UPDATE in a read-only transaction"),
    ("CREATE TABLE evil (id int)", "cannot execute CREATE TABLE in a read-only transaction"),
]


@pytest.mark.parametrize("mode", ["read", "write"])
@pytest.mark.parametrize(("sql", "expected"), REJECTED_IN_READ_MODE)
async def test_pg_query_rejects_writes(
    seeded: str, make_harness: Callable[..., ToolHarness], mode: str, sql: str, expected: str
) -> None:
    harness = make_harness(make_pg_config(seeded, mode=mode))
    text = await harness.call("pg_query", sql=sql)
    assert text.startswith("Error: PostgreSQL error"), text
    assert expected in text
    assert await count_items(seeded) == 3
    assert harness.sink.events[-1].result == "error"


async def test_explain_analyze_on_dml_is_rejected_with_read_access(
    seeded: str, make_harness: Callable[..., ToolHarness]
) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read"))
    text = await harness.call("pg_explain", sql="DELETE FROM items", analyze=True)
    assert "cannot execute DELETE in a read-only transaction" in text
    assert await count_items(seeded) == 3


async def test_explain_without_analyze_never_executes(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read"))
    text = await harness.call("pg_explain", sql="DELETE FROM items WHERE id = $1", params=[1])
    assert "Estimated plan (the statement was not executed)." in text
    assert "Delete on items" in text
    assert await count_items(seeded) == 3


async def test_explain_analyze_select_with_read_access(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read"))
    text = await harness.call("pg_explain", sql="SELECT * FROM items", analyze=True, buffers=True)
    assert "READ ONLY transaction" in text
    assert "actual time=" in text


async def test_session_setting_tricks_do_not_survive(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read", pool={"min_size": 1, "max_size": 1}))
    await harness.call("pg_query", sql="SELECT set_config('default_transaction_read_only', 'off', false)")
    await harness.call("pg_query", sql="COMMIT")
    shown = await harness.call("pg_query", sql="SHOW default_transaction_read_only")
    assert "| on |" in shown
    text = await harness.call("pg_query", sql="DELETE FROM items")
    assert "read-only transaction" in text
    assert await count_items(seeded) == 3


async def test_pg_query_returns_rows_and_respects_max_rows(
    seeded: str, make_harness: Callable[..., ToolHarness]
) -> None:
    harness = make_harness(make_pg_config(seeded, limits={"max_rows": 2}))
    text = await harness.call("pg_query", sql="SELECT name, qty FROM items WHERE qty > $1 ORDER BY id", params=[0])
    assert "Showing the first 2 rows" in text
    assert "| name | qty |" in text
    assert "| apple | 3 |" in text
    assert "plum" not in text
    assert harness.sink.events[-1].rows == 2
    assert harness.sink.events[-1].query_text == "SELECT name, qty FROM items WHERE qty > $1 ORDER BY id"


async def test_bad_parameter_type_is_explained(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded))
    text = await harness.call("pg_query", sql="SELECT * FROM items WHERE id = $1", params=["abc"])
    assert "invalid input for query argument $1" in text


async def test_statement_timeout(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded, statement_timeout="1s"))
    text = await harness.call("pg_query", sql="SELECT pg_sleep(3)")
    assert "canceling statement due to statement timeout" in text
    assert harness.sink.events[-1].result == "timeout"
```

- [ ] **Step 2: Run the tests**

Run: `.venv/Scripts/python -m pytest -m integration tests/integration/test_pg_read_guard.py -q`
Expected: PASS — `21 passed`

These tests target code that already exists, so they are expected to pass on the first run. If one fails, the bug is in the implementation from Tasks 11–16 (fix it there and rerun); never weaken an assertion. Use superpowers:systematic-debugging.

- [ ] **Step 3: Lint**

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 4: Commit**

```bash
git add tests/integration
git commit -m "Add PostgreSQL integration tests for read-mode enforcement" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 20: Integration tests for the write path

**Files:**
- Test: `tests/integration/test_pg_write.py`

Proves: write-level `pg_explain(analyze=true)` on `DELETE` leaves the data unchanged; `pg_execute` commits all statements or none (unique violation in statement 2 rolls back statement 1); two commands in one statement are refused by the protocol; a read-mode connection denies `pg_execute`; a statement timeout inside the batch rolls everything back and is audited as `timeout`.

- [ ] **Step 1: Write the tests**

Create `tests/integration/test_pg_write.py`:

```python
"""Write path: pg_execute atomicity and write-level EXPLAIN ANALYZE that never changes data."""

from collections.abc import Callable

import pytest

from tests.integration.helpers import ToolHarness, count_items, make_pg_config

pytestmark = pytest.mark.integration


async def test_write_explain_analyze_leaves_data_unchanged(
    seeded: str, make_harness: Callable[..., ToolHarness]
) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call("pg_explain", sql="DELETE FROM orders", analyze=True)
    assert "rolled back; no data was changed" in text
    assert "actual time=" in text
    text = await harness.call("pg_explain", sql="DELETE FROM items WHERE id > $1", params=[1], analyze=True)
    assert "rolled back; no data was changed" in text
    assert await count_items(seeded) == 3


async def test_execute_commits_all_statements(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call(
        "pg_execute",
        statements=[
            {"sql": "INSERT INTO items (name, qty) VALUES ($1, $2) RETURNING id, name", "params": ["kiwi", 1]},
            {"sql": "UPDATE items SET qty = qty + 1 WHERE name = $1", "params": ["apple"]},
        ],
    )
    assert "Transaction committed (2 statement(s))." in text
    assert "1. INSERT 0 1" in text
    assert "| 4 | kiwi |" in text
    assert "2. UPDATE 1" in text
    assert await count_items(seeded) == 4
    assert harness.sink.events[-1].rows == 2
    assert harness.sink.events[-1].result == "ok"


async def test_execute_rolls_back_everything_on_failure(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call(
        "pg_execute",
        statements=[
            {"sql": "INSERT INTO items (name) VALUES ('fig')"},
            {"sql": "INSERT INTO items (name) VALUES ('apple')"},
        ],
    )
    assert "Statement 2 of 2 failed" in text
    assert "duplicate key value violates unique constraint" in text
    assert await count_items(seeded) == 3
    assert harness.sink.events[-1].result == "error"


async def test_execute_rejects_multiple_commands_in_one_statement(
    seeded: str, make_harness: Callable[..., ToolHarness]
) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write"))
    text = await harness.call("pg_execute", statements=[{"sql": "DELETE FROM orders; DELETE FROM items"}])
    assert "cannot insert multiple commands into a prepared statement" in text
    assert await count_items(seeded) == 3


async def test_execute_on_read_mode_connection_is_denied(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded, mode="read"))
    text = await harness.call("pg_execute", statements=[{"sql": "DELETE FROM items"}])
    assert text == "Error: Write access required on connection 'db'."
    assert harness.sink.events[-1].result == "denied"
    assert await count_items(seeded) == 3


async def test_write_statement_timeout_rolls_back(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded, mode="write", statement_timeout="1s"))
    text = await harness.call(
        "pg_execute",
        statements=[{"sql": "INSERT INTO items (name) VALUES ('slow')"}, {"sql": "SELECT pg_sleep(3)"}],
    )
    assert "canceling statement due to statement timeout" in text
    assert harness.sink.events[-1].result == "timeout"
    assert await count_items(seeded) == 3
```

- [ ] **Step 2: Run the tests**

Run: `.venv/Scripts/python -m pytest -m integration tests/integration/test_pg_write.py -q`
Expected: PASS — `6 passed`

Expected to pass on the first run. A failure means a bug in `backend.py` / `querying.py`; fix the implementation, not the test.

- [ ] **Step 3: Lint**

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_pg_write.py
git commit -m "Add PostgreSQL integration tests for pg_execute and write explain" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 21: Integration tests for discovery, monitoring and health

**Files:**
- Test: `tests/integration/test_pg_discovery.py`

Exercises every catalog query of `introspection.py` against the seeded schema, `allowed_schemas` filtering, `list_connections` / `connection_health` on a real backend, and an unreachable DSN (`127.0.0.1:1`) whose error must not reveal the password or host.

- [ ] **Step 1: Write the tests**

Create `tests/integration/test_pg_discovery.py`:

```python
"""Discovery and monitoring tools against a real catalog."""

from collections.abc import Callable

import pytest

from tests.integration.helpers import ToolHarness, make_pg_config

pytestmark = pytest.mark.integration


async def test_list_schemas_and_allowed_schemas(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded))
    assert "| public |" in await harness.call("pg_list_schemas")
    limited = make_harness(make_pg_config(seeded, allowed_schemas=["sales"]))
    assert "| public |" not in await limited.call("pg_list_schemas")
    text = await limited.call("pg_list_tables", schema="public")
    assert "Schema 'public' is not available on connection 'db'" in text


async def test_list_tables(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    text = await make_harness(make_pg_config(seeded)).call("pg_list_tables")
    assert "| items | table | 3 |" in text
    assert "Things we sell" in text
    assert "| orders | table |" in text


async def test_describe_table(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded))
    text = await harness.call("pg_describe_table", table="orders")
    assert "## public.orders" in text
    assert "| item_id | integer | no |" in text
    assert "FOREIGN KEY (item_id) REFERENCES items(id)" in text
    assert "CHECK ((amount > 0))" in text
    assert "orders_item_idx" in text
    items = await harness.call("pg_describe_table", table="items")
    assert "### Referenced by" in items
    assert "| orders | orders_item_id_fkey |" in items


async def test_describe_missing_table(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    text = await make_harness(make_pg_config(seeded)).call("pg_describe_table", table="ghost")
    assert text == "Error: Table 'public.ghost' not found on 'db'. Use pg_list_tables to see what exists."


async def test_table_stats(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded))
    summary = await harness.call("pg_table_stats")
    assert "| table | total_size | live_rows |" in summary
    assert "| items |" in summary
    one = await harness.call("pg_table_stats", table="items")
    assert "## Statistics: public.items" in one
    assert "- **seq_scan:**" in one


async def test_activity_and_server_info(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded))
    activity = await harness.call("pg_activity")
    assert "## Active sessions on 'db'" in activity
    assert "## Waiting locks (0)" in activity
    info = await harness.call("pg_server_info")
    assert "- **version:** PostgreSQL 17" in info
    assert "| test | test | UTF8 |" in info


async def test_health_and_list_connections(seeded: str, make_harness: Callable[..., ToolHarness]) -> None:
    harness = make_harness(make_pg_config(seeded, description="Seeded test DB"))
    assert "| db | postgres | read | Seeded test DB |" in await harness.call("list_connections")
    health = await harness.call("connection_health")
    assert "| db | postgres | ok |" in health
    assert "PostgreSQL 17" in health


async def test_unreachable_connection_reports_without_leaking(make_harness: Callable[..., ToolHarness]) -> None:
    dsn = "postgresql://ratatoskr:hunter2@127.0.0.1:1/nowhere"
    harness = make_harness(make_pg_config(dsn))
    text = await harness.call("pg_query", sql="SELECT 1")
    assert "Connection 'db' is unavailable" in text
    assert "hunter2" not in text
    assert "127.0.0.1" not in text
```

- [ ] **Step 2: Run the tests**

Run: `.venv/Scripts/python -m pytest -m integration tests/integration/test_pg_discovery.py -q`
Expected: PASS — `8 passed`

Expected to pass on the first run. A failing assertion on table text usually means a column alias or ordering in `introspection.py` changed; fix the SQL, not the test.

Then run the whole integration suite once:

Run: `.venv/Scripts/python -m pytest -m integration -q`
Expected: `35 passed` plus the deselected unit tests.

- [ ] **Step 3: Lint**

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_pg_discovery.py
git commit -m "Add PostgreSQL integration tests for discovery and health" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 22: Example config, README, repo CLAUDE.md, remove Railway and .env files

**Files:**
- Create: `config.example.yaml`, `CLAUDE.md`
- Modify: `README.md` (full replacement)
- Delete: `.env.example`, `railway.json`
- Test: `tests/unit/test_example_config.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_example_config.py`:

```python
from pathlib import Path

from ratatoskr.config.loader import load_config

EXAMPLE = Path(__file__).resolve().parents[2] / "config.example.yaml"


def test_example_config_is_valid() -> None:
    config = load_config(EXAMPLE, env={"APP_DB_DSN": "postgresql://reader:pw@localhost:5432/app"})
    assert config.server.transport == "stdio"
    assert config.server.stdio_role == "admins"
    assert list(config.connections) == ["app-db"]
    assert config.connections["app-db"].mode == "read"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv/Scripts/python -m pytest tests/unit/test_example_config.py -q`
Expected: FAIL — `ratatoskr.config.loader.ConfigError: cannot read config file ...config.example.yaml: ...`

- [ ] **Step 3: Write the implementation**

The example must stay valid: the test loads it with a fake `APP_DB_DSN`.

Create `config.example.yaml`:

```yaml
# Ratatoskr configuration.
# Secrets never go in this file: reference them as ${ENV_VAR} or ${file:/path/to/secret}.
# An undefined variable is an error. Validate with:  ratatoskr check-config --config config.yaml

server:
  transport: stdio            # streamable-http (remote, with OAuth login) arrives in the next release
  stdio_role: admins          # over stdio you act as a member of this group (see roles)
  log_level: INFO             # logs go to stderr as JSON

# group -> { connection name or "*": read | write }
# Effective access = the highest grant of your groups, capped by the connection's mode.
roles:
  admins: { "*": write }

connections:
  app-db:                     # lowercase letters, digits, '-' and '_'
    kind: postgres
    description: "Application database"
    mode: read                # read (default) | write; only write connections accept pg_execute
    dsn: ${APP_DB_DSN}        # postgresql://user:password@host:5432/dbname
    statement_timeout: 30s
    pool: { min_size: 1, max_size: 5 }
    # allowed_schemas: [public]   # limits discovery tools only, not free SQL in pg_query
    # tls: { mode: verify-full, ca_file: /config/certs/app-db-ca.pem }
    # limits: { max_rows: 500, max_response_bytes: 65536, max_query_length: 20000 }

  # staging-db:
  #   kind: postgres
  #   description: "Staging database (writable)"
  #   mode: write
  #   dsn: ${STAGING_DB_DSN}
```

Replace `README.md` completely:

````markdown
# Ratatoskr

Ratatoskr is an MCP server that gives Claude (Claude Desktop, Claude Code, claude.ai connectors) safe access to
**several PostgreSQL databases at once**, with per-group access levels and an audit trail. Prometheus and Loki
backends are planned.

> **Status: 1.0.0.dev0.** This release runs over **stdio** (local). The remote HTTP transport with OAuth login
> (local users or OIDC such as Authentik) arrives in the next release. Coming from `claude-postgresql` 0.1?
> The `PG_MCP_*` environment variables are gone; everything lives in one YAML file.

## Features

- Any number of named PostgreSQL connections in one server; the tool set stays the same (11 tools).
- Access per group: `read` or `write`, capped by each connection's `mode`. Unknown and forbidden connections
  look identical ("Connection 'x' not found.").
- Reads are enforced by PostgreSQL itself: read-only sessions, single-statement prepared statements and
  `READ ONLY` transactions that are always rolled back. `pg_explain(analyze=true)` never changes data.
- Every tool call is audited (JSON log line on stderr with `event: audit`).
- Responses are clamped (rows and bytes) with an explicit note on how to narrow the request.

## Quick start (stdio)

```bash
pip install -e .                      # or: uv pip install -e .
cp config.example.yaml config.yaml    # edit connections and roles
export APP_DB_DSN='postgresql://readonly_user:password@localhost:5432/app'
ratatoskr check-config --config config.yaml
```

`check-config` validates the file and prints a summary without any secret. Secrets are never written in the
YAML file: use `${ENV_VAR}` or `${file:/run/secrets/name}`; an undefined variable is an error.

### Claude Desktop

```json
{
  "mcpServers": {
    "ratatoskr": {
      "command": "ratatoskr",
      "args": ["serve", "--config", "/absolute/path/to/config.yaml"],
      "env": { "APP_DB_DSN": "postgresql://readonly_user:password@localhost:5432/app" }
    }
  }
}
```

### Claude Code

```bash
claude mcp add ratatoskr -e APP_DB_DSN='postgresql://readonly_user:password@localhost:5432/app' \
  -- ratatoskr serve --config /absolute/path/to/config.yaml
```

The config path can also come from `RATATOSKR_CONFIG` (default `/config/config.yaml`).

## Tools

| Tool | Access | What it does |
|---|---|---|
| `list_connections` | - | Connections you may use, their kind, description and your access level. Call it first. |
| `connection_health` | read | Reachability, latency and server version of one or all of your connections. |
| `pg_list_schemas` | read | Non-system schemas (filtered by `allowed_schemas`). |
| `pg_list_tables` | read | Tables and views of a schema with estimated rows and size. |
| `pg_describe_table` | read | Columns, constraints (PK/FK/unique/check), incoming FKs and indexes in one call. |
| `pg_query` | read | One read-only statement; rows as a Markdown table. |
| `pg_execute` | write | One or more statements in a single atomic transaction. |
| `pg_explain` | read / write | Plan; `analyze=true` runs it in a transaction that is always rolled back. |
| `pg_activity` | read | Active sessions and waiting locks. |
| `pg_table_stats` | read | Size, scans, live/dead tuples, vacuum and analyze times. |
| `pg_server_info` | read | Version, current database and size, database list. |

## Security model

- Effective access = `min(max(grants of your groups), connection.mode)`; no grant means no access. Over stdio
  you act as a member of `server.stdio_role`.
- The **real boundary is the database role** in each DSN. Give every connection a role with only the grants it
  needs (for read connections: `CONNECT`, `USAGE` and `SELECT`). A read-only transaction does not stop
  extensions that open their own connections (`dblink`, `postgres_fdw`); only the role can.
- `allowed_schemas` filters the discovery tools only; it does not restrict SQL sent to `pg_query`.
- Error messages never contain the DSN, host or password.

## Development

```bash
pip install --index-url https://pypi.org/simple -e ".[dev]"
python -m pytest tests/unit -q          # unit tests, no network
python -m pytest -m integration -q      # needs Docker: starts PostgreSQL with testcontainers
python -m ruff check src tests
python -m mypy src
```

See `CLAUDE.md` for project conventions.

## License

MIT
````

Create `CLAUDE.md`:

```markdown
# Ratatoskr: repo conventions

Multi-connection MCP server (`src/ratatoskr`, PyPI `ratatoskr-mcp`, CLI `ratatoskr`). Design:
`docs/superpowers/specs/2026-11-21-multi-backend-redesign-design.md`; shared interfaces for stage 1:
`docs/superpowers/plans/2026-11-21-phase1-interfaces.md`.

## Commands (Windows, repo root)

- Unit tests (no network): `.venv/Scripts/python -m pytest tests/unit -q`
- Integration tests (Docker Desktop running; testcontainers starts `postgres:17`):
  `.venv/Scripts/python -m pytest -m integration -q`
- Lint: `.venv/Scripts/python -m ruff check src tests`
- Types: `.venv/Scripts/python -m mypy src`
- Validate a config: `.venv/Scripts/ratatoskr check-config --config config.yaml`
- Installing packages: pip's extra index on this machine is broken and slow; always pass
  `--index-url https://pypi.org/simple`.

Plain `pytest` skips integration tests (`addopts = -m 'not integration'`); `-m integration` selects them.

## Layout

- `config/` YAML loading (`loader.py`: `${VAR}`, `${file:/path}`), pydantic models (`models.py`), durations.
- `auth/` `Principal`, `Policy` (effective access), principal resolvers.
- `backends/` `Backend` protocol, `BackendRegistry` (lazy open, 10 s retry), user-safe errors, `clamp_text`.
- `backends/postgres/` pools and execution (`backend.py`), guard pre-checks, catalog SQL (`introspection.py`),
  query/execute/explain (`querying.py`), tool registration (`tools.py`) and tool texts (`descriptions.py`).
- `tools/runtime.py` the one wrapper every tool goes through; `tools/common.py` backend-independent tools.
- `observability/` audit events and sinks, JSON logging, secret redaction.
- `app.py` builds the FastMCP app; `cli.py` is the entry point.

## Rules

- Python 3.12+, `from __future__ import annotations`, full type hints; `ruff` (line length 120) and
  `mypy --strict` must stay clean. One responsibility per file; keep files small.
- Every tool call goes through `ToolRuntime.run` / `run_global`: identity, policy, deadline, clamping and audit
  live there and nowhere else.
- Unknown and forbidden connections must produce the identical `ConnectionNotFoundError` message.
- Text shown to the client may only come from `BackendError` subclasses, policy errors or PostgreSQL server
  messages. Anything else becomes a generic message and the details go to the log. Never put a DSN, host or
  password in a message; `observability.redact` is a last line of defence, not the mechanism.
- PostgreSQL read path: user SQL only through the read pool, inside `ReadSession` (READ ONLY transaction,
  always rolled back) and only via the extended protocol (`fetch`, `prepare`). Never pass user SQL to
  `connection.execute(sql)` without arguments: that is the simple protocol and accepts several statements.
  Session settings that must survive the pool's `RESET ALL` go in `server_settings`, not in `SET`.
- The write pool is only for `mode: write` connections and only used by `pg_execute` and write-level
  `pg_explain(analyze=true)` (always rolled back).
- Tool descriptions in `descriptions.py` / `tools/common.py` are product UX for the LLM: short, say what comes
  back, when to use the tool, the limits, and that `connection` comes from `list_connections`.
- Tests: unit tests must not touch the network or Docker (use `tests/fakes.py`). Anything that needs a real
  PostgreSQL goes in `tests/integration/` with `pytestmark = pytest.mark.integration`.
- Commits: imperative subject line; end the message with the agreed `Co-Authored-By` trailer.
```

Delete the env-based example and the Railway file (`git rm` stages the deletions for the commit):

```bash
git rm .env.example railway.json
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.venv/Scripts/python -m pytest tests/unit/test_example_config.py -q`
Expected: PASS — `1 passed`

Run: `.venv/Scripts/python -m ruff check src/ratatoskr tests/unit tests/integration tests/fakes.py`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src/ratatoskr`
Expected: `Success: no issues found in N source files`

- [ ] **Step 5: Commit**

```bash
git add config.example.yaml README.md CLAUDE.md tests/unit/test_example_config.py
git commit -m "Document YAML config and stdio quick start; drop Railway files" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 23: Remove the old claude_postgresql package and run full verification

**Files:**
- Delete: `src/claude_postgresql/` (all files: `__init__.py`, `auth.py`, `config.py`, `database.py`,
  `formatters.py`, `logging_config.py`, `query_history.py`, `security.py`, `server.py`, `tools/`)
- Delete: `tests/conftest.py`, `tests/test_auth.py`, `tests/test_config.py`, `tests/test_formatters.py`,
  `tests/test_security.py`

Everything useful has been moved and adapted: formatters → `backends/postgres/formatting.py`; the catalog SQL of
`tools/schema.py`, `tools/admin.py`, `tools/database_info.py` → `backends/postgres/introspection.py`; pool and
transaction code of `database.py` → `backends/postgres/backend.py`; the dangerous-pattern list of `security.py`
→ `backends/postgres/guard.py`; `logging_config.py` → `observability/logging.py`; `query_history.py` is replaced
by the audit sink (spec §3.1). `auth.py` (single-password OAuth) is superseded by Plan 1b.

- [ ] **Step 1: Confirm nothing outside the old package imports it**

Run: `grep -rn "claude_postgresql" src/ratatoskr tests/unit tests/integration tests/fakes.py pyproject.toml`
Expected: no output.

- [ ] **Step 2: Delete the old package and tests**

```bash
git rm -r src/claude_postgresql
git rm tests/conftest.py tests/test_auth.py tests/test_config.py tests/test_formatters.py tests/test_security.py
```

- [ ] **Step 3: Full verification**

Run: `.venv/Scripts/python -m pytest -q`
Expected: `200 passed, 35 deselected`

Run: `.venv/Scripts/python -m pytest -m integration -q`
Expected: `35 passed, 200 deselected`

Run: `.venv/Scripts/python -m ruff check src tests`
Expected: `All checks passed!`

Run: `.venv/Scripts/python -m mypy src`
Expected: `Success: no issues found in 33 source files`

Run (secret must not be printed):
```bash
APP_DB_DSN='postgresql://reader:hunter2@localhost:5432/app' .venv/Scripts/ratatoskr check-config --config config.example.yaml
```
Expected:
```
Config OK: config.example.yaml
transport: stdio
stdio_role: admins
auth: none
roles (1): admins
connections (1):
  - app-db: postgres, mode=read  Application database
```

Run: `.venv/Scripts/ratatoskr check-config --config config.example.yaml; echo "exit=$?"` (without `APP_DB_DSN`)
Expected: `Config error: ... connections.app-db.dsn: environment variable 'APP_DB_DSN' is not defined` and `exit=2`.

- [ ] **Step 4: Optional manual stdio smoke test (local container only)**

Start a throwaway database: `docker run --rm -d --name rtsk-pg -e POSTGRES_PASSWORD=pw -p 55432:5432 postgres:17`,
then `claude mcp add ratatoskr-dev -e APP_DB_DSN='postgresql://postgres:pw@localhost:55432/postgres' --
$(pwd)/.venv/Scripts/ratatoskr serve --config $(pwd)/config.example.yaml` and ask Claude Code to call
`list_connections` and `pg_server_info`. Remove afterwards with `claude mcp remove ratatoskr-dev` and
`docker stop rtsk-pg`.

- [ ] **Step 5: Commit**

```bash
git add -A src tests
git commit -m "Remove the claude_postgresql package" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Self-review against the spec (stage 1a)

| Requirement | Where |
|---|---|
| §2 names: module `ratatoskr`, PyPI `ratatoskr-mcp`, CLI `ratatoskr`, `RATATOSKR_CONFIG` | Tasks 1, 18 |
| §3.1 layout, one responsibility per file; old `server.py` split | File structure, Task 23 |
| §3.2 Backend protocol, wrapper per call | Tasks 6, 13 |
| §3.3 identical not-found message, audit fields, truncation note | Tasks 7, 13, 6 |
| §3.4 lazy open, 10 s retry, close at lifespan end | Tasks 12, 17 |
| §4 YAML, `${VAR}`, `${file:}`, undefined → error, check-config without secrets, validation rules | Tasks 2–4, 18 |
| §5.1 effective access, deny by default, `mode: read` caps admins | Task 7 |
| §5.5 stdio principal with `stdio_role` | Task 7 |
| §6.1 / §6.2 eleven tools, annotations, `connection` first | Tasks 15–17 |
| §6.2 guard layers 1–3 and 5, pg_explain semantics | Tasks 9, 11, 14, 19, 20 |
| §6.5 limits (500 rows, 64 KB), explicit truncation, no DSN/host in errors | Tasks 3, 6, 13, 14 |
| §10 unit: config, interpolation, policy matrix, limits, log masking | Tasks 2–7 |
| §10 integration: every listed PostgreSQL case | Tasks 19–20 |
| §9 `railway.json` removed; README/CLAUDE.md minimal | Task 22 |
