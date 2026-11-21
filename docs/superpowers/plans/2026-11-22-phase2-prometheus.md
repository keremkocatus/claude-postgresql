# Stage 2 — Prometheus backend Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `kind: prometheus` connections next to the PostgreSQL ones: five read-only tools (`prom_query`,
`prom_query_range`, `prom_list_metrics`, `prom_label_values`, `prom_alerts`) that go through `ToolRuntime`, return
compact text with explicit truncation notes, never leak credentials or internal hosts, and work against Prometheus and
Prometheus-compatible APIs (Mimir, Thanos Query, VictoriaMetrics).

**Architecture:** A new connection model (`config/prometheus_models.py`) built on shared HTTP connection models
(`config/http_models.py`: auth none/basic/bearer, headers, TLS) joins the `ConnectionConfig` union. The registry's
default factory builds a `PrometheusBackend` for it: one lazily created `httpx.AsyncClient` per connection
(`backends/http/client.py`: auth, headers, TLS, deadline, body cap while reading, user-safe transport errors), a thin
endpoint layer (`backends/prometheus/api.py`: Prometheus error envelope → `BackendError`, scrubbed server messages) and
one module per tool family (querying, discovery, alerts) that parses, summarises and formats. Times and steps are parsed
by a shared `backends/timeparse.py` that Loki (stage 3) reuses together with `config/http_models.py` and
`backends/http/`. `ToolRuntime.run` gains two optional arguments: `kind` (refuse a wrong-kind connection after
authorization, before opening it) and `truncation_hint` (per-kind advice in the clamp note).

**Tech Stack:** Python 3.12+, mcp 1.30 (FastMCP), httpx 0.28 (already a dependency), pydantic v2; tests with
pytest-asyncio (auto mode), respx 0.23 (already a dev dependency) and testcontainers 4.15 (`DockerContainer`,
`HttpWaitStrategy`, `with_copy_into_container`) running `prom/prometheus:v3.16.0`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-21-multi-backend-redesign-design.md` (§3.1 layout, §4 config, §6.3
Prometheus tools, §6.5 common rules, §10 tests, §12 stage 2).
**Contract:** `docs/superpowers/plans/2026-11-21-phase1-interfaces.md` (incl. its notes sections). Nothing in it changes;
this plan adds to it (Task 16 records the additions there).
**Baseline:** `design/multi-backend-redesign` at `00e3bc8`: 1261 unit tests passed (4 skipped), 143 integration tests,
ruff/mypy clean. Repo conventions: `CLAUDE.md` (binding).

**How this plan was verified:** every task was applied in order to a copy of the baseline tree (outside the repo).
Final state: **1473 unit tests passed** (4 skipped), ruff check + ruff format + `mypy --strict` clean, and the 11 new
integration tests passed against a real Prometheus 3.16.0 container. The intermediate tree after Task 7 was also checked
on its own (mypy, ruff, unit suite). All code blocks below are the verified files, formatted with `ruff format`.

---

## Decisions (where the spec left room)

1. **Prometheus connections are read-only by construction.** `PrometheusConnection.mode` is `Literal["read"]` with a
   before-validator: `mode: write` is a config error ("prometheus connections are read-only: omit mode or set it to
   read"). Every tool is a read of the HTTP API, so `write` would grant nothing and would make `list_connections`
   show a misleading `write`. `Policy` is unchanged: `min(grant, mode)` caps every principal at `read`.
2. **Tool signatures.** `prom_query(connection, promql, time?)`; `prom_query_range(connection, promql, start?, end?,
   step?)` — start/end are optional because spec §6.5 sets the default range to the last hour;
   `prom_list_metrics(connection, name_contains?, match?, start?, end?)` — `name_contains` (case-insensitive substring,
   applied client-side) is added next to the spec's `match` selector because an LLM looks for "metrics about http",
   not for a regex selector; `prom_label_values(connection, label, match?, start?, end?)`; `prom_alerts(connection)`.
   Names and label values are listed for a window (default last hour): cheap on Thanos/Mimir and "metrics with data
   now" is what an investigation needs.
3. **Limits** (`connections.<name>.limits`): `max_series: 100` (series per response, also alerts — each alert is an
   `ALERTS` series), `max_values: 500` (metric names, label values), `max_points: 1000` per series in a range query
   (≤ Prometheus' own 11,000), `max_range: 31d`, `max_query_length: 20000`, `max_response_bytes: 65536` (the shared
   runtime clamp; formatting stays 1 KiB under it so notes are never the part that is cut), `max_body_bytes: 16 MiB`
   (read cap while streaming the Prometheus answer).
4. **Step.** Without `step`, the smallest "round" step (1s, 2s, 5s, 10s, 15s, 30s, 1m … 12h, 1d, then whole days) that
   gives at most ~120 points (60–121 in practice). An explicit step that exceeds `max_points` is **refused** with the
   minimum step that fits (not silently raised): the summary statistics would otherwise describe a resolution the
   caller did not ask for.
5. **Range output.** Per series: point count, steps without data, NaN count, min/max (exact strings from
   Prometheus), avg (6 significant digits), last value and time, plus evenly spaced samples: 60 per series for up to 4
   series, shrinking to 6 (a shared budget of 240). Instant queries of a range vector (`up[5m]`) use the same block
   with raw samples.
6. **Transport.** `query` and `query_range` are `POST` form requests (long PromQL, PromQL stays out of proxy URL logs;
   Prometheus, Mimir, Thanos and VictoriaMetrics accept it); the rest are `GET`. The connection `timeout` (default 30s,
   1s–10m) is also sent as Prometheus' `timeout` parameter; the client deadline is `timeout + 5s` so the server's
   clearer message arrives first. No `limit` parameter is sent (older and compatible servers ignore or reject it, and
   the total count is part of the truncation note); `max_body_bytes` protects memory instead. Redirects are not
   followed. At most 10 pooled HTTP connections per Prometheus connection.
7. **Lifecycle.** `open()` only creates the httpx client (no request): an unreachable server surfaces on the first call
   as "Connection 'x' is unavailable (ConnectError); details are in the server log." `close()` is final and runs from
   `registry.close_all()` (stdio lifespan / HTTP process lifespan, unchanged ownership rule). Health uses
   `/api/v1/status/buildinfo` ("Prometheus 3.16.0"); servers without it (HTTP 404) are probed with `query=1`
   ("Prometheus API").
8. **Errors.** Prometheus' `errorType`/`error` are shown (`Error: Prometheus error (bad_data): 1:4: parse error …`);
   `timeout`/`canceled` become `BackendTimeoutError` (audit `timeout`). Server messages, warnings, infos and a rule's
   `lastError` pass through `scrub_upstream_text` first: URLs, IPv4/IPv6 addresses, `host:port`, `*.svc`/
   `*.cluster.local`/`*.internal`-style names and the connection's own host are replaced. Non-API answers (401/403,
   404, 429, 3xx, 5xx, HTML login pages) get fixed wording; details go to the log. Successful output is user data and
   is never scrubbed or redacted.
9. **Runtime.** `ToolRuntime.run(..., kind=None, truncation_hint=TRUNCATION_HINT)`. Prometheus tools pass
   `kind="prometheus"`: a PostgreSQL connection is refused *after* authorization (a forbidden connection still reads
   "not found") and *before* the registry opens it. PostgreSQL tools are not changed (they keep their isinstance check).
10. **Proxies and trust.** Like the OIDC client, httpx's environment handling stays on: `HTTPS_PROXY`/`HTTP_PROXY`/
    `NO_PROXY` apply (document: put in-cluster hosts in `NO_PROXY`). The default trust store is httpx's
    (`httpx.create_ssl_context()`: certifi, or `SSL_CERT_FILE`/`SSL_CERT_DIR`), built **once per process** (it costs
    ~0.5 s); `tls.ca_file` trusts only that CA; `tls.verify: false` disables verification. Client certificates (mTLS)
    are not supported in this stage.
11. **Secrets in config.** `auth.token`, `auth.password` and every header value are `SecretStr`; empty secrets are
    rejected; `Authorization`, `Proxy-Authorization`, `Host`, `Content-Length`, `Content-Type`, `Transfer-Encoding`,
    `Connection` cannot be set under `headers`; header values with CR/LF/NUL are rejected; numeric YAML header values
    (`X-Scope-OrgID: 42`) are turned into text; `url` must not carry credentials, a query string or a fragment.
    pydantic's "Input tag '…' found" message (which repeats a wrong `kind:`/`auth.type:` value, possibly a misplaced
    `${SECRET}`) is rewritten by the loader to "unknown value; expected one of …". `check-config` prints
    `auth: bearer, extra headers: 1`, never the URL, token or header values, and warns when credentials go over plain
    `http` to a non-loopback host.
12. **Logs.** httpx logs every request line (URL with query string: internal host, label matchers) at INFO; like the MCP
    per-request logger it is set to WARNING when `log_level` is INFO.
13. **Label names** for `prom_label_values` must match `^[A-Za-z_][A-Za-z0-9_]*$` (Prometheus 3's quoted UTF-8 names
    are out of scope); the name is URL-quoted anyway.

## Risks and notes

- **PromQL is not restricted.** Any principal with read access can run any query, including expensive ones (high
  cardinality selectors, long subqueries). The API is read-only, so the risk is load, not data change. Cost control:
  `max_range`, `max_points`, the server-side `timeout` parameter, the client deadline, `max_body_bytes` while reading,
  and the output caps. Operators should keep Prometheus' own guards (`--query.timeout`, `--query.max-samples`,
  `--query.max-concurrency`) and, on Mimir/Thanos, their per-tenant query limits. Document this in the README.
- **Compatibility.** Mimir/Cortex: `url` includes the `/prometheus` prefix (the client keeps the base path:
  `<url>/api/v1/...`), tenant via `headers: {X-Scope-OrgID: ...}`. Thanos Query: alerts/rules need the rules API
  (Thanos Ruler/sidecar); metadata comes through the StoreAPI and may be partial. VictoriaMetrics: metadata may be empty
  (the tool says so and still lists names); `/api/v1/alerts` and `/api/v1/rules` exist only with `-vmalert.proxyURL`,
  otherwise `prom_alerts` shows "Rule groups are unavailable: …" or an error. `buildinfo` missing → health still works.
- **Scrubbing is best effort.** It is pattern based; it is a filter for server messages, not a security boundary. The
  boundary is: no credential or configured URL is ever put into a message by Ratatoskr itself.
- **Proxy environment.** With `HTTP(S)_PROXY` set and no `NO_PROXY`, requests to in-cluster Prometheus go through the
  proxy. Documented; same behaviour as the OIDC client.
- **Clock.** Relative times use the server's clock (UTC); in the Docker Desktop VM the clock can drift slightly from
  Prometheus' — harmless for `now-…` windows.
- **Pulling the image.** The integration fixture needs `prom/prometheus:v3.16.0` (Docker Hub). The first run pulls it;
  everything else stays on 127.0.0.1.

## File structure

New (src):

| File | Responsibility |
|---|---|
| `src/ratatoskr/config/shared.py` | `DEFAULT_MAX_RESPONSE_BYTES`, `duration_value` (moved out of `models.py`, shared by all kinds) |
| `src/ratatoskr/config/http_models.py` | `NoAuth`/`BasicAuth`/`BearerAuth` (`HttpAuth`), `HttpTlsSettings`, URL and header checks (Loki reuses) |
| `src/ratatoskr/config/prometheus_models.py` | `PrometheusLimits`, `PrometheusConnection` |
| `src/ratatoskr/backends/timeparse.py` | RFC3339 / unix / `now-15m` parsing, ranges, auto step, formatting (Loki reuses) |
| `src/ratatoskr/backends/http/__init__.py` | package marker |
| `src/ratatoskr/backends/http/options.py` | config → httpx: auth headers, `httpx.Auth`, TLS verify (cached default context) |
| `src/ratatoskr/backends/http/client.py` | `HttpClient`: lifecycle, deadline, capped read, safe transport/status errors |
| `src/ratatoskr/backends/http/scrub.py` | remove addresses from upstream server messages |
| `src/ratatoskr/backends/prometheus/__init__.py` | package marker |
| `src/ratatoskr/backends/prometheus/api.py` | the read endpoints and the error envelope mapping |
| `src/ratatoskr/backends/prometheus/backend.py` | `PrometheusBackend` (Backend protocol: open/close/health/describe) |
| `src/ratatoskr/backends/prometheus/series.py` | parse query results; series names |
| `src/ratatoskr/backends/prometheus/formatting.py` | `BlockWriter`, truncation notes, cells, instant results |
| `src/ratatoskr/backends/prometheus/summarize.py` | range summaries and sampled points |
| `src/ratatoskr/backends/prometheus/querying.py` | `prom_query` / `prom_query_range` logic |
| `src/ratatoskr/backends/prometheus/discovery.py` | `prom_list_metrics` / `prom_label_values` logic |
| `src/ratatoskr/backends/prometheus/alerts.py` | `prom_alerts` logic |
| `src/ratatoskr/backends/prometheus/descriptions.py` | tool and argument texts (LLM UX) |
| `src/ratatoskr/backends/prometheus/tools.py` | `register_prometheus_tools` |

Modified (src): `config/models.py` (shared imports, union), `config/loader.py` (kind tag, tag message),
`config/notices.py` (plain-http warning), `cli.py` (summary), `backends/limits.py` (`clip_input`),
`backends/registry.py` (factory), `tools/runtime.py` (`kind`, `truncation_hint`), `tools/common.py`
(`list_connections` text), `observability/logging.py` (httpx logger), `app.py` (registration, instructions).

Tests: new `tests/unit/test_config_http_models.py`, `test_config_prometheus.py`, `test_timeparse.py`,
`test_http_scrub.py`, `test_http_client.py`, `prom_helpers.py`, `test_prom_api.py`, `test_prom_backend.py`,
`test_prom_wiring.py`, `test_prom_check_config.py`, `test_prom_formatting.py`, `test_prom_summarize.py`,
`test_prom_querying.py`, `test_prom_discovery.py`, `test_prom_alerts.py`, `test_prom_tools.py`,
`tests/integration/test_prom_tools.py`; modified `tests/fakes.py`, `tests/unit/conftest.py`, `test_runtime.py`,
`test_limits.py`, `test_redact_and_logging.py`, `test_app.py`, `test_cli.py`, `test_example_config.py`,
`tests/integration/conftest.py`, `tests/integration/helpers.py`.

Docs: `config.example.yaml`, `README.md`, `CLAUDE.md`, `pyproject.toml` (description, marker text),
`docs/superpowers/plans/2026-11-21-phase1-interfaces.md` (stage 2 additions).

Every unit test uses respx (`respx.mock(base_url=PROM_URL)`, which also fails any unmatched request) or pure functions:
no network, no Docker. Run single files with `.venv/Scripts/python -m pytest <file> -q`.

---

### Task 0: Preflight

- [ ] **Step 1: Confirm the baseline**

Run: `git status --short` (clean), `git log --oneline -1` (`00e3bc8` or a descendant on
`design/multi-backend-redesign`), then

```
.venv/Scripts/python -m pytest -q
.venv/Scripts/python -m ruff check src tests
.venv/Scripts/python -m ruff format --check src tests
.venv/Scripts/python -m mypy src
```

Expected: `1261 passed, 4 skipped, 143 deselected`; ruff and mypy report no issues. If the counts differ, note the new
baseline and continue (the deltas below are additive).

- [ ] **Step 2: Confirm the libraries this plan relies on**

Run: `.venv/Scripts/python -m pip show httpx respx testcontainers` — expect httpx 0.28.x, respx 0.23.x, testcontainers
4.x (≥ 4.10: `testcontainers.core.wait_strategies.HttpWaitStrategy` and `DockerContainer.with_copy_into_container`).

---

### Task 1: Shared config pieces and HTTP connection models

**Files:**
- Create: `src/ratatoskr/config/shared.py`, `src/ratatoskr/config/http_models.py`
- Modify: `src/ratatoskr/config/models.py`, `src/ratatoskr/backends/registry.py:15`
- Test: `tests/unit/test_config_http_models.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_config_http_models.py`:

```python
from pathlib import Path
from typing import Any

import pytest
from pydantic import AnyHttpUrl, BaseModel, SecretStr, ValidationError

from ratatoskr.config.http_models import (
    BasicAuth,
    BearerAuth,
    HttpAuth,
    HttpTlsSettings,
    NoAuth,
    check_base_url,
    check_headers,
    stringify_header_values,
)

SECRET = "s3cr3t-VALUE-never-shown"


class _Holder(BaseModel):
    auth: HttpAuth


def _messages(exc: ValidationError) -> str:
    return " | ".join(str(error["msg"]) for error in exc.errors(include_input=False, include_url=False))


def test_auth_variants() -> None:
    assert isinstance(_Holder.model_validate({"auth": {"type": "none"}}).auth, NoAuth)
    basic = _Holder.model_validate({"auth": {"type": "basic", "username": "u", "password": "p"}}).auth
    assert isinstance(basic, BasicAuth)
    assert basic.password.get_secret_value() == "p"
    bearer = _Holder.model_validate({"auth": {"type": "bearer", "token": SECRET}}).auth
    assert isinstance(bearer, BearerAuth)
    assert SECRET not in repr(bearer)


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        ({"type": "bearer", "token": ""}, "auth.token must not be empty"),
        ({"type": "basic", "username": "u", "password": ""}, "auth.password must not be empty"),
        ({"type": "basic", "username": "a:b", "password": "p"}, "auth.username must not contain ':'"),
        ({"type": "bearer", "token": SECRET, "extra": SECRET}, "Extra inputs are not permitted"),
    ],
)
def test_auth_errors_never_echo_values(auth: dict[str, Any], expected: str) -> None:
    with pytest.raises(ValidationError) as caught:
        _Holder.model_validate({"auth": auth})
    assert expected in _messages(caught.value)
    assert SECRET not in _messages(caught.value)


def test_tls_defaults_and_ca_file(tmp_path: Path) -> None:
    assert HttpTlsSettings() == HttpTlsSettings(verify=True, ca_file=None)
    ca = tmp_path / "ca.pem"
    ca.write_text("pem", encoding="utf-8")
    assert HttpTlsSettings(ca_file=ca).ca_file == ca
    with pytest.raises(ValidationError, match="does not exist"):
        HttpTlsSettings(ca_file=tmp_path / "missing.pem")
    with pytest.raises(ValidationError, match="no effect with tls.verify: false"):
        HttpTlsSettings(verify=False, ca_file=ca)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (f"http://user:{SECRET}@prometheus:9090", "must not contain credentials"),
        ("http://prometheus:9090/?token=x", "must not contain a query string or fragment"),
        ("http://prometheus:9090/#top", "must not contain a query string or fragment"),
    ],
)
def test_base_url_rules(url: str, expected: str) -> None:
    with pytest.raises(ValueError, match=expected) as caught:
        check_base_url(AnyHttpUrl(url))
    assert SECRET not in str(caught.value)


def test_base_url_with_a_path_prefix_is_fine() -> None:
    assert str(check_base_url(AnyHttpUrl("https://mimir.example.com/prometheus"))).endswith("/prometheus")


def test_header_values_are_stringified_before_validation() -> None:
    assert stringify_header_values({"X-Scope-OrgID": 42, "X-Flag": True, "X-Name": "a"}) == {
        "X-Scope-OrgID": "42",
        "X-Flag": True,
        "X-Name": "a",
    }
    assert stringify_header_values(None) is None


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"Bad Name": SECRET}, "entry 0 is not a valid header name"),
        ({"Authorization": SECRET}, "Authorization cannot be set here"),
        ({"host": SECRET}, "host cannot be set here"),
        ({"X-Tenant": f"a\r\nX-Injected: {SECRET}"}, "the value of X-Tenant contains a line break"),
    ],
)
def test_header_rules_never_echo_values(headers: dict[str, str], expected: str) -> None:
    with pytest.raises(ValueError, match=expected) as caught:
        check_headers({name: SecretStr(value) for name, value in headers.items()})
    assert SECRET not in str(caught.value)


def test_valid_headers_pass() -> None:
    headers = {"X-Scope-OrgID": SecretStr("team-a"), "X-Api-Key": SecretStr(SECRET)}
    assert check_headers(headers) == headers
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_http_models.py -q`
Expected: collection error `ModuleNotFoundError: No module named 'ratatoskr.config.http_models'`.

- [ ] **Step 3: Create the shared module**

Create `src/ratatoskr/config/shared.py`:

```python
"""Pieces the config models of every connection kind share."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from ratatoskr.config.durations import parse_duration

DEFAULT_MAX_RESPONSE_BYTES = 65536


def duration_value(value: Any) -> timedelta:
    """A ``mode="before"`` validator body for duration fields: seconds or ``30s``, ``5m``, ``1h``, ``30d``."""
    if isinstance(value, str | int | float | timedelta):
        return parse_duration(value)
    raise ValueError("duration must be a number of seconds or a string like '30s', '5m', '1h', '30d'")
```

- [ ] **Step 4: Create the HTTP connection models**

Create `src/ratatoskr/config/http_models.py`:

```python
"""Config models shared by HTTP-based connection kinds: Prometheus now, Loki in stage 3.

No validation message echoes a value: credentials, header values and URLs may hold secrets.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated, Any, Literal, Self

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator

# RFC 9110 token characters.
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
# Set by Ratatoskr or httpx; a configured value would conflict with them or bypass `auth`.
RESERVED_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "host",
        "content-length",
        "content-type",
        "transfer-encoding",
        "connection",
    }
)


def _not_empty(value: SecretStr, label: str) -> SecretStr:
    if not value.get_secret_value():
        raise ValueError(f"{label} must not be empty")
    return value


class NoAuth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["none"]


class BasicAuth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["basic"]
    username: str = Field(min_length=1)
    password: SecretStr

    @field_validator("username")
    @classmethod
    def _check_username(cls, value: str) -> str:
        if ":" in value:
            raise ValueError("auth.username must not contain ':'")
        return value

    @field_validator("password")
    @classmethod
    def _check_password(cls, value: SecretStr) -> SecretStr:
        return _not_empty(value, "auth.password")


class BearerAuth(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: Literal["bearer"]
    token: SecretStr

    @field_validator("token")
    @classmethod
    def _check_token(cls, value: SecretStr) -> SecretStr:
        return _not_empty(value, "auth.token")


HttpAuth = Annotated[NoAuth | BasicAuth | BearerAuth, Field(discriminator="type")]


class HttpTlsSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verify: bool = True
    ca_file: Path | None = None  # trust only this CA (instead of the default bundle)

    @model_validator(mode="after")
    def _check_ca_file(self) -> Self:
        if self.ca_file is None:
            return self
        if not self.verify:
            raise ValueError("tls.ca_file has no effect with tls.verify: false; remove one of them")
        if not self.ca_file.is_file():
            raise ValueError(f"tls.ca_file does not exist: {self.ca_file}")
        return self


def check_base_url(url: AnyHttpUrl) -> AnyHttpUrl:
    """The API root: credentials belong under ``auth``, and a query string or fragment would be dropped."""
    if url.username is not None or url.password is not None:
        raise ValueError("url must not contain credentials; use auth (basic or bearer) instead")
    if url.query is not None or url.fragment is not None:
        raise ValueError("url must not contain a query string or fragment")
    return url


def stringify_header_values(value: Any) -> Any:
    """``mode="before"``: YAML reads ``X-Scope-OrgID: 42`` as a number; header values are text."""
    if not isinstance(value, dict):
        return value
    return {
        name: str(item) if isinstance(item, int | float) and not isinstance(item, bool) else item
        for name, item in value.items()
    }


def check_headers(headers: dict[str, SecretStr]) -> dict[str, SecretStr]:
    for index, (name, value) in enumerate(headers.items()):
        if not _HEADER_NAME_RE.match(name):
            raise ValueError(f"headers: entry {index} is not a valid header name")
        if name.lower() in RESERVED_HEADERS:
            raise ValueError(f"headers: {name} cannot be set here (credentials go under auth)")
        if any(character in value.get_secret_value() for character in "\r\n\0"):
            raise ValueError(f"headers: the value of {name} contains a line break or NUL")
    return headers
```

- [ ] **Step 5: Use the shared pieces in `models.py` and the registry**

In `src/ratatoskr/config/models.py` replace the import

```python
from ratatoskr.config.durations import parse_duration
```

with

```python
from ratatoskr.config.shared import DEFAULT_MAX_RESPONSE_BYTES
from ratatoskr.config.shared import duration_value as _duration
```

and delete the local `_duration` function:

```python
def _duration(value: Any) -> timedelta:
    if isinstance(value, str | int | float | timedelta):
        return parse_duration(value)
    raise ValueError("duration must be a number of seconds or a string like '30s', '5m', '1h', '30d'")
```

and the line `DEFAULT_MAX_RESPONSE_BYTES = 65536` (above `class PgLimits`). `PgLimits` keeps using the imported
constant. In `src/ratatoskr/backends/registry.py` (mypy strict does not re-export imported names) replace

```python
from ratatoskr.config.models import DEFAULT_MAX_RESPONSE_BYTES, ConnectionConfig, RatatoskrConfig
```

with

```python
from ratatoskr.config.models import ConnectionConfig, RatatoskrConfig
from ratatoskr.config.shared import DEFAULT_MAX_RESPONSE_BYTES
```

- [ ] **Step 6: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_http_models.py tests/unit/test_config_models.py tests/unit/test_registry.py -q`
Expected: all pass. Then `.venv/Scripts/python -m mypy src` and `.venv/Scripts/python -m ruff check src tests`: clean.

- [ ] **Step 7: Commit**

```bash
git add src/ratatoskr/config/shared.py src/ratatoskr/config/http_models.py src/ratatoskr/config/models.py src/ratatoskr/backends/registry.py tests/unit/test_config_http_models.py
git commit -m "Add shared HTTP connection config models (auth, headers, TLS)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `PrometheusConnection` model

**Files:**
- Create: `src/ratatoskr/config/prometheus_models.py`
- Test: `tests/unit/test_config_prometheus.py`

The model is standalone in this task; Task 8 adds it to the `ConnectionConfig` union (after the backend exists, so the
registry and `check-config` can handle it in the same commit).

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_config_prometheus.py`:

```python
from datetime import timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from ratatoskr.config.http_models import BearerAuth, NoAuth
from ratatoskr.config.prometheus_models import PrometheusConnection, PrometheusLimits

TOKEN = "prom-token-VALUE-never-shown"


def _connection(**values: Any) -> PrometheusConnection:
    return PrometheusConnection.model_validate({"kind": "prometheus", "url": "http://prometheus:9090", **values})


def _errors(**values: Any) -> str:
    with pytest.raises(ValidationError) as caught:
        _connection(**values)
    return " | ".join(str(error["msg"]) for error in caught.value.errors(include_input=False, include_url=False))


def test_defaults() -> None:
    connection = _connection()
    assert connection.mode == "read"
    assert isinstance(connection.auth, NoAuth)
    assert connection.headers == {}
    assert connection.tls.verify is True
    assert connection.timeout == timedelta(seconds=30)
    assert connection.limits == PrometheusLimits()
    limits = connection.limits
    assert (limits.max_series, limits.max_values, limits.max_points) == (100, 500, 1000)
    assert (limits.max_range, limits.max_response_bytes) == (timedelta(days=31), 65536)
    assert limits.max_body_bytes == 16 * 1024 * 1024


def test_full_connection() -> None:
    connection = _connection(
        url="https://mimir.example.com/prometheus",
        auth={"type": "bearer", "token": TOKEN},
        headers={"X-Scope-OrgID": 42},
        timeout="1m",
        limits={"max_series": 20, "max_range": "7d"},
    )
    assert isinstance(connection.auth, BearerAuth)
    assert connection.auth.token.get_secret_value() == TOKEN
    assert connection.headers["X-Scope-OrgID"].get_secret_value() == "42"
    assert connection.timeout == timedelta(minutes=1)
    assert (connection.limits.max_series, connection.limits.max_range) == (20, timedelta(days=7))
    assert TOKEN not in repr(connection)


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({"mode": "write"}, "prometheus connections are read-only: omit mode or set it to read"),
        ({"timeout": "0s"}, "timeout must be between 1s and 10m"),
        ({"timeout": "1h"}, "timeout must be between 1s and 10m"),
        ({"limits": {"max_points": 20_000}}, "less than or equal to 11000"),
        ({"limits": {"max_range": "30s"}}, "max_range must be at least 1m"),
        ({"url": f"http://u:{TOKEN}@prometheus:9090"}, "url must not contain credentials"),
        ({"headers": {"Authorization": TOKEN}}, "Authorization cannot be set here"),
        ({"dsn": TOKEN}, "Extra inputs are not permitted"),
    ],
)
def test_invalid_values_are_rejected_without_echo(values: dict[str, Any], expected: str) -> None:
    messages = _errors(**values)
    assert expected in messages
    assert TOKEN not in messages
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_prometheus.py -q`
Expected: `ModuleNotFoundError: No module named 'ratatoskr.config.prometheus_models'`.

- [ ] **Step 3: Implement**

Create `src/ratatoskr/config/prometheus_models.py`:

```python
"""Config model of a ``kind: prometheus`` connection (spec 4 and 6.3)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, SecretStr, field_validator

from ratatoskr.config.http_models import (
    HttpAuth,
    HttpTlsSettings,
    NoAuth,
    check_base_url,
    check_headers,
    stringify_header_values,
)
from ratatoskr.config.shared import DEFAULT_MAX_RESPONSE_BYTES, duration_value

# Prometheus refuses range queries with more than 11,000 points per series.
PROMETHEUS_MAX_POINTS = 11_000


class PrometheusLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_series: int = Field(default=100, ge=1, le=10_000)  # series (and alerts) shown per response
    max_values: int = Field(default=500, ge=1, le=100_000)  # metric names / label values shown per response
    max_points: int = Field(default=1000, ge=10, le=PROMETHEUS_MAX_POINTS)  # per series in prom_query_range
    max_range: timedelta = timedelta(days=31)
    max_query_length: int = Field(default=20_000, ge=1)
    max_response_bytes: int = Field(default=DEFAULT_MAX_RESPONSE_BYTES, ge=1024)
    max_body_bytes: int = Field(default=16 * 1024 * 1024, ge=64 * 1024)  # read from Prometheus per request

    @field_validator("max_range", mode="before")
    @classmethod
    def _parse_max_range(cls, value: Any) -> timedelta:
        return duration_value(value)

    @field_validator("max_range")
    @classmethod
    def _check_max_range(cls, value: timedelta) -> timedelta:
        if value < timedelta(minutes=1):
            raise ValueError("max_range must be at least 1m")
        return value


class PrometheusConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: Literal["prometheus"]
    description: str = ""
    # Every Prometheus tool is a read of the HTTP API, so the connection is read-only; `write` would grant nothing.
    mode: Literal["read"] = "read"
    url: AnyHttpUrl
    auth: HttpAuth = NoAuth(type="none")
    headers: dict[str, SecretStr] = {}
    tls: HttpTlsSettings = HttpTlsSettings()
    timeout: timedelta = timedelta(seconds=30)
    limits: PrometheusLimits = PrometheusLimits()

    @field_validator("mode", mode="before")
    @classmethod
    def _check_mode(cls, value: Any) -> Any:
        if value != "read":
            raise ValueError("prometheus connections are read-only: omit mode or set it to read")
        return value

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: AnyHttpUrl) -> AnyHttpUrl:
        return check_base_url(value)

    @field_validator("headers", mode="before")
    @classmethod
    def _stringify_headers(cls, value: Any) -> Any:
        return stringify_header_values(value)

    @field_validator("headers")
    @classmethod
    def _check_headers(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        return check_headers(value)

    @field_validator("timeout", mode="before")
    @classmethod
    def _parse_timeout(cls, value: Any) -> timedelta:
        return duration_value(value)

    @field_validator("timeout")
    @classmethod
    def _check_timeout(cls, value: timedelta) -> timedelta:
        if not timedelta(seconds=1) <= value <= timedelta(minutes=10):
            raise ValueError("timeout must be between 1s and 10m")
        return value
```

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_prometheus.py -q` — expected: 10 passed. mypy and ruff clean.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/config/prometheus_models.py tests/unit/test_config_prometheus.py
git commit -m "Add the Prometheus connection model (read-only, limits, timeout)" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: `ToolRuntime.run`: `kind` check and per-call truncation hint

**Files:**
- Modify: `src/ratatoskr/tools/runtime.py`
- Test: `tests/unit/test_runtime.py` (append)

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_runtime.py` (its imports already cover everything used):

```python
async def test_wrong_kind_is_refused_before_the_backend_opens() -> None:
    runtime, sink, factory = _runtime()
    result = await runtime.run(tool="prom_query", connection="prod", need=Access.READ, call=_ok, kind="prometheus")
    assert result == ToolResult(
        "Error: Connection 'prod' is a postgres connection; prom_query needs a prometheus connection. "
        "list_connections shows the kind of each connection.",
        is_error=True,
    )
    assert factory.backends["prod"].open_calls == 0
    [event] = sink.events
    assert (event.result, event.error_class) == ("error", "InvalidRequestError")


async def test_kind_check_comes_after_authorization() -> None:
    runtime, sink, _ = _runtime(role=None)
    result = await runtime.run(tool="prom_query", connection="prod", need=Access.READ, call=_ok, kind="prometheus")
    assert result.text == "Error: Connection 'prod' not found."
    assert sink.events[0].result == "denied"


async def test_matching_kind_runs_the_call() -> None:
    runtime, _, _ = _runtime()
    result = await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=_ok, kind="postgres")
    assert result == ToolResult("prod:READ", is_error=False)


async def test_truncation_hint_is_chosen_per_call() -> None:
    runtime, _, _ = _runtime()

    async def big(backend: Backend, access: Access) -> ToolOutput:
        return ToolOutput(text="x" * 5000)

    result = await runtime.run(
        tool="prom_query", connection="prod", need=Access.READ, call=big, truncation_hint="Add label matchers."
    )
    assert result.text.endswith("Add label matchers.]")
    assert len(result.text.encode()) <= 1024
```

- [ ] **Step 2: Run them to see them fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_runtime.py -q`
Expected: 4 failures, `TypeError: ToolRuntime.run() got an unexpected keyword argument 'kind'` (and
`'truncation_hint'`).

- [ ] **Step 3: Implement**

In `src/ratatoskr/tools/runtime.py`:

1. Replace the errors import with

```python
from ratatoskr.backends.errors import (
    BackendError,
    BackendTimeoutError,
    BackendUnavailableError,
    InvalidRequestError,
)
```

2. Extend the `run` signature and docstring: after `on_unavailable: ...` add

```python
        kind: str | None = None,
        truncation_hint: str = TRUNCATION_HINT,
```

and insert as the docstring's second paragraph

```python
        ``kind``: the backend kind the tool needs (``prometheus``). Checked after authorization (so a forbidden
        connection still reads "not found") and before the backend is opened. ``truncation_hint`` ends the note
        appended when the response is clamped; it should say how to narrow a request of this kind.
```

3. In `run`, right after `access = self.policy.authorize(principal, connection, need)` add

```python
            if kind is not None:
                self._check_kind(tool, connection, kind)
```

and pass the hint on: `result = self._success(output.text, connection, truncation_hint)` and
`result = self._failure(text, connection, truncation_hint)` (`run_global` stays unchanged).

4. Add after `run` (before `run_global`):

```python
    def _check_kind(self, tool: str, connection: str, kind: str) -> None:
        actual = self.registry.describe(connection).kind
        if actual != kind:
            raise InvalidRequestError(
                f"Connection '{connection}' is a {actual} connection; {tool} needs a {kind} connection. "
                "list_connections shows the kind of each connection."
            )
```

5. Replace `_success`, `_failure` and `_clamp` with

```python
    def _success(self, text: str, connection: str | None, hint: str = TRUNCATION_HINT) -> ToolResult:
        """Successful output is the user's data: it is clamped but never redacted (that would corrupt rows)."""
        return ToolResult(text=self._clamp(text, connection, hint), is_error=False)

    def _failure(self, text: str, connection: str | None, hint: str = TRUNCATION_HINT) -> ToolResult:
        """Error text is redacted first, then clamped, so the byte limit always holds."""
        return ToolResult(text=self._clamp(redact(text), connection, hint), is_error=True)

    def _clamp(self, text: str, connection: str | None, hint: str) -> str:
        return clamp_text(text, self.registry.max_response_bytes(connection), hint).text
```

`InvalidRequestError` is a `BackendError`, so `_error_text` already shows it and audits `error`.

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_runtime.py tests/unit/test_common_tools.py tests/unit/test_pg_tools.py -q`
Expected: all pass (42 in `test_runtime.py`). mypy and ruff clean.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/tools/runtime.py tests/unit/test_runtime.py
git commit -m "Let tools require a backend kind and choose the truncation hint" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: Shared time parsing (`backends/timeparse.py`)

**Files:**
- Create: `src/ratatoskr/backends/timeparse.py`
- Modify: `src/ratatoskr/backends/limits.py` (add `clip_input`)
- Test: `tests/unit/test_timeparse.py`, `tests/unit/test_limits.py` (append)

Loki (stage 3) reuses this module unchanged: `parse_time`, `resolve_range`, `parse_duration_text`, `format_time`,
`format_duration`, `unix_seconds`. Errors are `InvalidRequestError` (shown to the client as is) that name the argument
and echo at most 64 characters of the input.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_timeparse.py`:

```python
from datetime import UTC, datetime, timedelta

import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.timeparse import (
    auto_step,
    format_duration,
    format_time,
    parse_duration_text,
    parse_time,
    point_count,
    resolve_range,
    resolve_step,
    step_seconds,
    unix_seconds,
)

NOW = datetime(2026, 11, 22, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("now", "2026-11-22T10:00:00Z"),
        ("now-15m", "2026-11-22T09:45:00Z"),
        ("NOW - 1h30m", "2026-11-22T08:30:00Z"),
        ("now+5m", "2026-11-22T10:05:00Z"),
        ("now-2d", "2026-11-20T10:00:00Z"),
        ("2026-11-22T09:00:00Z", "2026-11-22T09:00:00Z"),
        ("2026-11-22T11:00:00+02:00", "2026-11-22T09:00:00Z"),
        ("2026-11-22T09:12:00.123456789Z", "2026-11-22T09:12:00.123Z"),
        ("1795341600", "2026-11-22T10:00:00Z"),
        ("1795341600.5", "2026-11-22T10:00:00.500Z"),
    ],
)
def test_parse_time(text: str, expected: str) -> None:
    assert format_time(parse_time(text, now=NOW, argument="time")) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-11-22T09:00:00", "add a time zone"),
        ("1795341600000", "looks like milliseconds"),
        ("15", "use RFC3339"),
        ("yesterday", "use RFC3339"),
        ("now-0s", "use now-<duration>"),
        ("now-", "use RFC3339"),
        ("now-99999999999999999d", "use now-<duration>"),
    ],
)
def test_parse_time_errors_name_the_argument(text: str, expected: str) -> None:
    with pytest.raises(InvalidRequestError, match=expected) as caught:
        parse_time(text, now=NOW, argument="start")
    assert str(caught.value).startswith("Invalid start '")


def test_parse_time_echoes_at_most_64_characters() -> None:
    with pytest.raises(InvalidRequestError) as caught:
        parse_time("x" * 500, now=NOW, argument="end")
    assert "x" * 65 not in str(caught.value)


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("30s", 30), ("5m", 300), ("1h30m", 5400), ("2d", 172800), ("1w", 604800), ("250ms", 0.25), ("15", 15)],
)
def test_parse_duration_text(text: str, seconds: float) -> None:
    assert parse_duration_text(text, argument="step") == timedelta(seconds=seconds)


@pytest.mark.parametrize("text", ["0s", "0", "-5m", "5 minutes", "1y", ""])
def test_parse_duration_text_rejects(text: str) -> None:
    with pytest.raises(InvalidRequestError, match="Invalid step"):
        parse_duration_text(text, argument="step")


def test_resolve_range_defaults_to_the_last_hour() -> None:
    window = resolve_range(None, None, now=NOW, max_range=None)
    assert (window.start, window.end, window.span) == (NOW - timedelta(hours=1), NOW, timedelta(hours=1))


def test_resolve_range_start_defaults_to_an_hour_before_end() -> None:
    window = resolve_range(None, "2026-11-22T08:00:00Z", now=NOW, max_range=None)
    assert format_time(window.start) == "2026-11-22T07:00:00Z"


def test_resolve_range_rejects_reversed_and_too_long_ranges() -> None:
    with pytest.raises(InvalidRequestError, match=r"start \(2026-11-22T10:00:00Z\) must be before end"):
        resolve_range("now", "now-1h", now=NOW, max_range=None)
    with pytest.raises(InvalidRequestError, match="The range is 40d; this connection allows at most 31d"):
        resolve_range("now-40d", None, now=NOW, max_range=timedelta(days=31))


@pytest.mark.parametrize(
    ("span", "step", "points"),
    [
        (timedelta(minutes=5), "5s", 61),
        (timedelta(hours=1), "30s", 121),
        (timedelta(hours=24), "15m", 97),
        (timedelta(days=7), "2h", 85),
        (timedelta(days=31), "12h", 63),
        (timedelta(days=400), "4d", 101),
    ],
)
def test_auto_step_targets_about_120_points(span: timedelta, step: str, points: int) -> None:
    chosen = auto_step(span)
    assert (format_duration(chosen), point_count(span, chosen)) == (step, points)


def test_resolve_step_respects_a_small_point_limit() -> None:
    step = resolve_step(None, timedelta(hours=1), max_points=10)
    assert point_count(timedelta(hours=1), step) <= 10


def test_resolve_step_refuses_too_many_points_with_the_minimum_step() -> None:
    with pytest.raises(InvalidRequestError) as caught:
        resolve_step("1s", timedelta(hours=1), max_points=1000)
    assert str(caught.value) == (
        "step 1s gives 3601 points per series over 1h; this connection allows 1000. Use step 4s or more, or omit step."
    )


def test_api_formats() -> None:
    assert unix_seconds(NOW) == "1795341600.000"
    assert step_seconds(timedelta(seconds=30)) == "30"
    assert step_seconds(timedelta(milliseconds=250)) == "0.25"
    assert format_duration(timedelta(seconds=5400)) == "1h30m"
    assert format_duration(timedelta(0)) == "0s"
```

In `tests/unit/test_limits.py` change the import to `from ratatoskr.backends.limits import clamp_text, clip_input` and
append:

```python
def test_clip_input_keeps_short_text_and_cuts_long_text() -> None:
    assert clip_input("now-15m") == "now-15m"
    assert clip_input("x" * 100) == "x" * 64 + "…"
```

- [ ] **Step 2: Run them to see them fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_timeparse.py tests/unit/test_limits.py -q`
Expected: `ModuleNotFoundError: No module named 'ratatoskr.backends.timeparse'` and `ImportError: cannot import name
'clip_input'`.

- [ ] **Step 3: Add `clip_input`**

Append to `src/ratatoskr/backends/limits.py`:

```python
def clip_input(text: str, limit: int = 64) -> str:
    """User input echoed in an error message, cut to *limit* characters."""
    return text if len(text) <= limit else text[:limit] + "…"
```

- [ ] **Step 4: Implement the module**

Create `src/ratatoskr/backends/timeparse.py`:

```python
"""Parse the time arguments of the metric and log tools (spec 6.5); shared by Prometheus and, in stage 3, Loki.

Accepted times: RFC3339 with a zone (``2026-11-22T10:00:00Z``, ``...+02:00``), unix seconds (``1732270000`` or
``1732270000.5``), ``now`` and ``now-<duration>`` / ``now+<duration>`` (``now-15m``, ``now-1h30m``).
Durations: ``250ms``, ``30s``, ``5m``, ``1h30m``, ``2d``, ``1w`` or a plain number of seconds.
Every error is an ``InvalidRequestError`` that names the argument and echoes at most 64 characters of the input.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.limits import clip_input

DEFAULT_SPAN = timedelta(hours=1)
TARGET_POINTS = 120
TIME_FORMATS = "RFC3339 (2026-11-22T10:00:00Z), unix seconds (1732270000) or relative (now, now-15m)"

_UNITS = {
    "ms": timedelta(milliseconds=1),
    "s": timedelta(seconds=1),
    "m": timedelta(minutes=1),
    "h": timedelta(hours=1),
    "d": timedelta(days=1),
    "w": timedelta(weeks=1),
}
_DURATION_RE = re.compile(r"(?:\d+(?:ms|s|m|h|d|w))+")
_DURATION_PART_RE = re.compile(r"(\d+)(ms|s|m|h|d|w)")
_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")
_RELATIVE_RE = re.compile(r"now(?:([+-])(.+))?")
_UNIX_MIN = 1e9  # 2001-09-09: smaller numbers are not plausible unix times in seconds
_UNIX_MAX = 1e11  # year 5138: larger numbers are milliseconds (or finer)
_NICE_STEPS = tuple(
    timedelta(seconds=seconds)
    for seconds in (1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400)
)


@dataclass(frozen=True)
class TimeRange:
    start: datetime
    end: datetime

    @property
    def span(self) -> timedelta:
        return self.end - self.start


def utc_now() -> datetime:
    return datetime.now(UTC)


def parse_duration_text(text: str, *, argument: str) -> timedelta:
    """A positive duration: ``250ms``, ``30s``, ``1h30m``, ``2d``, ``1w`` or a plain number of seconds."""
    value = text.strip().lower()
    try:
        if _NUMBER_RE.fullmatch(value):
            result = timedelta(seconds=float(value))
        elif _DURATION_RE.fullmatch(value):
            result = sum((int(count) * _UNITS[unit] for count, unit in _DURATION_PART_RE.findall(value)), timedelta())
        else:
            raise InvalidRequestError(
                f"Invalid {argument} '{clip_input(text)}': use a duration such as 30s, 5m, 1h30m or 2d."
            )
    except OverflowError:
        raise InvalidRequestError(f"Invalid {argument} '{clip_input(text)}': the duration is too large.") from None
    if result <= timedelta(0):
        raise InvalidRequestError(f"Invalid {argument} '{clip_input(text)}': the duration must be greater than zero.")
    return result


def parse_time(text: str, *, now: datetime, argument: str) -> datetime:
    """An absolute UTC time from RFC3339, unix seconds or ``now[+-]<duration>``."""
    value = text.strip()
    relative = _RELATIVE_RE.fullmatch("".join(value.split()).lower())
    if relative is not None:
        sign, amount = relative.groups()
        if sign is None:
            return now
        try:
            offset = parse_duration_text(amount, argument=argument)
            return now + offset if sign == "+" else now - offset
        except (InvalidRequestError, OverflowError):
            message = f"Invalid {argument} '{clip_input(text)}': use now-<duration> such as now-15m, now-2h or now-1d."
        raise InvalidRequestError(message)
    if _NUMBER_RE.fullmatch(value):
        return _from_unix(float(value), text, argument)
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise InvalidRequestError(f"Invalid {argument} '{clip_input(text)}': use {TIME_FORMATS}.") from None
    if parsed.tzinfo is None:
        raise InvalidRequestError(
            f"Invalid {argument} '{clip_input(text)}': add a time zone, e.g. 2026-11-22T10:00:00Z or +02:00."
        )
    return parsed.astimezone(UTC)


def _from_unix(seconds: float, text: str, argument: str) -> datetime:
    if seconds >= _UNIX_MAX:
        raise InvalidRequestError(
            f"Invalid {argument} '{clip_input(text)}': this looks like milliseconds; pass unix seconds."
        )
    if seconds < _UNIX_MIN:
        raise InvalidRequestError(f"Invalid {argument} '{clip_input(text)}': use {TIME_FORMATS}.")
    return datetime.fromtimestamp(seconds, UTC)


def resolve_range(
    start: str | None,
    end: str | None,
    *,
    now: datetime,
    max_range: timedelta | None,
    default_span: timedelta = DEFAULT_SPAN,
) -> TimeRange:
    """``end`` defaults to now and ``start`` to ``default_span`` before ``end``."""
    end_at = now if end is None else parse_time(end, now=now, argument="end")
    start_at = end_at - default_span if start is None else parse_time(start, now=now, argument="start")
    if start_at >= end_at:
        raise InvalidRequestError(f"start ({format_time(start_at)}) must be before end ({format_time(end_at)}).")
    span = end_at - start_at
    if max_range is not None and span > max_range:
        raise InvalidRequestError(
            f"The range is {format_duration(span)}; this connection allows at most {format_duration(max_range)}. "
            "Use a later start or an earlier end."
        )
    return TimeRange(start=start_at, end=end_at)


def auto_step(span: timedelta, *, target_points: int = TARGET_POINTS) -> timedelta:
    """The smallest "round" step that keeps *span* at or below about *target_points* points."""
    raw = span / max(1, target_points)
    for step in _NICE_STEPS:
        if step >= raw:
            return step
    return timedelta(days=math.ceil(raw / timedelta(days=1)))


def point_count(span: timedelta, step: timedelta) -> int:
    return span // step + 1


def resolve_step(step: str | None, span: timedelta, *, max_points: int) -> timedelta:
    """The given step, or an automatic one; refuses a step that gives more than *max_points* per series."""
    if step is None:
        return auto_step(span, target_points=min(TARGET_POINTS, max_points - 1))
    chosen = parse_duration_text(step, argument="step")
    points = point_count(span, chosen)
    if points > max_points:
        minimum = timedelta(seconds=max(1, math.ceil(span.total_seconds() / (max_points - 1))))
        raise InvalidRequestError(
            f"step {format_duration(chosen)} gives {points} points per series over {format_duration(span)}; "
            f"this connection allows {max_points}. Use step {format_duration(minimum)} or more, or omit step."
        )
    return chosen


def format_time(moment: datetime) -> str:
    """RFC3339 in UTC with a ``Z``; milliseconds only when present."""
    utc = moment.astimezone(UTC)
    spec = "milliseconds" if utc.microsecond else "seconds"
    return utc.isoformat(timespec=spec).replace("+00:00", "Z")


def format_duration(value: timedelta) -> str:
    """``1h30m``, ``250ms``, ``31d``; ``0s`` for zero."""
    remaining = round(value.total_seconds() * 1000)
    parts: list[str] = []
    for unit, size in (("d", 86_400_000), ("h", 3_600_000), ("m", 60_000), ("s", 1000), ("ms", 1)):
        count, remaining = divmod(remaining, size)
        if count:
            parts.append(f"{count}{unit}")
    return "".join(parts) or "0s"


def unix_seconds(moment: datetime) -> str:
    """A time as the API parameter Prometheus and Loki accept: unix seconds with milliseconds."""
    return f"{moment.timestamp():.3f}"


def step_seconds(step: timedelta) -> str:
    """A step as seconds without trailing zeros: ``30``, ``0.25``."""
    return f"{step.total_seconds():.3f}".rstrip("0").rstrip(".")
```

- [ ] **Step 5: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_timeparse.py tests/unit/test_limits.py -q` — all pass. mypy, ruff
clean.

- [ ] **Step 6: Commit**

```bash
git add src/ratatoskr/backends/timeparse.py src/ratatoskr/backends/limits.py tests/unit/test_timeparse.py tests/unit/test_limits.py
git commit -m "Add shared time parsing: RFC3339, unix seconds, now-15m, auto step" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 5: Scrub addresses from upstream server messages

**Files:**
- Create: `src/ratatoskr/backends/http/__init__.py`, `src/ratatoskr/backends/http/scrub.py`
- Test: `tests/unit/test_http_scrub.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_http_scrub.py`:

```python
import pytest

from ratatoskr.backends.http.scrub import MAX_UPSTREAM_TEXT, scrub_upstream_text


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            'Get "http://10.0.0.7:10902/api/v1/query": dial tcp: i/o timeout',
            'Get "<url>": dial tcp: i/o timeout',
        ),
        ("receive series from 10.0.0.7:10901: rpc error", "receive series from <address>: rpc error"),
        ("store [fd00::7]:10901 failed", "store <address> failed"),
        ("addr thanos-store.monitoring.svc.cluster.local failed", "addr <host> failed"),
        ("ingester-3.ingesters.prod.example.com:9095 refused", "<address> refused"),
        ("db.internal is slow", "<host> is slow"),
    ],
)
def test_addresses_are_replaced(text: str, expected: str) -> None:
    assert scrub_upstream_text(text) == expected


def test_promql_errors_stay_readable() -> None:
    text = '1:14: parse error: unexpected "}" in label matching, expected string; rate(x[5m:1m]) job:up:sum'
    assert scrub_upstream_text(text) == text


def test_configured_single_label_host_is_replaced_only_with_a_port() -> None:
    text = "prometheus:9090 is down; prometheus_http_requests_total exists"
    assert scrub_upstream_text(text, hosts=["prometheus"]) == "<host> is down; prometheus_http_requests_total exists"


def test_configured_dotted_host_is_replaced_everywhere() -> None:
    text = "query failed at prom.example.com (prom.example.com:443)"
    assert scrub_upstream_text(text, hosts=["prom.example.com"]) == "query failed at <host> (<host>)"


def test_long_text_is_cut() -> None:
    assert len(scrub_upstream_text("a" * 5000)) == MAX_UPSTREAM_TEXT + 2
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_http_scrub.py -q`
Expected: `ModuleNotFoundError: No module named 'ratatoskr.backends.http'`.

- [ ] **Step 3: Implement**

Create `src/ratatoskr/backends/http/__init__.py`:

```python
"""Shared pieces of HTTP-based backends (Prometheus now, Loki in stage 3)."""
```

Create `src/ratatoskr/backends/http/scrub.py`:

```python
"""Remove addresses from upstream server messages before they reach the client (spec 6.5: no internal hosts).

Error texts and warnings of Prometheus-compatible servers (Thanos, Mimir) can name the stores or ingesters they
talked to. This is a best-effort filter for those server messages; it is never applied to successful tool output,
which is the user's data.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable

MAX_UPSTREAM_TEXT = 1000

_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+", re.IGNORECASE)
_IPV6_RE = re.compile(r"\[[0-9A-Fa-f:.]+\](?::\d{1,5})?")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b")
_HOST_PORT_RE = re.compile(r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+:\d{1,5}\b")
_INTERNAL_NAME_RE = re.compile(
    r"\b[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.(?:svc|cluster\.local|internal|local|lan|corp)\b", re.IGNORECASE
)


def scrub_upstream_text(text: str, *, hosts: Iterable[str] = ()) -> str:
    """*text* with URLs, IP addresses, ``host:port`` pairs, internal names and the given *hosts* replaced."""
    for host in sorted({host for host in hosts if host}, key=len, reverse=True):
        text = _host_pattern(host).sub("<host>", text)
    text = _URL_RE.sub("<url>", text)
    text = _IPV6_RE.sub("<address>", text)
    text = _IPV4_RE.sub("<address>", text)
    text = _HOST_PORT_RE.sub("<address>", text)
    text = _INTERNAL_NAME_RE.sub("<host>", text)
    if len(text) > MAX_UPSTREAM_TEXT:
        text = text[:MAX_UPSTREAM_TEXT] + " …"
    return text


def _host_pattern(host: str) -> re.Pattern[str]:
    """A dotted name or IP address is replaced wherever it stands; a single-label name (``prometheus``) only
    together with a port, so metric names such as ``prometheus_http_requests_total`` stay readable."""
    escaped = re.escape(host)
    if "." in host or ":" in host or _is_ip(host):
        return re.compile(rf"(?<![\w.-]){escaped}(?::\d{{1,5}})?(?![\w-])", re.IGNORECASE)
    return re.compile(rf"(?<![\w.-]){escaped}:\d{{1,5}}\b", re.IGNORECASE)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True
```

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_http_scrub.py -q` — 10 passed. mypy, ruff clean.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/http/__init__.py src/ratatoskr/backends/http/scrub.py tests/unit/test_http_scrub.py
git commit -m "Scrub addresses from upstream server messages" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: HTTP client for HTTP backends

**Files:**
- Create: `src/ratatoskr/backends/http/options.py`, `src/ratatoskr/backends/http/client.py`
- Test: `tests/unit/test_http_client.py`

Notes for the implementer:
- respx (`respx.mock(base_url=...)`) patches httpx's transports, so the real `httpx.AsyncClient` built by `HttpClient`
  is used; an unmatched request raises `AllMockedAssertionError` (not an `httpx.HTTPError`), so it fails the test
  loudly instead of being turned into "unavailable".
- respx rewrites the cause chain of exceptions raised from a `side_effect`, so the TLS-certificate detection is tested
  on `is_certificate_error` directly (real httpx chains `ConnectError` ← httpcore ← `ssl.SSLCertVerificationError`).
- The default SSL context takes ~0.5 s to build; it is cached (`functools.cache`), so the suite pays it once.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_http_client.py`:

```python
import logging
import ssl
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from pydantic import SecretStr

from ratatoskr import __version__
from ratatoskr.backends.errors import BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.http import options
from ratatoskr.backends.http.client import (
    EndpointNotFoundError,
    HttpClient,
    ResponseTooLargeError,
    is_certificate_error,
    parse_json,
    status_error,
)
from ratatoskr.config.http_models import BasicAuth, BearerAuth, HttpAuth, HttpTlsSettings, NoAuth

BASE = "http://mimir.internal:8080/prometheus"
SECRET = "tok-VALUE-never-shown"


def _client(auth: HttpAuth | None = None, *, max_body_bytes: int = 1000, **headers: str) -> HttpClient:
    return HttpClient(
        "prom",
        base_url=BASE,
        auth=auth or NoAuth(type="none"),
        headers={name.replace("_", "-"): SecretStr(value) for name, value in headers.items()},
        tls=HttpTlsSettings(),
        timeout=2.0,
        max_body_bytes=max_body_bytes,
    )


@pytest.fixture
def router() -> Iterator[respx.Router]:
    """Every outbound request is mocked; an unmatched one fails the test instead of reaching the network."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mocked:
        yield mocked


@pytest.fixture
async def client() -> AsyncIterator[HttpClient]:
    opened = _client()
    await opened.open()
    yield opened
    await opened.aclose()


async def test_post_form_keeps_the_path_prefix_and_repeats_list_fields(
    router: respx.Router, client: HttpClient
) -> None:
    route = router.post("/api/v1/query").mock(return_value=httpx.Response(200, json={"status": "success"}))
    reply = await client.request("POST", "/api/v1/query", form={"query": "up", "match[]": ["a", "b"]})
    assert (reply.status, parse_json(reply.body)) == (200, {"status": "success"})
    request = route.calls.last.request
    assert request.url.path == "/prometheus/api/v1/query"
    assert parse_qs(request.content.decode()) == {"query": ["up"], "match[]": ["a", "b"]}
    assert request.headers["user-agent"] == f"ratatoskr/{__version__}"
    assert request.headers["accept"] == "application/json"


async def test_get_sends_query_parameters(router: respx.Router, client: HttpClient) -> None:
    route = router.get("/api/v1/labels").mock(return_value=httpx.Response(200, json={}))
    await client.request("GET", "/api/v1/labels", params={"start": "1", "match[]": ["x"]})
    assert parse_qs(route.calls.last.request.url.query.decode()) == {"start": ["1"], "match[]": ["x"]}


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        (BearerAuth(type="bearer", token=SecretStr(SECRET)), f"Bearer {SECRET}"),
        (BasicAuth(type="basic", username="reader", password=SecretStr("pw")), "Basic cmVhZGVyOnB3"),
        (NoAuth(type="none"), None),
    ],
)
async def test_auth_and_extra_headers_are_sent(router: respx.Router, auth: HttpAuth, expected: str | None) -> None:
    route = router.get("/x").mock(return_value=httpx.Response(200))
    client = _client(auth, X_Scope_OrgID="team-a")
    await client.open()
    await client.request("GET", "/x")
    await client.aclose()
    headers = route.calls.last.request.headers
    assert headers.get("authorization") == expected
    assert headers["x-scope-orgid"] == "team-a"


async def test_any_status_is_returned(router: respx.Router, client: HttpClient) -> None:
    router.get("/x").mock(return_value=httpx.Response(503, text="busy"))
    reply = await client.request("GET", "/x")
    assert (reply.status, reply.body) == (503, b"busy")


async def test_declared_large_body_is_refused(router: respx.Router, client: HttpClient) -> None:
    router.get("/x").mock(return_value=httpx.Response(200, content=b"y" * 2000))
    with pytest.raises(ResponseTooLargeError) as caught:
        await client.request("GET", "/x", too_large_hint="Narrow it.")
    assert str(caught.value) == (
        "The answer from connection 'prom' is larger than 1000 bytes, the limit for this connection. Narrow it."
    )


async def test_streamed_body_is_cut_while_reading(router: respx.Router, client: HttpClient) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(5):
            yield b"x" * 400

    router.get("/x").mock(return_value=httpx.Response(200, content=chunks()))
    with pytest.raises(ResponseTooLargeError):
        await client.request("GET", "/x")


async def test_large_limits_are_named_in_mib(router: respx.Router) -> None:
    router.get("/x").mock(return_value=httpx.Response(200, content=b"y" * (2 * 1024 * 1024 + 1)))
    client = _client(max_body_bytes=2 * 1024 * 1024)
    await client.open()
    with pytest.raises(ResponseTooLargeError, match="larger than 2 MiB"):
        await client.request("GET", "/x")
    await client.aclose()


async def test_timeout_names_only_the_connection(router: respx.Router, client: HttpClient) -> None:
    router.get("/x").mock(side_effect=httpx.ReadTimeout("timed out"))
    with pytest.raises(BackendTimeoutError) as caught:
        await client.request("GET", "/x")
    assert str(caught.value) == "Connection 'prom' did not answer within 2s."


async def test_transport_error_hides_the_address(
    router: respx.Router, client: HttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    router.get("/x").mock(side_effect=httpx.ConnectError("[Errno 111] connect to 10.0.0.5:8080 refused"))
    with (
        caplog.at_level(logging.WARNING, logger="ratatoskr.backends.http"),
        pytest.raises(BackendUnavailableError) as caught,
    ):
        await client.request("GET", "/x")
    assert str(caught.value) == "Connection 'prom' is unavailable (ConnectError); details are in the server log."
    assert "request to connection prom failed (ConnectError)" in caplog.text


def test_certificate_errors_are_found_in_the_cause_chain() -> None:
    try:
        try:
            raise ssl.SSLCertVerificationError(1, "certificate verify failed")
        except ssl.SSLCertVerificationError as inner:
            raise httpx.ConnectError("failed") from inner
    except httpx.ConnectError as outer:
        assert is_certificate_error(outer) is True
    assert is_certificate_error(httpx.ConnectError("refused")) is False


def test_certificate_error_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ratatoskr.backends.http.client.is_certificate_error", lambda exc: True)
    error = _client()._unavailable(httpx.ConnectError("x"))
    assert "its TLS certificate could not be verified" in str(error)


async def test_closed_and_unopened_clients_refuse() -> None:
    client = _client()
    with pytest.raises(BackendUnavailableError, match="is not open"):
        await client.request("GET", "/x")
    await client.open()
    assert client.is_open
    await client.aclose()
    assert not client.is_open
    with pytest.raises(BackendUnavailableError, match="is closed"):
        await client.request("GET", "/x")
    with pytest.raises(BackendUnavailableError, match="is closed"):
        await client.open()


@pytest.mark.parametrize(
    ("status", "error", "text"),
    [
        (401, BackendQueryError, "refused the request (HTTP 401)"),
        (403, BackendQueryError, "refused the request (HTTP 403)"),
        (404, EndpointNotFoundError, "answered HTTP 404"),
        (429, BackendQueryError, "rate limiting"),
        (302, BackendUnavailableError, "redirect (HTTP 302)"),
        (502, BackendUnavailableError, "answered HTTP 502"),
        (418, BackendQueryError, "rejected the request (HTTP 418)"),
    ],
)
def test_status_errors(status: int, error: type[Exception], text: str) -> None:
    result = status_error("prom", status)
    assert type(result) is error
    assert text in str(result)


def test_parse_json() -> None:
    assert parse_json(b'{"a": 1}') == {"a": 1}
    assert parse_json(b"<html>") is None


def test_default_ssl_context_is_built_once() -> None:
    assert options.build_verify(HttpTlsSettings()) is options.build_verify(HttpTlsSettings())
    assert options.build_verify(HttpTlsSettings(verify=False)) is False


def test_ca_file_builds_its_own_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("pem", encoding="utf-8")
    seen: dict[str, Any] = {}

    def fake_context(cafile: str) -> str:
        seen["cafile"] = cafile
        return "context"

    monkeypatch.setattr(options.ssl, "create_default_context", fake_context)
    assert options.build_verify(HttpTlsSettings(ca_file=ca)) == "context"
    assert seen == {"cafile": str(ca)}
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_http_client.py -q`
Expected: `ModuleNotFoundError: No module named 'ratatoskr.backends.http.options'`.

- [ ] **Step 3: Implement the options**

Create `src/ratatoskr/backends/http/options.py`:

```python
"""Turn the shared HTTP connection settings (auth, headers, TLS) into what httpx needs."""

from __future__ import annotations

import functools
import ssl
from collections.abc import Mapping

import httpx
from pydantic import SecretStr

from ratatoskr.config.http_models import BasicAuth, BearerAuth, HttpAuth, HttpTlsSettings


@functools.cache
def default_ssl_context() -> ssl.SSLContext:
    """httpx's own default trust (certifi, or ``SSL_CERT_FILE`` / ``SSL_CERT_DIR``), built once per process:
    loading a CA bundle takes about half a second, too long to repeat for every connection."""
    return httpx.create_ssl_context()


def build_verify(tls: HttpTlsSettings) -> ssl.SSLContext | bool:
    if not tls.verify:
        return False
    if tls.ca_file is not None:
        return ssl.create_default_context(cafile=str(tls.ca_file))
    return default_ssl_context()


def build_auth(auth: HttpAuth, headers: Mapping[str, SecretStr]) -> tuple[dict[str, str], httpx.Auth | None]:
    """The request headers (configured ones plus a bearer token) and the httpx auth (basic) of a connection."""
    plain = {name: value.get_secret_value() for name, value in headers.items()}
    if isinstance(auth, BearerAuth):
        plain["Authorization"] = f"Bearer {auth.token.get_secret_value()}"
        return plain, None
    if isinstance(auth, BasicAuth):
        return plain, httpx.BasicAuth(auth.username, auth.password.get_secret_value())
    return plain, None
```

- [ ] **Step 4: Implement the client**

Create `src/ratatoskr/backends/http/client.py`:

```python
"""One httpx client per HTTP connection: auth, headers, TLS, deadlines, a capped body read and user-safe errors.

No message built here names a URL, host, header or credential: transport failures become ``BackendError``s that
name only the connection, and the details go to the log.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import httpx
from pydantic import SecretStr

from ratatoskr import __version__
from ratatoskr.backends.errors import BackendError, BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.http.options import build_auth, build_verify
from ratatoskr.config.http_models import HttpAuth, HttpTlsSettings

CONNECT_TIMEOUT_SECONDS = 10.0
# The server's own timeout (sent as a parameter) should answer first, with a clearer message.
TIMEOUT_GRACE_SECONDS = 5.0
MAX_CONNECTIONS = 10
_MIB = 1024 * 1024

Fields = Mapping[str, str | Sequence[str]]

logger = logging.getLogger("ratatoskr.backends.http")


class ResponseTooLargeError(BackendQueryError):
    """The response body exceeded the connection's ``limits.max_body_bytes`` while it was being read."""


class EndpointNotFoundError(BackendQueryError):
    """HTTP 404: the server does not offer this endpoint (or the url is not the API root)."""


@dataclass(frozen=True)
class HttpReply:
    status: int
    body: bytes


class HttpClient:
    def __init__(
        self,
        connection: str,
        *,
        base_url: str,
        auth: HttpAuth,
        headers: Mapping[str, SecretStr],
        tls: HttpTlsSettings,
        timeout: float,
        max_body_bytes: int,
    ) -> None:
        self._connection = connection
        self._base_url = base_url
        self._auth = auth
        self._headers = headers
        self._tls = tls
        self.timeout = timeout
        self._max_body_bytes = max_body_bytes
        self._client: httpx.AsyncClient | None = None
        self._closed = False

    @property
    def is_open(self) -> bool:
        return self._client is not None

    async def open(self) -> None:
        """Create the httpx client (no network traffic). Proxy settings come from the environment, as for the
        OIDC client: ``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``NO_PROXY``."""
        if self._closed:
            raise BackendUnavailableError(f"Connection '{self._connection}' is closed.")
        if self._client is None:
            headers, auth = build_auth(self._auth, self._headers)
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={"User-Agent": f"ratatoskr/{__version__}", "Accept": "application/json", **headers},
                auth=auth,
                verify=build_verify(self._tls),
                timeout=httpx.Timeout(self.timeout, connect=min(CONNECT_TIMEOUT_SECONDS, self.timeout)),
                limits=httpx.Limits(max_connections=MAX_CONNECTIONS, max_keepalive_connections=MAX_CONNECTIONS),
                follow_redirects=False,
            )

    async def aclose(self) -> None:
        self._closed = True
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    async def request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        params: Fields | None = None,
        form: Fields | None = None,
        too_large_hint: str = "",
    ) -> HttpReply:
        """Send one request and read at most ``max_body_bytes`` of the (decoded) body. Any status is returned."""
        client = self._client
        if client is None:
            state = "closed" if self._closed else "not open"
            raise BackendUnavailableError(f"Connection '{self._connection}' is {state}.")
        try:
            async with (
                asyncio.timeout(self.timeout + TIMEOUT_GRACE_SECONDS),
                client.stream(method, path, params=params, data=form) as response,
            ):
                body = await self._read_capped(response, too_large_hint)
                return HttpReply(status=response.status_code, body=body)
        except BackendError:
            raise
        except (TimeoutError, httpx.TimeoutException):
            raise BackendTimeoutError(
                f"Connection '{self._connection}' did not answer within {self.timeout:.0f}s."
            ) from None
        except httpx.HTTPError as exc:
            raise self._unavailable(exc) from None

    async def _read_capped(self, response: httpx.Response, hint: str) -> bytes:
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max_body_bytes:
            raise self._too_large(hint)
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > self._max_body_bytes:
                raise self._too_large(hint)
            chunks.append(chunk)
        return b"".join(chunks)

    def _too_large(self, hint: str) -> ResponseTooLargeError:
        limit = self._max_body_bytes
        size = f"{limit / _MIB:g} MiB" if limit >= _MIB else f"{limit} bytes"
        message = (
            f"The answer from connection '{self._connection}' is larger than {size}, the limit for this "
            f"connection. {hint}"
        )
        return ResponseTooLargeError(message.strip())

    def _unavailable(self, exc: httpx.HTTPError) -> BackendUnavailableError:
        logger.warning("request to connection %s failed (%s)", self._connection, type(exc).__name__, exc_info=exc)
        if is_certificate_error(exc):
            return BackendUnavailableError(
                f"Connection '{self._connection}' is unavailable: its TLS certificate could not be verified. "
                "Ask the administrator to check the connection's tls settings; details are in the server log."
            )
        return BackendUnavailableError(
            f"Connection '{self._connection}' is unavailable ({type(exc).__name__}); details are in the server log."
        )


def is_certificate_error(exc: BaseException) -> bool:
    """Whether a certificate verification failure is anywhere in the cause/context chain (cycles are skipped)."""
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending and len(seen) < 20:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        pending.extend(linked for linked in (current.__cause__, current.__context__) if linked is not None)
    return False


def parse_json(body: bytes) -> Any | None:
    """The decoded JSON body, or None when it is not JSON."""
    try:
        return json.loads(body)
    except ValueError:
        return None


def status_error(connection: str, status: int) -> BackendError:
    """A user-safe error for an HTTP status that did not come with an API error body."""
    if status in (401, 403):
        return BackendQueryError(
            f"Connection '{connection}' refused the request (HTTP {status}): its configured credentials or headers "
            "were not accepted. Ask the administrator to check them."
        )
    if status == 404:
        return EndpointNotFoundError(
            f"Connection '{connection}' answered HTTP 404: the server does not offer this API endpoint, or the "
            "connection's url is not the API root."
        )
    if status == 429:
        return BackendQueryError(f"Connection '{connection}' is rate limiting requests (HTTP 429); try again later.")
    if 300 <= status < 400:
        return BackendUnavailableError(
            f"Connection '{connection}' answered with a redirect (HTTP {status}), which is not followed; the "
            "connection's url must be the final address."
        )
    if status >= 500:
        return BackendUnavailableError(
            f"Connection '{connection}' answered HTTP {status}; details are in the server log."
        )
    return BackendQueryError(f"Connection '{connection}' rejected the request (HTTP {status}).")
```

- [ ] **Step 5: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_http_client.py -q` — 24 passed. mypy, ruff clean.

- [ ] **Step 6: Commit**

```bash
git add src/ratatoskr/backends/http/options.py src/ratatoskr/backends/http/client.py tests/unit/test_http_client.py
git commit -m "Add the HTTP client for HTTP backends: capped reads, safe errors" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Prometheus API layer and backend

**Files:**
- Create: `src/ratatoskr/backends/prometheus/__init__.py`, `src/ratatoskr/backends/prometheus/api.py`,
  `src/ratatoskr/backends/prometheus/backend.py`
- Modify: `src/ratatoskr/observability/logging.py`, `tests/unit/conftest.py`
- Test: `tests/unit/prom_helpers.py` (new helpers), `tests/unit/test_prom_api.py`, `tests/unit/test_prom_backend.py`,
  `tests/unit/test_redact_and_logging.py` (append)

- [ ] **Step 1: Add the test helpers and fixtures**

Create `tests/unit/prom_helpers.py`:

```python
"""Builders for Prometheus unit tests: a backend on a fixed clock and API response bodies. No network."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import httpx

from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.config.prometheus_models import PrometheusConnection

PROM_URL = "http://prometheus.internal:9090"
NOW = datetime(2026, 11, 22, 10, 0, tzinfo=UTC)
TS = NOW.timestamp()

Labels = dict[str, str]


def prom_connection(**values: Any) -> PrometheusConnection:
    return PrometheusConnection.model_validate({"kind": "prometheus", "url": PROM_URL, **values})


def make_backend(**values: Any) -> PrometheusBackend:
    return PrometheusBackend("prom", prom_connection(**values), clock=lambda: NOW)


def success(data: Any, **extra: Any) -> httpx.Response:
    return httpx.Response(200, json={"status": "success", "data": data, **extra})


def api_error(status: int, error_type: str, message: str) -> httpx.Response:
    return httpx.Response(status, json={"status": "error", "errorType": error_type, "error": message})


def vector(*items: tuple[Labels, str], ts: float = TS) -> dict[str, Any]:
    return {"resultType": "vector", "result": [{"metric": labels, "value": [ts, value]} for labels, value in items]}


def matrix(*items: tuple[Labels, Sequence[tuple[float, str]]]) -> dict[str, Any]:
    return {
        "resultType": "matrix",
        "result": [{"metric": labels, "values": [[ts, value] for ts, value in values]} for labels, values in items],
    }
```

In `tests/unit/conftest.py` replace the imports at the top with

```python
import logging
from collections.abc import AsyncIterator, Iterator

import pytest
import respx

from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import PROM_URL, make_backend
```

add `logging.getLogger("httpx").setLevel(logging.NOTSET)` as the last line of `_restore_logging`, and append:

```python
@pytest.fixture
def prom_api() -> Iterator[respx.Router]:
    """The fake Prometheus at PROM_URL. Every outbound httpx request is mocked; an unmatched one fails the test."""
    with respx.mock(base_url=PROM_URL, assert_all_called=False) as router:
        yield router


@pytest.fixture
async def prom_backend(prom_api: respx.Router) -> AsyncIterator[PrometheusBackend]:
    """An opened backend named 'prom' on the fake Prometheus, with the clock fixed at prom_helpers.NOW."""
    backend = make_backend()
    await backend.open()
    yield backend
    await backend.close()
```

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/test_prom_api.py`:

```python
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from ratatoskr.backends.errors import BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.http.client import EndpointNotFoundError
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import api_error, success, vector


async def test_query_posts_promql_time_and_eval_timeout(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    route = prom_api.post("/api/v1/query").mock(return_value=success(vector(({"job": "a"}, "1"))))
    result = await prom_backend.api.query("up", "1795341600.000")
    assert result.data["resultType"] == "vector"
    assert result.notes == []
    form = parse_qs(route.calls.last.request.content.decode())
    assert form == {"query": ["up"], "time": ["1795341600.000"], "timeout": ["30s"]}


async def test_query_range_posts_the_window(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.post("/api/v1/query_range").mock(return_value=success({"resultType": "matrix", "result": []}))
    await prom_backend.api.query_range("up", "1", "2", "30")
    form = parse_qs(route.calls.last.request.content.decode())
    assert form == {"query": ["up"], "start": ["1"], "end": ["2"], "step": ["30"], "timeout": ["30s"]}


async def test_label_values_quotes_the_label_and_passes_match(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    route = prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(["up"]))
    result = await prom_backend.api.label_values("__name__", match='{job="a"}', start="1", end="2")
    assert result.data == ["up"]
    query = parse_qs(route.calls.last.request.url.query.decode())
    assert query == {"start": ["1"], "end": ["2"], "match[]": ['{job="a"}']}


async def test_warnings_and_infos_become_scrubbed_notes(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.post("/api/v1/query").mock(
        return_value=success(
            vector(),
            warnings=["partial response: store 10.0.0.7:10901 unavailable"],
            infos=['PromQL info: metric might not be a counter, name does not end in _total: "x"'],
        )
    )
    result = await prom_backend.api.query("rate(x[5m])", "1")
    assert result.notes == [
        "warning: partial response: store <address> unavailable",
        'info: PromQL info: metric might not be a counter, name does not end in _total: "x"',
    ]


async def test_bad_promql_shows_the_prometheus_message(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.post("/api/v1/query").mock(
        return_value=api_error(400, "bad_data", '1:4: parse error: unexpected "}" in label matching')
    )
    with pytest.raises(BackendQueryError) as caught:
        await prom_backend.api.query("up}", "1")
    assert str(caught.value) == 'Prometheus error (bad_data): 1:4: parse error: unexpected "}" in label matching'


@pytest.mark.parametrize("error_type", ["timeout", "canceled"])
async def test_server_timeouts_are_timeouts(
    prom_api: respx.Router, prom_backend: PrometheusBackend, error_type: str
) -> None:
    prom_api.post("/api/v1/query").mock(return_value=api_error(503, error_type, "query timed out in query execution"))
    with pytest.raises(BackendTimeoutError, match=rf"Prometheus stopped the query \({error_type}\)"):
        await prom_backend.api.query("up", "1")


async def test_error_text_loses_internal_addresses(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    message = (
        'expanding series: Get "http://thanos-store.monitoring.svc.cluster.local:10902/api": dial 10.0.0.7:10901; '
        "prometheus.internal:9090 refused"
    )
    prom_api.post("/api/v1/query").mock(return_value=api_error(422, "execution", message))
    with pytest.raises(BackendQueryError) as caught:
        await prom_backend.api.query("up", "1")
    text = str(caught.value)
    for leak in ("thanos-store", "svc.cluster.local", "10.0.0.7", "prometheus.internal"):
        assert leak not in text
    assert text.startswith('Prometheus error (execution): expanding series: Get "<url>"')


@pytest.mark.parametrize(
    ("response", "error", "text"),
    [
        (httpx.Response(401, text="Unauthorized"), BackendQueryError, "refused the request (HTTP 401)"),
        (httpx.Response(404, text="404 page not found"), EndpointNotFoundError, "answered HTTP 404"),
        (httpx.Response(502, text="<html>bad gateway</html>"), BackendUnavailableError, "answered HTTP 502"),
        (httpx.Response(200, text="<html>login</html>"), BackendUnavailableError, "did not answer like a Prometheus"),
    ],
)
async def test_non_api_answers(
    prom_api: respx.Router, prom_backend: PrometheusBackend, response: httpx.Response, error: type, text: str
) -> None:
    prom_api.get("/api/v1/alerts").mock(return_value=response)
    with pytest.raises(error) as caught:
        await prom_backend.api.alerts()
    assert text in str(caught.value)
    assert "prometheus.internal" not in str(caught.value)
```

Create `tests/unit/test_prom_backend.py`:

```python
import httpx
import respx

from ratatoskr.backends.base import ConnectionInfo
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import api_error, make_backend, success, vector


def test_describe() -> None:
    backend = make_backend(description="Production metrics")
    assert backend.describe() == ConnectionInfo(
        name="prom", kind="prometheus", description="Production metrics", mode="read"
    )


async def test_open_sends_no_request_and_close_is_final(prom_api: respx.Router) -> None:
    backend = make_backend()
    await backend.open()
    assert backend.is_open
    assert prom_api.calls.call_count == 0
    await backend.close()
    assert not backend.is_open


async def test_health_reports_the_build_version(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(return_value=success({"version": "3.5.0", "revision": "abc"}))
    health = await prom_backend.health()
    assert (health.ok, health.version, health.error) == (True, "Prometheus 3.5.0", None)
    assert health.latency_ms is not None


async def test_health_falls_back_to_a_query_without_buildinfo(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(return_value=httpx.Response(404, text="not found"))
    query = prom_api.post("/api/v1/query").mock(return_value=success({"resultType": "scalar", "result": [1, "1"]}))
    health = await prom_backend.health()
    assert (health.ok, health.version) == (True, "Prometheus API")
    assert query.called


async def test_health_failure_is_reported_without_the_address(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(side_effect=httpx.ConnectError("connect to 10.1.2.3 refused"))
    health = await prom_backend.health()
    assert health.ok is False
    assert health.error == "Connection 'prom' is unavailable (ConnectError); details are in the server log."


async def test_health_reports_api_errors(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(return_value=api_error(503, "unavailable", "starting up"))
    health = await prom_backend.health()
    assert (health.ok, health.error) == (False, "Prometheus error (unavailable): starting up")


async def test_query_result_round_trip(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.post("/api/v1/query").mock(return_value=success(vector(({"__name__": "up"}, "1"))))
    assert (await prom_backend.api.query("up", "1")).data["result"][0]["value"][1] == "1"
```

Append to `tests/unit/test_redact_and_logging.py` (after `test_setup_logging_hides_per_request_mcp_lines_at_info`):

```python
@pytest.mark.parametrize(("level", "shown"), [("INFO", False), ("DEBUG", True)])
def test_setup_logging_hides_httpx_request_lines_at_info(level: str, shown: bool) -> None:
    stream = io.StringIO()
    setup_logging(level, stream=stream)
    logging.getLogger("httpx").info('HTTP Request: POST http://prometheus.internal:9090/api/v1/query "200 OK"')
    logging.getLogger("httpx").warning("httpx warning stays")
    assert ("prometheus.internal" in stream.getvalue()) is shown
    assert "httpx warning stays" in stream.getvalue()
```

- [ ] **Step 3: Run them to see them fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_api.py tests/unit/test_prom_backend.py tests/unit/test_redact_and_logging.py -q`
Expected: collection errors (`No module named 'ratatoskr.backends.prometheus'`, raised from `conftest.py` for every
unit test until Step 4 is done) and, after Step 4, one failure in the logging test.

- [ ] **Step 4: Implement the API layer and the backend**

Create `src/ratatoskr/backends/prometheus/__init__.py`:

```python
"""Prometheus backend (spec 6.3): HTTP API client, five read-only tools, range summaries."""
```

Create `src/ratatoskr/backends/prometheus/api.py`:

```python
"""The Prometheus HTTP API endpoints Ratatoskr reads, and the mapping of its error envelope to user-safe errors.

Only read endpoints are called: query, query_range, label values, metadata, alerts, rules and buildinfo. The admin
and write APIs (``/api/v1/admin/*``, remote write, ``/-/reload``) are not reachable through this module. Server
messages (errors, warnings) are passed on after :func:`scrub_upstream_text` removes addresses from them.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import quote

from ratatoskr.backends.errors import BackendError, BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.http.client import Fields, HttpClient, HttpReply, parse_json, status_error
from ratatoskr.backends.http.scrub import scrub_upstream_text

SERIES_HINT = "Select fewer series with label matchers, or aggregate (sum by (...), topk(10, ...))."
VALUES_HINT = 'Pass a match selector such as {job="api"}, or a shorter time range.'
MAX_NOTES = 10
_TIMEOUT_ERROR_TYPES = frozenset({"timeout", "canceled"})

logger = logging.getLogger("ratatoskr.backends.prometheus")


@dataclass(frozen=True)
class ApiResult:
    data: Any
    notes: list[str] = field(default_factory=list)  # scrubbed warnings and infos from the server


class PrometheusApi:
    def __init__(self, connection: str, client: HttpClient, *, hosts: Iterable[str]) -> None:
        self._connection = connection
        self._client = client
        self._hosts = frozenset(hosts)
        # Prometheus' own evaluation timeout; the HTTP deadline is a little longer so this one answers first.
        self._eval_timeout = f"{max(1, int(client.timeout))}s"

    def scrub(self, text: str) -> str:
        return scrub_upstream_text(text, hosts=self._hosts)

    async def query(self, promql: str, time: str) -> ApiResult:
        form = {"query": promql, "time": time, "timeout": self._eval_timeout}
        return await self._call("POST", "/api/v1/query", form=form, hint=SERIES_HINT)

    async def query_range(self, promql: str, start: str, end: str, step: str) -> ApiResult:
        form = {"query": promql, "start": start, "end": end, "step": step, "timeout": self._eval_timeout}
        return await self._call("POST", "/api/v1/query_range", form=form, hint=SERIES_HINT)

    async def label_values(self, label: str, *, match: str | None, start: str, end: str) -> ApiResult:
        params: dict[str, str | list[str]] = {"start": start, "end": end}
        if match is not None:
            params["match[]"] = [match]
        path = f"/api/v1/label/{quote(label, safe='')}/values"
        return await self._call("GET", path, params=params, hint=VALUES_HINT)

    async def metadata(self) -> ApiResult:
        return await self._call("GET", "/api/v1/metadata", params={"limit_per_metric": "1"})

    async def alerts(self) -> ApiResult:
        return await self._call("GET", "/api/v1/alerts")

    async def rules(self) -> ApiResult:
        return await self._call("GET", "/api/v1/rules")

    async def buildinfo(self) -> ApiResult:
        return await self._call("GET", "/api/v1/status/buildinfo")

    async def _call(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        params: Fields | None = None,
        form: Fields | None = None,
        hint: str = "",
    ) -> ApiResult:
        reply = await self._client.request(method, path, params=params, form=form, too_large_hint=hint)
        payload = parse_json(reply.body)
        if reply.status == 200 and isinstance(payload, dict) and payload.get("status") == "success":
            return ApiResult(data=payload.get("data"), notes=self._notes(payload))
        raise self._error(reply, payload, path)

    def _notes(self, payload: dict[str, Any]) -> list[str]:
        notes: list[str] = []
        for key, label in (("warnings", "warning"), ("infos", "info")):
            values = payload.get(key)
            if isinstance(values, list):
                notes += [f"{label}: {self.scrub(str(value))}" for value in values[:MAX_NOTES]]
        return notes

    def _error(self, reply: HttpReply, payload: Any, path: str) -> BackendError:
        if isinstance(payload, dict) and payload.get("status") == "error":
            error_type = str(payload.get("errorType") or "error")
            message = self.scrub(str(payload.get("error") or "no details"))
            if error_type in _TIMEOUT_ERROR_TYPES:
                return BackendTimeoutError(
                    f"Prometheus stopped the query ({error_type}): {message}. "
                    "Shorten the range, raise the step, or select fewer series."
                )
            return BackendQueryError(f"Prometheus error ({error_type}): {message}")
        logger.warning(
            "connection %s answered HTTP %d on %s without an API body: %r",
            self._connection,
            reply.status,
            path,
            reply.body[:200],
        )
        if reply.status == 200:
            return BackendUnavailableError(
                f"Connection '{self._connection}' did not answer like a Prometheus API; check that its url is the "
                "API root. Details are in the server log."
            )
        return status_error(self._connection, reply.status)
```

Create `src/ratatoskr/backends/prometheus/backend.py`:

```python
"""Prometheus backend: one httpx client per connection, opened lazily by the registry and closed on shutdown.

Opening creates the client only (no request), so an unreachable server shows up on the first tool call as a
user-safe "unavailable" error rather than at startup.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from datetime import datetime
from typing import Any, ClassVar

from ratatoskr.backends.base import ConnectionInfo, HealthResult
from ratatoskr.backends.errors import BackendError
from ratatoskr.backends.http.client import EndpointNotFoundError, HttpClient
from ratatoskr.backends.prometheus.api import PrometheusApi
from ratatoskr.backends.timeparse import unix_seconds, utc_now
from ratatoskr.config.prometheus_models import PrometheusConnection, PrometheusLimits

logger = logging.getLogger("ratatoskr.backends.prometheus")


class PrometheusBackend:
    kind: ClassVar[str] = "prometheus"

    def __init__(self, name: str, config: PrometheusConnection, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.name = name
        self.config = config
        self._clock = clock
        self._client = HttpClient(
            name,
            base_url=str(config.url),
            auth=config.auth,
            headers=config.headers,
            tls=config.tls,
            timeout=config.timeout.total_seconds(),
            max_body_bytes=config.limits.max_body_bytes,
        )
        host = config.url.host or ""
        self.api = PrometheusApi(name, self._client, hosts={host, f"{host}:{config.url.port}"})

    @property
    def limits(self) -> PrometheusLimits:
        return self.config.limits

    @property
    def is_open(self) -> bool:
        return self._client.is_open

    def now(self) -> datetime:
        return self._clock()

    async def open(self) -> None:
        await self._client.open()

    async def close(self) -> None:
        await self._client.aclose()

    async def health(self) -> HealthResult:
        started = time.perf_counter()
        try:
            version = await self._version()
        except BackendError as exc:
            return HealthResult(ok=False, latency_ms=None, version=None, error=str(exc))
        except Exception as exc:
            logger.warning("health check of %s failed", self.name, exc_info=True)
            return HealthResult(ok=False, latency_ms=None, version=None, error=type(exc).__name__)
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        return HealthResult(ok=True, latency_ms=latency_ms, version=version, error=None)

    async def _version(self) -> str:
        """``Prometheus <version>`` from buildinfo; servers without that endpoint are probed with a query."""
        try:
            result = await self.api.buildinfo()
        except EndpointNotFoundError:
            await self.api.query("1", unix_seconds(self.now()))
            return "Prometheus API"
        version = _field(result.data, "version")
        return f"Prometheus {version}" if version else "Prometheus API"

    def describe(self) -> ConnectionInfo:
        return ConnectionInfo(
            name=self.name, kind=self.kind, description=self.config.description, mode=self.config.mode
        )


def _field(data: Any, key: str) -> str | None:
    value = data.get(key) if isinstance(data, dict) else None
    return str(value) if value else None
```

- [ ] **Step 5: Quiet the httpx request lines**

In `src/ratatoskr/observability/logging.py` add next to `MCP_REQUEST_LOGGER = "mcp.server.lowlevel.server"`:

```python
HTTPX_LOGGER = "httpx"
```

and at the end of `setup_logging`, after the `MCP_REQUEST_LOGGER` line:

```python
    # httpx logs every request line (URL with query string: internal hosts, label matchers) at INFO.
    logging.getLogger(HTTPX_LOGGER).setLevel(logging.WARNING if quiet else logging.NOTSET)
```

- [ ] **Step 6: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_api.py tests/unit/test_prom_backend.py tests/unit/test_redact_and_logging.py -q`
Expected: all pass. Then the whole unit suite (`.venv/Scripts/python -m pytest -q`): everything passes (the conftest
now imports the Prometheus backend). mypy, ruff clean.

- [ ] **Step 7: Commit**

```bash
git add src/ratatoskr/backends/prometheus/__init__.py src/ratatoskr/backends/prometheus/api.py src/ratatoskr/backends/prometheus/backend.py src/ratatoskr/observability/logging.py tests/unit/conftest.py tests/unit/prom_helpers.py tests/unit/test_prom_api.py tests/unit/test_prom_backend.py tests/unit/test_redact_and_logging.py
git commit -m "Add the Prometheus API layer and backend" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Wire `kind: prometheus` into config, registry and `check-config`

**Files:**
- Modify: `src/ratatoskr/config/models.py`, `src/ratatoskr/config/loader.py`, `src/ratatoskr/backends/registry.py`,
  `src/ratatoskr/cli.py`, `src/ratatoskr/config/notices.py`, `tests/fakes.py`
- Test: `tests/unit/test_prom_wiring.py`, `tests/unit/test_prom_check_config.py`

All of these change together: as soon as the union contains `PrometheusConnection`, mypy requires the registry factory
and `cli.summarize` (which reads `write_dsn`) to tell the kinds apart.

- [ ] **Step 1: Let `make_config` build Prometheus connections**

In `tests/fakes.py` replace the body of `make_config` with:

```python
    """A valid config; connections default to one read-mode 'main' connection.

    Connections are PostgreSQL unless their values say ``kind: prometheus`` (then they get a fake URL).
    """
    if connections is None:
        connections = {"main": {"mode": "read"}}
    data: dict[str, Any] = {
        "server": server,
        "roles": roles or {},
        "connections": {name: _connection(name, values) for name, values in connections.items()},
    }
    return RatatoskrConfig.model_validate(data)


def _connection(name: str, values: dict[str, Any]) -> dict[str, Any]:
    if values.get("kind") == "prometheus":
        return {"url": f"http://{name}.prometheus.internal:9090", **values}
    return {"kind": "postgres", "dsn": f"postgresql://u:secret@db.internal/{name}", **values}
```

- [ ] **Step 2: Write the failing tests**

Create `tests/unit/test_prom_wiring.py`:

```python
"""A `kind: prometheus` connection end to end through config loading, policy, make_config and the registry."""

from pathlib import Path

import pytest
import respx

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.principal import Principal
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.loader import ConfigError, load_config
from ratatoskr.config.models import Access, PostgresConnection
from ratatoskr.config.prometheus_models import PrometheusConnection
from tests.fakes import make_config

TOKEN = "prom-token-VALUE-never-shown"


def _write(tmp_path: Path, connection: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(f"roles: {{admins: {{'*': write}}}}\nconnections:\n  prom:\n{connection}", encoding="utf-8")
    return path


def test_connection_loads_from_yaml(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        "    kind: prometheus\n"
        "    url: https://mimir.example.com/prometheus\n"
        "    auth:\n      type: bearer\n      token: ${PROM_TOKEN}\n"
        "    headers:\n      X-Scope-OrgID: ${PROM_TENANT}\n",
    )
    connection = load_config(path, env={"PROM_TOKEN": TOKEN, "PROM_TENANT": "team-a"}).connections["prom"]
    assert isinstance(connection, PrometheusConnection)
    assert connection.headers["X-Scope-OrgID"].get_secret_value() == "team-a"


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("    kind: prometheus\n    url: http://p:9090\n    mode: write\n", "connections.prom.mode: prometheus "),
        ("    kind: prometheus\n", "connections.prom.url: Field required"),
        ("    kind: prometheus\n    url: http://p:9090\n    dsn: x\n", "connections.prom.dsn: Extra inputs"),
    ],
)
def test_error_paths_drop_the_kind_tag(tmp_path: Path, body: str, expected: str) -> None:
    with pytest.raises(ConfigError, match=expected):
        load_config(_write(tmp_path, body), env={})


@pytest.mark.parametrize(
    "body",
    [
        "    kind: prometheus\n    url: http://p:9090\n    auth: { type: bearer, token: '${PROM_TOKEN}', x: 1 }\n",
        "    kind: prometheus\n    url: ${PROM_TOKEN}\n",
        "    kind: prometheus\n    url: http://u:${PROM_TOKEN}@p:9090\n",
        "    kind: prometheus\n    url: http://p:9090\n    auth: { type: '${PROM_TOKEN}' }\n",
        "    kind: ${PROM_TOKEN}\n    url: http://p:9090\n",
        '    kind: prometheus\n    url: http://p:9090\n    headers: { X-A: "a\\nb${PROM_TOKEN}" }\n',
    ],
)
def test_validation_errors_never_echo_secrets(tmp_path: Path, body: str) -> None:
    with pytest.raises(ConfigError) as caught:
        load_config(_write(tmp_path, body), env={"PROM_TOKEN": TOKEN})
    assert TOKEN not in str(caught.value)


def test_unknown_auth_type_lists_the_choices(tmp_path: Path) -> None:
    body = "    kind: prometheus\n    url: http://p:9090\n    auth: { type: digest }\n"
    with pytest.raises(ConfigError, match="auth: unknown value; expected one of 'none', 'basic', 'bearer'"):
        load_config(_write(tmp_path, body), env={})


def test_policy_caps_prometheus_at_read() -> None:
    config = make_config(connections={"prom": {"kind": "prometheus"}}, roles={"admins": {"*": "write"}})
    principal = Principal("alice", "Alice", frozenset({"admins"}), "local")
    assert Policy(config).effective_access(principal, "prom") == Access.READ


def test_make_config_builds_both_kinds() -> None:
    config = make_config(connections={"db": {}, "prom": {"kind": "prometheus", "description": "m"}})
    assert isinstance(config.connections["db"], PostgresConnection)
    prom = config.connections["prom"]
    assert isinstance(prom, PrometheusConnection)
    assert prom.description == "m"


async def test_registry_builds_opens_and_closes_prometheus_backends(prom_api: respx.Router) -> None:
    config = make_config(connections={"db": {}, "prom": {"kind": "prometheus"}})
    registry = BackendRegistry(config)
    backend = await registry.get("prom")
    assert isinstance(backend, PrometheusBackend)
    assert backend.is_open
    assert registry.describe("prom").kind == "prometheus"
    assert registry.max_response_bytes("prom") == 65536
    await registry.close_all()
    assert not backend.is_open
```

Create `tests/unit/test_prom_check_config.py`:

```python
from pathlib import Path

import pytest

from ratatoskr.cli import main, summarize
from ratatoskr.config.notices import config_warnings
from tests.fakes import make_config

TOKEN = "prom-token-7731"
CONFIG = """
server:
  stdio_role: admins
roles:
  admins: {"*": write}
connections:
  metrics:
    kind: prometheus
    description: Production metrics
    url: https://prometheus.internal.example.com
    auth:
      type: bearer
      token: ${PROM_TOKEN}
    headers:
      X-Scope-OrgID: team-7731
"""


def test_summary_names_the_auth_type_but_no_secret() -> None:
    config = make_config(
        connections={
            "metrics": {"kind": "prometheus", "auth": {"type": "bearer", "token": TOKEN}, "headers": {"X-A": "b"}}
        }
    )
    summary = summarize(config)
    assert "  - metrics: prometheus, mode=read, auth: bearer, extra headers: 1" in summary
    assert TOKEN not in summary
    assert "prometheus.internal" not in summary


def test_check_config_prints_no_secrets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setenv("PROM_TOKEN", TOKEN)
    assert main(["check-config", "--config", str(path)]) == 0
    captured = capsys.readouterr()
    output = captured.out + captured.err
    assert "metrics: prometheus, mode=read, auth: bearer, extra headers: 1  Production metrics" in captured.out
    for secret in (TOKEN, "team-7731", "prometheus.internal"):
        assert secret not in output


@pytest.mark.parametrize(
    ("url", "auth", "warned"),
    [
        ("http://prometheus.example.com:9090", {"type": "bearer", "token": "t"}, True),
        ("https://prometheus.example.com", {"type": "bearer", "token": "t"}, False),
        ("http://127.0.0.1:9090", {"type": "basic", "username": "u", "password": "p"}, False),
        ("http://prometheus.example.com:9090", {"type": "none"}, False),
    ],
)
def test_credentials_over_plain_http_are_warned_about(url: str, auth: dict[str, str], warned: bool) -> None:
    config = make_config(connections={"metrics": {"kind": "prometheus", "url": url, "auth": auth}})
    expected = ["connections.metrics: credentials are sent over plain http; use an https url"] if warned else []
    assert config_warnings(config) == expected
```

- [ ] **Step 3: Run them to see them fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_wiring.py tests/unit/test_prom_check_config.py -q`
Expected: failures — `make_config` raises a pydantic error (`Input tag 'prometheus' found using 'kind' does not match
any of the expected tags: 'postgres'`), the loader tests get the same.

- [ ] **Step 4: Extend the union and the loader**

In `src/ratatoskr/config/models.py` add the import

```python
from ratatoskr.config.prometheus_models import PrometheusConnection
```

and replace

```python
ConnectionConfig = Annotated[PostgresConnection, Field(discriminator="kind")]
# Stage 2/3 extend this union with PrometheusConnection / LokiConnection.
```

with

```python
ConnectionConfig = Annotated[PostgresConnection | PrometheusConnection, Field(discriminator="kind")]
# Stage 3 adds LokiConnection to this union.
```

In `src/ratatoskr/config/loader.py` replace `_KIND_TAGS = frozenset({"postgres"})` with
`_KIND_TAGS = frozenset({"postgres", "prometheus"})`, and in `_format_validation_error`, after the
`message = str(error["msg"]).removeprefix("Value error, ")` line, add:

```python
        if error["type"] == "union_tag_invalid":
            # pydantic's text repeats the given tag, which could be a misplaced ${SECRET}
            message = f"unknown value; expected one of {error.get('ctx', {}).get('expected_tags', '')}"
```

- [ ] **Step 5: Registry factory**

In `src/ratatoskr/backends/registry.py` add the imports

```python
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.config.prometheus_models import PrometheusConnection
```

and replace `default_factory` with

```python
def default_factory(name: str, config: ConnectionConfig) -> Backend:
    if isinstance(config, PrometheusConnection):
        return PrometheusBackend(name, config)
    return PostgresBackend(name, config)
```

- [ ] **Step 6: `check-config` summary and warning**

In `src/ratatoskr/cli.py` replace `from ratatoskr.config.models import RatatoskrConfig` with

```python
from ratatoskr.config.models import PostgresConnection, RatatoskrConfig
```

add `from ratatoskr.config.prometheus_models import PrometheusConnection` (after the `notices` import), and in
`summarize` replace

```python
        separate = ""
        if connection.mode == "write":
            separate = f", separate write role: {'yes' if connection.write_dsn is not None else 'no'}"
        lines.append(f"  - {name}: {connection.kind}, mode={connection.mode}{separate}{description}")
```

with

```python
        details = ""
        if isinstance(connection, PostgresConnection) and connection.mode == "write":
            details = f", separate write role: {'yes' if connection.write_dsn is not None else 'no'}"
        elif isinstance(connection, PrometheusConnection):
            details = f", auth: {connection.auth.type}, extra headers: {len(connection.headers)}"
        lines.append(f"  - {name}: {connection.kind}, mode={connection.mode}{details}{description}")
```

In `src/ratatoskr/config/notices.py` replace the import with

```python
from ratatoskr.config.models import LOOPBACK_HOSTS, RatatoskrConfig
from ratatoskr.config.prometheus_models import PrometheusConnection
```

and before `return warnings` add:

```python
    for name, connection in sorted(config.connections.items()):
        if (
            isinstance(connection, PrometheusConnection)
            and connection.auth.type != "none"
            and connection.url.scheme == "http"
            and connection.url.host not in LOOPBACK_HOSTS
        ):
            warnings.append(f"connections.{name}: credentials are sent over plain http; use an https url")
```

`serve` and `check-config` already log/print every entry of `config_warnings` (spec: the same checks for both).

- [ ] **Step 7: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_wiring.py tests/unit/test_prom_check_config.py tests/unit/test_cli.py tests/unit/test_config_loader.py tests/unit/test_policy.py -q`
Expected: all pass. Then the whole unit suite, `mypy src`, `ruff check src tests`: clean.

- [ ] **Step 8: Commit**

```bash
git add src/ratatoskr/config/models.py src/ratatoskr/config/loader.py src/ratatoskr/backends/registry.py src/ratatoskr/cli.py src/ratatoskr/config/notices.py tests/fakes.py tests/unit/test_prom_wiring.py tests/unit/test_prom_check_config.py
git commit -m "Accept kind: prometheus connections in config, registry and check-config" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Parse results and format instant queries

**Files:**
- Create: `src/ratatoskr/backends/prometheus/series.py`, `src/ratatoskr/backends/prometheus/formatting.py`
- Test: `tests/unit/test_prom_formatting.py`

Output rules (LLM reader): one line per series in PromQL notation (`up{job="api", instance="a:9100"} 1`), the server's
order kept (it matters for `sort`/`topk`), values exactly as Prometheus wrote them, a header with the result type,
count and evaluation time, and `[Showing N of M series: <reason>. <how to narrow>]` whenever something is left out.
`BlockWriter` keeps whole lines until the byte budget (max_response_bytes − 1 KiB) is used up.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_prom_formatting.py`:

```python
import pytest

from ratatoskr.backends.errors import BackendQueryError
from ratatoskr.backends.prometheus.formatting import (
    BlockWriter,
    cell,
    format_instant,
    response_budget,
    short_time,
    truncation_note,
    with_notes,
)
from ratatoskr.backends.prometheus.series import QueryResult, Series, parse_result, series_name
from tests.unit.prom_helpers import NOW, TS, matrix, vector


def test_parse_vector_matrix_scalar_and_histograms() -> None:
    parsed = parse_result(vector(({"__name__": "up", "job": "a"}, "1")))
    assert parsed == QueryResult("vector", [Series({"__name__": "up", "job": "a"}, [(TS, "1")], [])])
    parsed = parse_result(matrix(({"job": "a"}, [(TS - 30, "1"), (TS, "NaN")])))
    assert parsed.series[0].values == [(TS - 30, "1"), (TS, "NaN")]
    assert parse_result({"resultType": "scalar", "result": [TS, "42"]}).scalar == (TS, "42")
    histogram = {"count": "3", "sum": "1.5", "buckets": []}
    parsed = parse_result({"resultType": "vector", "result": [{"metric": {}, "histogram": [TS, histogram]}]})
    assert parsed.series[0].histograms == [(TS, histogram)]


@pytest.mark.parametrize(
    "data",
    [None, {}, {"resultType": "vector"}, {"resultType": "weird", "result": []}, {"resultType": "scalar", "result": 1}],
)
def test_unreadable_results(data: object) -> None:
    with pytest.raises(BackendQueryError, match="cannot read"):
        parse_result(data)


def test_series_name() -> None:
    assert series_name({"__name__": "up", "job": "a", "instance": "h:9100"}) == 'up{job="a", instance="h:9100"}'
    assert series_name({"__name__": "up"}) == "up"
    assert series_name({"job": 'say "hi"\\n'}) == '{job="say \\"hi\\"\\\\n"}'
    assert series_name({}) == "{}"


def test_block_writer_keeps_the_first_block_and_stops_at_the_budget() -> None:
    writer = BlockWriter(10)
    assert writer.add("x" * 50) is True
    assert writer.add("y") is False
    assert (writer.kept, writer.text()) == (1, "x" * 50)


def test_truncation_note_reasons() -> None:
    assert truncation_note(3, 3, 100) == ""
    assert "the limit is 2" in truncation_note(2, 3, 2)
    assert "the response size limit was reached" in truncation_note(1, 3, 2, unit="metrics", hint="Narrow.")
    assert truncation_note(1, 3, 2, unit="metrics", hint="Narrow.").endswith(
        "3 metrics: the response size limit was reached. Narrow.]"
    )


def test_helpers() -> None:
    assert response_budget(65536) == 64512
    assert response_budget(1024) == 512
    assert with_notes("x", []) == "x"
    assert with_notes("x", ["warning: a"]) == "x\n\nNotes from Prometheus:\n- warning: a"
    assert cell("a|b\nc") == "a\\|b c"
    assert cell("z" * 400).endswith("…")
    assert short_time("2026-11-22T09:12:00.123456789Z") == "2026-11-22T09:12:00Z"
    assert short_time("0001-01-01T00:00:00Z") == "never"


def test_instant_vector() -> None:
    result = parse_result(vector(({"__name__": "up", "job": "a"}, "1"), ({"__name__": "up", "job": "b"}, "0")))
    text, shown = format_instant(result, at=NOW, max_series=100, budget=10_000)
    assert text == 'vector: 2 series at 2026-11-22T10:00:00Z\nup{job="a"} 1\nup{job="b"} 0'
    assert shown == 2


def test_instant_vector_keeps_the_server_order_and_caps_series() -> None:
    result = parse_result(vector(*(({"i": str(i)}, str(i)) for i in (3, 1, 2))))
    text, shown = format_instant(result, at=NOW, max_series=2, budget=10_000)
    assert text.splitlines()[1:3] == ['{i="3"} 3', '{i="1"} 1']
    assert shown == 2
    assert text.endswith(
        "[Showing 2 of 3 series: the limit is 2. Select fewer series with label matchers, or aggregate "
        "(sum by (...), topk(10, ...)).]"
    )


def test_instant_vector_stops_at_the_byte_budget() -> None:
    result = parse_result(vector(*(({"name": "n" * 100, "i": str(i)}, "1") for i in range(50))))
    text, shown = format_instant(result, at=NOW, max_series=100, budget=1000)
    assert 0 < shown < 50
    assert f"[Showing {shown} of 50 series: the response size limit was reached." in text


def test_instant_scalar_and_empty() -> None:
    scalar = parse_result({"resultType": "scalar", "result": [TS, "2"]})
    assert format_instant(scalar, at=NOW, max_series=100, budget=1000) == ("scalar: 2 at 2026-11-22T10:00:00Z", 1)
    text, shown = format_instant(parse_result(vector()), at=NOW, max_series=100, budget=1000)
    assert text.startswith("vector: no series at 2026-11-22T10:00:00Z. Nothing matched")
    assert shown == 0


def test_instant_native_histogram() -> None:
    data = {
        "resultType": "vector",
        "result": [{"metric": {"__name__": "h"}, "histogram": [TS, {"count": "3", "sum": "1.5"}]}],
    }
    text, _ = format_instant(parse_result(data), at=NOW, max_series=100, budget=1000)
    assert text.endswith("h histogram(count=3, sum=1.5)")
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_formatting.py -q`
Expected: `ModuleNotFoundError: No module named 'ratatoskr.backends.prometheus.formatting'`.

- [ ] **Step 3: Implement the parser**

Create `src/ratatoskr/backends/prometheus/series.py`:

```python
"""Parse Prometheus query results into small typed values; render series names the way PromQL writes them."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ratatoskr.backends.errors import BackendQueryError

Sample = tuple[float, str]  # (unix time, value exactly as Prometheus wrote it: "1", "0.25", "NaN", "+Inf")
HistogramSample = tuple[float, dict[str, Any]]  # native histogram: count, sum, buckets


@dataclass(frozen=True)
class Series:
    labels: dict[str, str]
    values: list[Sample] = field(default_factory=list)
    histograms: list[HistogramSample] = field(default_factory=list)


@dataclass(frozen=True)
class QueryResult:
    result_type: str  # vector | matrix | scalar | string
    series: list[Series]
    scalar: Sample | None = None


def parse_result(data: Any) -> QueryResult:
    try:
        return _parse(data)
    except (KeyError, IndexError, TypeError, ValueError):
        raise _unreadable() from None


def _parse(data: Any) -> QueryResult:
    result_type, raw = data["resultType"], data["result"]
    if result_type in ("scalar", "string"):
        return QueryResult(result_type=result_type, series=[], scalar=_sample(raw))
    if result_type in ("vector", "matrix") and isinstance(raw, list):
        return QueryResult(result_type=result_type, series=[_series(item, result_type) for item in raw])
    raise _unreadable()


def _series(item: dict[str, Any], result_type: str) -> Series:
    labels = {str(key): str(value) for key, value in (item.get("metric") or {}).items()}
    if result_type == "vector":
        values = [_sample(item["value"])] if "value" in item else []
        histograms = [_histogram(item["histogram"])] if "histogram" in item else []
    else:
        values = [_sample(point) for point in item.get("values") or []]
        histograms = [_histogram(point) for point in item.get("histograms") or []]
    return Series(labels=labels, values=values, histograms=histograms)


def _sample(point: Any) -> Sample:
    ts, value = point
    return float(ts), str(value)


def _histogram(point: Any) -> HistogramSample:
    ts, value = point
    if not isinstance(value, dict):
        raise TypeError("histogram")
    return float(ts), value


def _unreadable() -> BackendQueryError:
    return BackendQueryError("Prometheus returned a result in a shape Ratatoskr cannot read.")


def series_name(labels: Mapping[str, str]) -> str:
    """``up{instance="a:9100", job="node"}``; ``{}`` for a series without name and labels."""
    name = labels.get("__name__", "")
    pairs = ", ".join(f'{key}="{escape_label_value(value)}"' for key, value in labels.items() if key != "__name__")
    if not pairs and name:
        return name
    return f"{name}{{{pairs}}}"


def escape_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def histogram_text(histogram: Mapping[str, Any]) -> str:
    return f"histogram(count={histogram.get('count', '?')}, sum={histogram.get('sum', '?')})"
```

- [ ] **Step 4: Implement the formatting helpers**

Create `src/ratatoskr/backends/prometheus/formatting.py`:

```python
"""Compact text for an LLM reader: the byte-budgeted block writer, truncation notes and instant results."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from ratatoskr.backends.prometheus.api import SERIES_HINT
from ratatoskr.backends.prometheus.series import QueryResult, Series, histogram_text, series_name
from ratatoskr.backends.timeparse import format_time

# Room kept for the truncation note and server notes, so they are never the part that gets clamped.
NOTE_RESERVE_BYTES = 1024
_FRACTION_RE = re.compile(r"\.\d+(?=Z$|[+-]\d{2}:\d{2}$)")
_NEVER = "0001-01-01T00:00:00Z"


class BlockWriter:
    """Collects blocks until the byte budget is spent. The first block is always kept."""

    def __init__(self, budget: int) -> None:
        self._budget = budget
        self._blocks: list[str] = []
        self._size = 0

    @property
    def kept(self) -> int:
        return len(self._blocks)

    def add(self, block: str) -> bool:
        size = len(block.encode("utf-8")) + 1
        if self._blocks and self._size + size > self._budget:
            return False
        self._blocks.append(block)
        self._size += size
        return True

    def text(self) -> str:
        return "\n".join(self._blocks)


def response_budget(max_response_bytes: int) -> int:
    return max(512, max_response_bytes - NOTE_RESERVE_BYTES)


def truncation_note(shown: int, total: int, limit: int, *, unit: str = "series", hint: str = SERIES_HINT) -> str:
    """Empty when everything is shown; otherwise says how many were left out, why, and how to narrow."""
    if shown >= total:
        return ""
    reason = f"the limit is {limit}" if shown >= limit else "the response size limit was reached"
    return f"\n\n[Showing {shown} of {total} {unit}: {reason}. {hint}]"


def with_notes(text: str, notes: Sequence[str]) -> str:
    if not notes:
        return text
    return text + "\n\nNotes from Prometheus:\n" + "\n".join(f"- {note}" for note in notes)


def cell(value: Any, limit: int = 300) -> str:
    """One Markdown table cell: pipes escaped, line breaks flattened, long text cut."""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", "").replace("\n", " ")
    return text if len(text) <= limit else text[:limit] + "…"


def short_time(value: Any) -> str:
    """A server RFC3339 time without its fraction (``2026-11-22T09:12:00Z``); ``never`` for Go's zero time."""
    text = _FRACTION_RE.sub("", str(value or ""))
    return "never" if not text or text == _NEVER else text


def instant_line(series: Series) -> str:
    name = series_name(series.labels)
    if series.histograms:
        return f"{name} {histogram_text(series.histograms[-1][1])}"
    if series.values:
        return f"{name} {series.values[-1][1]}"
    return name


def format_instant(result: QueryResult, *, at: datetime, max_series: int, budget: int) -> tuple[str, int]:
    """Text and number of series shown for a vector, scalar or string result."""
    when = format_time(at)
    if result.result_type in ("scalar", "string"):
        value = result.scalar[1] if result.scalar is not None else "-"
        return f"{result.result_type}: {value} at {when}", 1
    total = len(result.series)
    if total == 0:
        return (
            f"{result.result_type}: no series at {when}. Nothing matched at that time: check metric and label "
            "names with prom_list_metrics and prom_label_values, or look at a past window with prom_query_range.",
            0,
        )
    writer = BlockWriter(budget)
    writer.add(f"{result.result_type}: {total} series at {when}")
    for series in result.series[:max_series]:
        if not writer.add(instant_line(series)):
            break
    shown = writer.kept - 1
    return writer.text() + truncation_note(shown, total, max_series), shown
```

- [ ] **Step 5: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_formatting.py -q` — all pass. mypy, ruff clean.

- [ ] **Step 6: Commit**

```bash
git add src/ratatoskr/backends/prometheus/series.py src/ratatoskr/backends/prometheus/formatting.py tests/unit/test_prom_formatting.py
git commit -m "Parse Prometheus results and format instant queries compactly" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: Range summaries

**Files:**
- Create: `src/ratatoskr/backends/prometheus/summarize.py`
- Test: `tests/unit/test_prom_summarize.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_prom_summarize.py`:

```python
import math

from ratatoskr.backends.prometheus.series import Series, parse_result
from ratatoskr.backends.prometheus.summarize import (
    format_matrix,
    number,
    sample_indexes,
    samples_per_series,
    series_block,
    summarize,
)
from tests.unit.prom_helpers import TS, matrix


def test_summarize_keeps_raw_min_max_and_skips_nan() -> None:
    summary = summarize([(1.0, "3"), (2.0, "NaN"), (3.0, "1e+03"), (4.0, "0.5")])
    assert (summary.points, summary.nan, summary.minimum, summary.maximum) == (4, 1, "0.5", "1e+03")
    assert summary.average is not None and math.isclose(summary.average, 1003.5 / 3)
    assert summary.last == (4.0, "0.5")


def test_summarize_all_nan() -> None:
    summary = summarize([(1.0, "NaN")])
    assert (summary.minimum, summary.maximum, summary.average) == (None, None, None)


def test_number() -> None:
    assert [number(x) for x in (3.0, 2 / 3, math.inf, -math.inf, math.nan, 1e20)] == [
        "3",
        "0.666667",
        "+Inf",
        "-Inf",
        "NaN",
        "1e+20",
    ]


def test_sample_indexes() -> None:
    assert sample_indexes(5, 10) == [0, 1, 2, 3, 4]
    assert sample_indexes(121, 5) == [0, 30, 60, 90, 120]
    assert sample_indexes(10, 1) == [9]


def test_samples_per_series_shrinks_with_more_series() -> None:
    assert [samples_per_series(n) for n in (1, 4, 10, 20, 100)] == [60, 60, 24, 12, 6]


def test_series_block() -> None:
    series = Series({"__name__": "up", "job": "api"}, [(TS - 60, "1"), (TS - 30, "0"), (TS, "1")])
    assert series_block(series, expected=121, samples=60, same_day=True) == (
        'up{job="api"}\n'
        "  3 points, 118 steps without data, min 0, max 1, avg 0.666667, last 1 at 10:00:00\n"
        "  samples: 09:59:00=1 09:59:30=0 10:00:00=1"
    )


def test_series_block_across_days_shows_the_date() -> None:
    block = series_block(Series({}, [(TS, "1")]), expected=None, samples=60, same_day=False)
    assert block.endswith("samples: 11-22T10:00:00=1")


def test_format_matrix_caps_series() -> None:
    result = parse_result(matrix(*(({"i": str(i)}, [(TS, "1")]) for i in range(5))))
    text, shown = format_matrix(
        result, header="matrix: 5 series", expected=1, same_day=True, max_series=2, budget=10_000
    )
    assert text.startswith('matrix: 5 series\n{i="0"}\n  1 points, min 1, max 1, avg 1, last 1 at 10:00:00')
    assert shown == 2
    assert "[Showing 2 of 5 series: the limit is 2." in text


def test_format_matrix_empty() -> None:
    text, shown = format_matrix(
        parse_result(matrix()), header="matrix: 0 series", expected=121, same_day=True, max_series=100, budget=1000
    )
    assert (
        text
        == "matrix: 0 series\nNo series had data in this window: check metric and label names with prom_list_metrics."
    )
    assert shown == 0
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_summarize.py -q`
Expected: `ModuleNotFoundError: No module named 'ratatoskr.backends.prometheus.summarize'`.

- [ ] **Step 3: Implement**

Create `src/ratatoskr/backends/prometheus/summarize.py`:

```python
"""Range results as per-series summaries (points, min, max, avg, last) plus evenly spaced sample points."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from ratatoskr.backends.prometheus.formatting import BlockWriter, truncation_note
from ratatoskr.backends.prometheus.series import QueryResult, Sample, Series, histogram_text, series_name

MIN_SAMPLES = 6
MAX_SAMPLES = 60
SAMPLE_BUDGET = 240  # sample points shared by all series shown


@dataclass(frozen=True)
class Summary:
    points: int
    nan: int
    minimum: str | None  # as Prometheus wrote the value
    maximum: str | None
    average: float | None
    last: Sample | None


def summarize(values: Sequence[Sample]) -> Summary:
    """NaN samples are counted but left out of min, max and avg."""
    nan = counted = 0
    total = 0.0
    low: tuple[float, str] | None = None
    high: tuple[float, str] | None = None
    for _, raw in values:
        number = _float(raw)
        if math.isnan(number):
            nan += 1
            continue
        if low is None or number < low[0]:
            low = (number, raw)
        if high is None or number > high[0]:
            high = (number, raw)
        total += number
        counted += 1
    return Summary(
        points=len(values),
        nan=nan,
        minimum=low[1] if low else None,
        maximum=high[1] if high else None,
        average=total / counted if counted else None,
        last=values[-1] if values else None,
    )


def _float(raw: str) -> float:
    try:
        return float(raw)
    except ValueError:
        return math.nan


def number(value: float) -> str:
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "+Inf" if value > 0 else "-Inf"
    if value.is_integer() and abs(value) < 1e15:
        return str(int(value))
    return f"{value:.6g}"


def sample_indexes(count: int, wanted: int) -> list[int]:
    """Up to *wanted* evenly spaced indexes into *count* points, always including the first and the last."""
    if count <= wanted:
        return list(range(count))
    if wanted <= 1:
        return [count - 1]
    return sorted({round(i * (count - 1) / (wanted - 1)) for i in range(wanted)})


def samples_per_series(series_count: int) -> int:
    return max(MIN_SAMPLES, min(MAX_SAMPLES, SAMPLE_BUDGET // max(1, series_count)))


def clock(ts: float, *, same_day: bool) -> str:
    moment = datetime.fromtimestamp(ts, UTC)
    return moment.strftime("%H:%M:%S" if same_day else "%m-%dT%H:%M:%S")


def series_block(series: Series, *, expected: int | None, samples: int, same_day: bool) -> str:
    lines = [series_name(series.labels)]
    if series.values:
        summary = summarize(series.values)
        parts = [f"{summary.points} points"]
        if expected is not None and expected > summary.points:
            parts.append(f"{expected - summary.points} steps without data")
        if summary.nan:
            parts.append(f"{summary.nan} NaN")
        if summary.minimum is not None and summary.average is not None:
            parts += [f"min {summary.minimum}", f"max {summary.maximum}", f"avg {number(summary.average)}"]
        if summary.last is not None:
            parts.append(f"last {summary.last[1]} at {clock(summary.last[0], same_day=same_day)}")
        lines.append("  " + ", ".join(parts))
        picked = (series.values[index] for index in sample_indexes(len(series.values), samples))
        lines.append("  samples: " + " ".join(f"{clock(ts, same_day=same_day)}={value}" for ts, value in picked))
    if series.histograms:
        ts, histogram = series.histograms[-1]
        lines.append(
            f"  native histogram: {len(series.histograms)} samples, last {histogram_text(histogram)} "
            f"at {clock(ts, same_day=same_day)}"
        )
    return "\n".join(lines)


def format_matrix(
    result: QueryResult, *, header: str, expected: int | None, same_day: bool, max_series: int, budget: int
) -> tuple[str, int]:
    """Text and number of series shown. *expected* is the number of steps in the range (None: raw samples)."""
    total = len(result.series)
    if total == 0:
        no_data = "No series had data in this window: check metric and label names with prom_list_metrics."
        return f"{header}\n{no_data}", 0
    writer = BlockWriter(budget)
    writer.add(header)
    samples = samples_per_series(min(total, max_series))
    for series in result.series[:max_series]:
        if not writer.add(series_block(series, expected=expected, samples=samples, same_day=same_day)):
            break
    shown = writer.kept - 1
    return writer.text() + truncation_note(shown, total, max_series), shown
```

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_summarize.py -q` — all pass. mypy, ruff clean.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/prometheus/summarize.py tests/unit/test_prom_summarize.py
git commit -m "Summarise range results per series with sampled points" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 11: `prom_query` / `prom_query_range` logic

**Files:**
- Create: `src/ratatoskr/backends/prometheus/querying.py`
- Test: `tests/unit/test_prom_querying.py`

Arguments are checked before any request (empty or too long PromQL, unparsable times, a window over `max_range`, a
step over `max_points`), so a bad call costs Prometheus nothing.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_prom_querying.py`:

```python
from urllib.parse import parse_qs

import pytest
import respx

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.prometheus import querying
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import TS, make_backend, matrix, success, vector


def _form(route: respx.Route) -> dict[str, list[str]]:
    return parse_qs(route.calls.last.request.content.decode())


async def test_instant_query_at_now(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.post("/api/v1/query").mock(
        return_value=success(vector(({"__name__": "up", "job": "api", "instance": "a:9100"}, "1")))
    )
    output = await querying.instant_query(prom_backend, "  up ", None)
    assert _form(route) == {"query": ["up"], "time": ["1795341600.000"], "timeout": ["30s"]}
    assert output.text == 'vector: 1 series at 2026-11-22T10:00:00Z\nup{job="api", instance="a:9100"} 1'
    assert output.rows == 1


async def test_instant_query_at_a_relative_time(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.post("/api/v1/query").mock(return_value=success(vector()))
    output = await querying.instant_query(prom_backend, "up", "now-1h")
    assert _form(route)["time"] == ["1795338000.000"]
    assert output.text.startswith("vector: no series at 2026-11-22T09:00:00Z.")
    assert output.rows == 0


async def test_instant_query_of_a_range_vector_lists_raw_samples(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.post("/api/v1/query").mock(return_value=success(matrix(({"job": "a"}, [(TS - 15, "1"), (TS, "2")]))))
    output = await querying.instant_query(prom_backend, "up[1m]", None)
    assert output.text.splitlines() == [
        "matrix: 1 series of raw samples up to 2026-11-22T10:00:00Z (times are UTC)",
        '{job="a"}',
        "  2 points, min 1, max 2, avg 1.5, last 2 at 11-22T10:00:00",
        "  samples: 11-22T09:59:45=1 11-22T10:00:00=2",
    ]


async def test_server_notes_are_appended(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.post("/api/v1/query").mock(return_value=success(vector(), warnings=["partial response"]))
    output = await querying.instant_query(prom_backend, "up", None)
    assert output.text.endswith("Notes from Prometheus:\n- warning: partial response")


@pytest.mark.parametrize(
    ("promql", "expected"),
    [("   ", "promql is empty"), ("x" * 20_001, "promql is 20001 characters long; the limit")],
)
async def test_promql_is_checked_before_any_request(
    prom_api: respx.Router, prom_backend: PrometheusBackend, promql: str, expected: str
) -> None:
    with pytest.raises(InvalidRequestError, match=expected):
        await querying.instant_query(prom_backend, promql, None)
    assert prom_api.calls.call_count == 0


async def test_range_query_defaults_to_the_last_hour(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.post("/api/v1/query_range").mock(
        return_value=success(matrix(({"__name__": "up", "job": "api"}, [(TS - 60, "1"), (TS - 30, "0"), (TS, "1")])))
    )
    output = await querying.range_query(prom_backend, "up", None, None, None)
    assert _form(route) == {
        "query": ["up"],
        "start": ["1795338000.000"],
        "end": ["1795341600.000"],
        "step": ["30"],
        "timeout": ["30s"],
    }
    assert output.text.splitlines() == [
        "matrix: 1 series from 2026-11-22T09:00:00Z to 2026-11-22T10:00:00Z, step 30s "
        "(up to 121 points per series; times are UTC)",
        'up{job="api"}',
        "  3 points, 118 steps without data, min 0, max 1, avg 0.666667, last 1 at 10:00:00",
        "  samples: 09:59:00=1 09:59:30=0 10:00:00=1",
    ]
    assert output.rows == 1


async def test_range_query_with_explicit_window_and_step(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    route = prom_api.post("/api/v1/query_range").mock(return_value=success(matrix()))
    output = await querying.range_query(prom_backend, "up", "2026-11-21T10:00:00Z", "now", "15m")
    assert _form(route)["step"] == ["900"]
    assert "step 15m (up to 97 points per series" in output.text


async def test_range_query_refuses_too_many_points_without_a_request(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    with pytest.raises(InvalidRequestError, match="step 1s gives 3601 points per series"):
        await querying.range_query(prom_backend, "up", None, None, "1s")
    assert prom_api.calls.call_count == 0


async def test_range_query_refuses_a_range_over_the_limit(prom_api: respx.Router) -> None:
    backend = make_backend(limits={"max_range": "1d"})
    await backend.open()
    with pytest.raises(InvalidRequestError, match="The range is 2d; this connection allows at most 1d"):
        await querying.range_query(backend, "up", "now-2d", None, None)
    await backend.close()
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_querying.py -q`
Expected: `ImportError: cannot import name 'querying' from 'ratatoskr.backends.prometheus'`.

- [ ] **Step 3: Implement**

Create `src/ratatoskr/backends/prometheus/querying.py`:

```python
"""prom_query and prom_query_range: check the arguments, resolve the times, call the API and format."""

from __future__ import annotations

from ratatoskr.backends.errors import BackendQueryError, InvalidRequestError
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.prometheus.formatting import format_instant, response_budget, with_notes
from ratatoskr.backends.prometheus.series import parse_result
from ratatoskr.backends.prometheus.summarize import format_matrix
from ratatoskr.backends.timeparse import (
    format_duration,
    format_time,
    parse_time,
    point_count,
    resolve_range,
    resolve_step,
    step_seconds,
    unix_seconds,
)
from ratatoskr.config.prometheus_models import PrometheusLimits
from ratatoskr.tools.runtime import ToolOutput


def check_promql(promql: str, limits: PrometheusLimits) -> str:
    text = promql.strip()
    if not text:
        raise InvalidRequestError(
            "promql is empty: pass a PromQL expression such as up or rate(http_requests_total[5m])."
        )
    if len(promql) > limits.max_query_length:
        raise InvalidRequestError(
            f"promql is {len(promql)} characters long; the limit for this connection is {limits.max_query_length}."
        )
    return text


async def instant_query(backend: PrometheusBackend, promql: str, time: str | None) -> ToolOutput:
    limits = backend.limits
    query = check_promql(promql, limits)
    now = backend.now()
    at = now if time is None else parse_time(time, now=now, argument="time")
    result = await backend.api.query(query, unix_seconds(at))
    parsed = parse_result(result.data)
    budget = response_budget(limits.max_response_bytes)
    if parsed.result_type == "matrix":  # a range vector selector such as up[5m]: raw samples
        header = f"matrix: {len(parsed.series)} series of raw samples up to {format_time(at)} (times are UTC)"
        text, shown = format_matrix(
            parsed, header=header, expected=None, same_day=False, max_series=limits.max_series, budget=budget
        )
    else:
        text, shown = format_instant(parsed, at=at, max_series=limits.max_series, budget=budget)
    return ToolOutput(text=with_notes(text, result.notes), rows=shown)


async def range_query(
    backend: PrometheusBackend, promql: str, start: str | None, end: str | None, step: str | None
) -> ToolOutput:
    limits = backend.limits
    query = check_promql(promql, limits)
    window = resolve_range(start, end, now=backend.now(), max_range=limits.max_range)
    chosen = resolve_step(step, window.span, max_points=limits.max_points)
    result = await backend.api.query_range(
        query, unix_seconds(window.start), unix_seconds(window.end), step_seconds(chosen)
    )
    parsed = parse_result(result.data)
    if parsed.result_type != "matrix":
        raise BackendQueryError(f"Prometheus answered a range query with a {parsed.result_type} result.")
    expected = point_count(window.span, chosen)
    header = (
        f"matrix: {len(parsed.series)} series from {format_time(window.start)} to {format_time(window.end)}, "
        f"step {format_duration(chosen)} (up to {expected} points per series; times are UTC)"
    )
    text, shown = format_matrix(
        parsed,
        header=header,
        expected=expected,
        same_day=window.start.date() == window.end.date(),
        max_series=limits.max_series,
        budget=response_budget(limits.max_response_bytes),
    )
    return ToolOutput(text=with_notes(text, result.notes), rows=shown)
```

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_querying.py -q` — 10 passed. mypy, ruff clean.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/prometheus/querying.py tests/unit/test_prom_querying.py
git commit -m "Add instant and range PromQL queries" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 12: `prom_list_metrics` / `prom_label_values` logic

**Files:**
- Create: `src/ratatoskr/backends/prometheus/discovery.py`
- Test: `tests/unit/test_prom_discovery.py`

Metric names come from `/api/v1/label/__name__/values` (window + optional `match[]`), filtered client-side by
`name_contains`; type/help/unit from one `/api/v1/metadata?limit_per_metric=1` call. Metadata is optional: a failure or
an empty answer (VictoriaMetrics) only adds a note.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_prom_discovery.py`:

```python
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.prometheus import discovery
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import make_backend, success

NAMES = ["go_goroutines", "http_requests_total", "process_cpu_seconds_total", "up"]
METADATA = {
    "http_requests_total": [{"type": "counter", "help": "Requests | by code", "unit": ""}],
    "process_cpu_seconds_total": [{"type": "counter", "help": "CPU time.", "unit": "seconds"}],
    "up": [{"type": "gauge", "help": "Target is up.", "unit": ""}],
}
WINDOW = "with data between 2026-11-22T09:00:00Z and 2026-11-22T10:00:00Z"


async def test_list_metrics_joins_names_and_metadata(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    names = prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(NAMES))
    prom_api.get("/api/v1/metadata").mock(return_value=success(METADATA))
    output = await discovery.list_metrics(prom_backend, match=None, name_contains=None, start=None, end=None)
    assert parse_qs(names.calls.last.request.url.query.decode()) == {
        "start": ["1795338000.000"],
        "end": ["1795341600.000"],
    }
    assert output.text.splitlines() == [
        f"4 metric names {WINDOW}.",
        "| metric | type | help |",
        "| --- | --- | --- |",
        "| go_goroutines | - | - |",
        "| http_requests_total | counter | Requests \\| by code |",
        "| process_cpu_seconds_total | counter (seconds) | CPU time. |",
        "| up | gauge | Target is up. |",
    ]
    assert output.rows == 4


async def test_list_metrics_filters_by_text_and_selector(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    names = prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(NAMES))
    prom_api.get("/api/v1/metadata").mock(return_value=success(METADATA))
    output = await discovery.list_metrics(prom_backend, match='{job="api"}', name_contains="HTTP", start=None, end=None)
    assert parse_qs(names.calls.last.request.url.query.decode())["match[]"] == ['{job="api"}']
    assert output.text.startswith(f'1 metric names containing "HTTP" in series matching {{job="api"}} {WINDOW}.')
    assert output.rows == 1


async def test_list_metrics_caps_the_list(prom_api: respx.Router) -> None:
    backend = make_backend(limits={"max_values": 2})
    await backend.open()
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(NAMES))
    prom_api.get("/api/v1/metadata").mock(return_value=success(METADATA))
    output = await discovery.list_metrics(backend, match=None, name_contains=None, start=None, end=None)
    assert output.rows == 2
    assert output.text.endswith(
        "[Showing 2 of 4 metrics: the limit is 2. Pass name_contains or match to narrow the list.]"
    )
    await backend.close()


async def test_list_metrics_without_metadata_still_lists_names(
    prom_api: respx.Router, prom_backend: PrometheusBackend
) -> None:
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(["up"]))
    prom_api.get("/api/v1/metadata").mock(return_value=httpx.Response(404, text="not found"))
    output = await discovery.list_metrics(prom_backend, match=None, name_contains=None, start=None, end=None)
    assert "| up | - | - |" in output.text
    assert "Type and help are unavailable: Connection 'prom' answered HTTP 404" in output.text


async def test_list_metrics_notes_empty_metadata(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(["up"]))
    prom_api.get("/api/v1/metadata").mock(return_value=success({}))
    output = await discovery.list_metrics(prom_backend, match=None, name_contains=None, start=None, end=None)
    assert output.text.endswith("This server returned no metadata (type and help) for its metrics.")


async def test_list_metrics_nothing_found(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(NAMES))
    output = await discovery.list_metrics(prom_backend, match=None, name_contains="nginx", start=None, end=None)
    assert output.text == f'No metric names containing "nginx" {WINDOW}. Widen the time range or loosen the filter.'
    assert output.rows == 0


async def test_label_values(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    route = prom_api.get("/api/v1/label/job/values").mock(return_value=success(["api", "node"]))
    output = await discovery.label_values(prom_backend, label="job", match="up", start="now-6h", end=None)
    query = parse_qs(route.calls.last.request.url.query.decode())
    assert (query["match[]"], query["start"]) == (["up"], ["1795320000.000"])
    assert output.text == (
        '2 values of label "job" on series matching up between 2026-11-22T04:00:00Z and 2026-11-22T10:00:00Z:'
        "\napi\nnode"
    )
    assert output.rows == 2


async def test_label_values_empty(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/label/team/values").mock(return_value=success([]))
    output = await discovery.label_values(prom_backend, label="team", match=None, start=None, end=None)
    assert output.text.startswith('No values of label "team" between')
    assert output.rows == 0


@pytest.mark.parametrize("label", ["job name", "../admin", "0abc", ""])
async def test_label_name_is_checked_before_any_request(
    prom_api: respx.Router, prom_backend: PrometheusBackend, label: str
) -> None:
    with pytest.raises(InvalidRequestError, match="Invalid label name"):
        await discovery.label_values(prom_backend, label=label, match=None, start=None, end=None)
    assert prom_api.calls.call_count == 0
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_discovery.py -q`
Expected: `ImportError: cannot import name 'discovery'`.

- [ ] **Step 3: Implement**

Create `src/ratatoskr/backends/prometheus/discovery.py`:

```python
"""prom_list_metrics and prom_label_values: names and values with data in a time window (default last hour)."""

from __future__ import annotations

import re
from typing import Any

from ratatoskr.backends.errors import BackendError, BackendQueryError, InvalidRequestError
from ratatoskr.backends.limits import clip_input
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.prometheus.formatting import (
    BlockWriter,
    cell,
    response_budget,
    truncation_note,
    with_notes,
)
from ratatoskr.backends.timeparse import TimeRange, format_time, resolve_range, unix_seconds
from ratatoskr.config.prometheus_models import PrometheusLimits
from ratatoskr.tools.runtime import ToolOutput

LABEL_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
HELP_CHARS = 160
METRICS_HINT = "Pass name_contains or match to narrow the list."
VALUES_HINT = 'Pass a match selector such as {job="api"} or a shorter time range.'


def check_selector(match: str | None, limits: PrometheusLimits) -> str | None:
    if match is None or not match.strip():
        return None
    if len(match) > limits.max_query_length:
        raise InvalidRequestError(
            f"match is {len(match)} characters long; the limit for this connection is {limits.max_query_length}."
        )
    return match.strip()


async def list_metrics(
    backend: PrometheusBackend, *, match: str | None, name_contains: str | None, start: str | None, end: str | None
) -> ToolOutput:
    limits = backend.limits
    selector = check_selector(match, limits)
    window = resolve_range(start, end, now=backend.now(), max_range=limits.max_range)
    result = await backend.api.label_values(
        "__name__", match=selector, start=unix_seconds(window.start), end=unix_seconds(window.end)
    )
    names = _strings(result.data)
    if name_contains and name_contains.strip():
        needle = name_contains.strip().casefold()
        names = [name for name in names if needle in name.casefold()]
    scope = _metric_scope(selector, name_contains, window)
    if not names:
        return ToolOutput(text=f"No metric names {scope}. Widen the time range or loosen the filter.", rows=0)
    metadata, metadata_note = await _metadata(backend)
    writer = BlockWriter(response_budget(limits.max_response_bytes))
    writer.add(f"{len(names)} metric names {scope}.")
    writer.add("| metric | type | help |\n| --- | --- | --- |")
    for name in names[: limits.max_values]:
        if not writer.add(_metric_row(name, metadata.get(name, {}))):
            break
    shown = writer.kept - 2
    text = writer.text() + truncation_note(shown, len(names), limits.max_values, unit="metrics", hint=METRICS_HINT)
    if metadata_note:
        text += f"\n\n{metadata_note}"
    return ToolOutput(text=with_notes(text, result.notes), rows=shown)


async def label_values(
    backend: PrometheusBackend, *, label: str, match: str | None, start: str | None, end: str | None
) -> ToolOutput:
    limits = backend.limits
    name = label.strip()
    if not LABEL_NAME_RE.match(name):
        raise InvalidRequestError(
            f"Invalid label name '{clip_input(label)}': use letters, digits and underscores, e.g. job, instance "
            "or __name__."
        )
    selector = check_selector(match, limits)
    window = resolve_range(start, end, now=backend.now(), max_range=limits.max_range)
    result = await backend.api.label_values(
        name, match=selector, start=unix_seconds(window.start), end=unix_seconds(window.end)
    )
    values = _strings(result.data)
    matching = f" on series matching {selector}" if selector else ""
    scope = f'of label "{name}"{matching} between {format_time(window.start)} and {format_time(window.end)}'
    if not values:
        return ToolOutput(
            text=f"No values {scope}. The label may not exist on series with data in this window.", rows=0
        )
    writer = BlockWriter(response_budget(limits.max_response_bytes))
    writer.add(f"{len(values)} values {scope}:")
    for value in values[: limits.max_values]:
        if not writer.add(value.replace("\n", "\\n")):
            break
    shown = writer.kept - 1
    text = writer.text() + truncation_note(shown, len(values), limits.max_values, unit="values", hint=VALUES_HINT)
    return ToolOutput(text=with_notes(text, result.notes), rows=shown)


def _strings(data: Any) -> list[str]:
    if not isinstance(data, list):
        raise BackendQueryError("Prometheus returned a list in a shape Ratatoskr cannot read.")
    return [str(item) for item in data]


def _metric_scope(selector: str | None, contains: str | None, window: TimeRange) -> str:
    parts = []
    if contains and contains.strip():
        parts.append(f'containing "{contains.strip()}"')
    if selector:
        parts.append(f"in series matching {selector}")
    parts.append(f"with data between {format_time(window.start)} and {format_time(window.end)}")
    return " ".join(parts)


async def _metadata(backend: PrometheusBackend) -> tuple[dict[str, dict[str, str]], str | None]:
    """Type, help and unit per metric name. Metadata is optional: a failure only adds a note."""
    try:
        result = await backend.api.metadata()
    except BackendError as exc:
        return {}, f"Type and help are unavailable: {exc}"
    found: dict[str, dict[str, str]] = {}
    if isinstance(result.data, dict):
        for name, entries in result.data.items():
            if isinstance(entries, list) and entries and isinstance(entries[0], dict):
                found[str(name)] = {str(key): str(value) for key, value in entries[0].items()}
    if not found:
        return found, "This server returned no metadata (type and help) for its metrics."
    return found, None


def _metric_row(name: str, meta: dict[str, str]) -> str:
    kind = meta.get("type") or "-"
    if meta.get("unit"):
        kind = f"{kind} ({meta['unit']})"
    return f"| {cell(name)} | {cell(kind)} | {cell(meta.get('help') or '-', HELP_CHARS)} |"
```

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_discovery.py -q` — 12 passed. mypy, ruff clean.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/prometheus/discovery.py tests/unit/test_prom_discovery.py
git commit -m "List metric names with metadata and label values" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 13: `prom_alerts` logic

**Files:**
- Create: `src/ratatoskr/backends/prometheus/alerts.py`
- Test: `tests/unit/test_prom_alerts.py`

Firing alerts first, then pending, then by name; the rule-group table counts alerting/recording rules, firing/pending
alerting rules and unhealthy rules (`health: err`), and lists unhealthy rules with their scrubbed `lastError`. Only the
file *name* of a rule group is shown, not the server's path. If `/api/v1/rules` fails, the alerts are still shown.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_prom_alerts.py`:

```python
from typing import Any

import respx

from ratatoskr.backends.prometheus import alerts
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from tests.unit.prom_helpers import api_error, success

ALERTS = {
    "alerts": [
        {
            "labels": {"alertname": "DiskFilling", "severity": "warning", "instance": "db-1"},
            "annotations": {"description": "Disk is 85% full"},
            "state": "pending",
            "activeAt": "2026-11-22T09:50:00.5Z",
        },
        {
            "labels": {"alertname": "HighErrorRate", "severity": "critical", "job": "api"},
            "annotations": {"summary": "5xx above 5% | for 10m"},
            "state": "firing",
            "activeAt": "2026-11-22T09:12:00.123456789Z",
        },
    ]
}
RULES: dict[str, Any] = {
    "groups": [
        {
            "name": "api",
            "file": "/etc/prometheus/rules/api.yml",
            "interval": 30,
            "lastEvaluation": "2026-11-22T09:59:45.1Z",
            "evaluationTime": 0.0042,
            "rules": [
                {"type": "alerting", "name": "HighErrorRate", "state": "firing", "health": "ok"},
                {"type": "alerting", "name": "Latency", "state": "inactive", "health": "ok"},
                {
                    "type": "recording",
                    "name": "job:errors:rate5m",
                    "health": "err",
                    "lastError": "query timed out fetching from 10.0.0.9:9090",
                },
            ],
        }
    ]
}


async def test_alerts_and_rule_groups(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/alerts").mock(return_value=success(ALERTS))
    prom_api.get("/api/v1/rules").mock(return_value=success(RULES))
    output = await alerts.alerts_overview(prom_backend)
    assert output.text.splitlines() == [
        "Alerts: 1 firing, 1 pending.",
        "| state | alert | since | severity | labels | summary |",
        "| --- | --- | --- | --- | --- | --- |",
        '| firing | HighErrorRate | 2026-11-22T09:12:00Z | critical | job="api" | 5xx above 5% \\| for 10m |',
        '| pending | DiskFilling | 2026-11-22T09:50:00Z | warning | instance="db-1" | Disk is 85% full |',
        "",
        "Rule groups: 1 groups, 3 rules, 1 unhealthy.",
        "| group | file | interval | alerting | recording | firing | pending | unhealthy | last evaluation | took |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        "| api | api.yml | 30s | 2 | 1 | 1 | 0 | 1 | 2026-11-22T09:59:45Z | 4.2 ms |",
        "",
        "Unhealthy rules:",
        "- api / job:errors:rate5m: query timed out fetching from <address>",
    ]
    assert output.rows == 2


async def test_no_alerts_and_no_rules(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/alerts").mock(return_value=success({"alerts": []}))
    prom_api.get("/api/v1/rules").mock(return_value=success({"groups": []}))
    output = await alerts.alerts_overview(prom_backend)
    assert output.text == "Alerts: none firing or pending.\n\nRule groups: none loaded."
    assert output.rows == 0


async def test_rules_endpoint_failure_keeps_the_alerts(prom_api: respx.Router, prom_backend: PrometheusBackend) -> None:
    prom_api.get("/api/v1/alerts").mock(return_value=success(ALERTS))
    prom_api.get("/api/v1/rules").mock(return_value=api_error(400, "bad_data", "vmalert.proxyURL is not set"))
    output = await alerts.alerts_overview(prom_backend)
    assert "Alerts: 1 firing, 1 pending." in output.text
    assert output.text.endswith("Rule groups are unavailable: Prometheus error (bad_data): vmalert.proxyURL is not set")


def test_alerts_are_capped() -> None:
    many = [{"labels": {"alertname": f"A{i:02}"}, "state": "firing"} for i in range(5)]
    text = alerts.format_alerts(many, max_items=2, budget=10_000)
    assert text.count("| firing |") == 2
    assert text.endswith(
        '[Showing 2 of 5 alerts: the limit is 2. Query ALERTS{alertstate="firing"} with prom_query to filter them.]'
    )
```

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_alerts.py -q`
Expected: `ImportError: cannot import name 'alerts'`.

- [ ] **Step 3: Implement**

Create `src/ratatoskr/backends/prometheus/alerts.py`:

```python
"""prom_alerts: alerts that are firing or pending, and the state of every rule group."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from pathlib import PurePosixPath
from typing import Any

from ratatoskr.backends.errors import BackendError
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.prometheus.formatting import (
    BlockWriter,
    cell,
    response_budget,
    short_time,
    truncation_note,
    with_notes,
)
from ratatoskr.backends.timeparse import format_duration
from ratatoskr.tools.runtime import ToolOutput

SUMMARY_CHARS = 200
ERROR_CHARS = 300
MAX_UNHEALTHY = 20
ALERTS_HINT = 'Query ALERTS{alertstate="firing"} with prom_query to filter them.'
_STATE_ORDER = {"firing": 0, "pending": 1}


async def alerts_overview(backend: PrometheusBackend) -> ToolOutput:
    limits = backend.limits
    half = response_budget(limits.max_response_bytes) // 2
    alerts_result = await backend.api.alerts()
    alerts = _dicts(alerts_result.data, "alerts")
    sections = [format_alerts(alerts, max_items=limits.max_series, budget=half)]
    notes = list(alerts_result.notes)
    try:
        rules_result = await backend.api.rules()
    except BackendError as exc:  # e.g. VictoriaMetrics without a vmalert proxy
        sections.append(f"Rule groups are unavailable: {exc}")
    else:
        groups = _dicts(rules_result.data, "groups")
        sections.append(format_rule_groups(groups, budget=half, scrub=backend.api.scrub))
        notes += rules_result.notes
    return ToolOutput(text=with_notes("\n\n".join(sections), notes), rows=len(alerts))


def format_alerts(alerts: list[dict[str, Any]], *, max_items: int, budget: int) -> str:
    if not alerts:
        return "Alerts: none firing or pending."
    firing = sum(1 for alert in alerts if alert.get("state") == "firing")
    pending = sum(1 for alert in alerts if alert.get("state") == "pending")
    ordered = sorted(
        alerts,
        key=lambda alert: (
            _STATE_ORDER.get(str(alert.get("state")), 2),
            _labels(alert).get("alertname", ""),
            str(alert.get("activeAt", "")),
        ),
    )
    writer = BlockWriter(budget)
    writer.add(f"Alerts: {firing} firing, {pending} pending.")
    writer.add("| state | alert | since | severity | labels | summary |\n| --- | --- | --- | --- | --- | --- |")
    for alert in ordered[:max_items]:
        if not writer.add(_alert_row(alert)):
            break
    shown = writer.kept - 2
    return writer.text() + truncation_note(shown, len(alerts), max_items, unit="alerts", hint=ALERTS_HINT)


def _alert_row(alert: dict[str, Any]) -> str:
    labels = _labels(alert)
    others = ", ".join(f'{key}="{value}"' for key, value in labels.items() if key not in ("alertname", "severity"))
    raw_annotations = alert.get("annotations")
    annotations = raw_annotations if isinstance(raw_annotations, dict) else {}
    summary = annotations.get("summary") or annotations.get("description") or ""
    cells = [
        cell(alert.get("state", "?")),
        cell(labels.get("alertname", "?")),
        cell(short_time(alert.get("activeAt"))),
        cell(labels.get("severity", "-")),
        cell(others or "-"),
        cell(summary or "-", SUMMARY_CHARS),
    ]
    return "| " + " | ".join(cells) + " |"


def format_rule_groups(groups: list[dict[str, Any]], *, budget: int, scrub: Callable[[str], str]) -> str:
    if not groups:
        return "Rule groups: none loaded."
    rules = [(group, rule) for group in groups for rule in _dicts(group, "rules")]
    unhealthy = [(group, rule) for group, rule in rules if rule.get("health") == "err"]
    writer = BlockWriter(budget)
    writer.add(f"Rule groups: {len(groups)} groups, {len(rules)} rules, {len(unhealthy)} unhealthy.")
    writer.add(
        "| group | file | interval | alerting | recording | firing | pending | unhealthy | last evaluation | took |\n"
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"
    )
    for group in groups:
        if not writer.add(_group_row(group)):
            break
    shown = writer.kept - 2
    text = writer.text() + truncation_note(
        shown, len(groups), len(groups), unit="rule groups", hint="Narrow with prom_query on ALERTS."
    )
    if unhealthy:
        lines = ["", "Unhealthy rules:"]
        for group, rule in unhealthy[:MAX_UNHEALTHY]:
            error = scrub(str(rule.get("lastError") or "no error text"))
            lines.append(f"- {group.get('name', '?')} / {rule.get('name', '?')}: {cell(error, ERROR_CHARS)}")
        if len(unhealthy) > MAX_UNHEALTHY:
            lines.append(f"- ... and {len(unhealthy) - MAX_UNHEALTHY} more")
        text += "\n" + "\n".join(lines)
    return text


def _group_row(group: dict[str, Any]) -> str:
    rules = _dicts(group, "rules")
    alerting = [rule for rule in rules if rule.get("type") == "alerting"]
    cells = [
        cell(group.get("name", "?")),
        cell(PurePosixPath(str(group.get("file") or "-")).name),  # the file name only, not the server's path
        _seconds(group.get("interval")),
        str(len(alerting)),
        str(sum(1 for rule in rules if rule.get("type") == "recording")),
        str(sum(1 for rule in alerting if rule.get("state") == "firing")),
        str(sum(1 for rule in alerting if rule.get("state") == "pending")),
        str(sum(1 for rule in rules if rule.get("health") == "err")),
        cell(short_time(group.get("lastEvaluation"))),
        _milliseconds(group.get("evaluationTime")),
    ]
    return "| " + " | ".join(cells) + " |"


def _labels(alert: dict[str, Any]) -> dict[str, str]:
    labels = alert.get("labels")
    return {str(key): str(value) for key, value in labels.items()} if isinstance(labels, dict) else {}


def _dicts(data: Any, key: str) -> list[dict[str, Any]]:
    items = data.get(key) if isinstance(data, dict) else None
    return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []


def _seconds(value: Any) -> str:
    return format_duration(timedelta(seconds=value)) if isinstance(value, int | float) else "-"


def _milliseconds(value: Any) -> str:
    return f"{value * 1000:.1f} ms" if isinstance(value, int | float) else "-"
```

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_alerts.py -q` — 4 passed. mypy, ruff clean.

- [ ] **Step 5: Commit**

```bash
git add src/ratatoskr/backends/prometheus/alerts.py tests/unit/test_prom_alerts.py
git commit -m "Show firing and pending alerts with rule group state" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 14: Register the five tools; `list_connections` and instructions

**Files:**
- Create: `src/ratatoskr/backends/prometheus/descriptions.py`, `src/ratatoskr/backends/prometheus/tools.py`
- Modify: `src/ratatoskr/app.py`, `src/ratatoskr/tools/common.py`, `tests/unit/test_app.py`, `tests/unit/test_cli.py:267`
- Test: `tests/unit/test_prom_tools.py`

Every tool: first argument `connection`, `need=Access.READ`, `kind="prometheus"`, the Prometheus truncation hint,
`query_text` = the PromQL (`prom_query`, `prom_query_range`) or the `match` selector (`prom_list_metrics`,
`prom_label_values`; `None` for `prom_alerts`). Annotations: `readOnlyHint=True`, `destructiveHint=False`,
`idempotentHint=True`, `openWorldHint=False`. `list_connections` and `connection_health` need no change beyond the
description: they already use `registry.describe(...).kind` and `backend.health()`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_prom_tools.py`:

```python
from typing import Any

import pytest
import respx
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.backends.prometheus.tools import register_prometheus_tools
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import ConnectionConfig
from ratatoskr.config.prometheus_models import PrometheusConnection
from ratatoskr.tools.common import register_common_tools
from ratatoskr.tools.runtime import ToolRuntime
from tests.fakes import FakeBackend, RecordingSink, make_config
from tests.unit.prom_helpers import NOW, PROM_URL, api_error, success, vector

PROM_TOOLS = ["prom_query", "prom_query_range", "prom_list_metrics", "prom_label_values", "prom_alerts"]
CONFIG = make_config(
    connections={
        "db": {},
        "prom": {"kind": "prometheus", "url": PROM_URL, "description": "Metrics"},
        "secret-prom": {"kind": "prometheus"},
    },
    roles={"team": {"db": "read", "prom": "write"}},
)


def _factory(name: str, config: ConnectionConfig) -> Backend:
    if isinstance(config, PrometheusConnection):
        return PrometheusBackend(name, config, clock=lambda: NOW)
    return FakeBackend(name, config)


class _Harness:
    def __init__(self) -> None:
        self.sink = RecordingSink()
        self.backends: dict[str, Backend] = {}
        self.registry = BackendRegistry(CONFIG, factory=self._create)
        runtime = ToolRuntime(Policy(CONFIG), self.registry, StdioPrincipalResolver("team"), self.sink)
        self.mcp: FastMCP[Any] = FastMCP("test")
        register_common_tools(self.mcp, runtime)
        register_prometheus_tools(self.mcp, runtime)

    def _create(self, name: str, config: ConnectionConfig) -> Backend:
        self.backends[name] = backend = _factory(name, config)
        return backend

    async def call(self, tool: str, **arguments: Any) -> CallToolResult:
        result = await self.mcp.call_tool(tool, arguments)
        assert isinstance(result, CallToolResult)
        assert isinstance(result.content[0], TextContent)
        return result


def _text(result: CallToolResult) -> str:
    block = result.content[0]
    assert isinstance(block, TextContent)
    return block.text


@pytest.fixture
async def harness(prom_api: respx.Router) -> Any:
    created = _Harness()
    yield created
    await created.registry.close_all()


async def test_registers_the_five_tools_in_spec_order(harness: _Harness) -> None:
    names = [tool.name for tool in await harness.mcp.list_tools()]
    assert names[2:] == PROM_TOOLS


@pytest.mark.parametrize("name", PROM_TOOLS)
async def test_tool_schema_and_annotations(harness: _Harness, name: str) -> None:
    tool = {tool.name: tool for tool in await harness.mcp.list_tools()}[name]
    schema = tool.inputSchema
    assert next(iter(schema["properties"])) == "connection"
    assert "connection" in schema["required"]
    assert "list_connections" in schema["properties"]["connection"]["description"]
    assert 80 < len(tool.description or "") < 700
    assert tool.annotations is not None
    assert (tool.annotations.readOnlyHint, tool.annotations.destructiveHint) == (True, False)
    assert tool.annotations.idempotentHint is True
    assert tool.annotations.title


async def test_prom_query_goes_through_the_runtime_and_audits_the_promql(
    prom_api: respx.Router, harness: _Harness
) -> None:
    prom_api.post("/api/v1/query").mock(return_value=success(vector(({"__name__": "up"}, "1"))))
    result = await harness.call("prom_query", connection="prom", promql="up")
    assert (result.isError, _text(result)) == (False, "vector: 1 series at 2026-11-22T10:00:00Z\nup 1")
    [event] = harness.sink.events
    assert (event.tool, event.connection, event.query_text, event.result, event.rows) == (
        "prom_query",
        "prom",
        "up",
        "ok",
        1,
    )


async def test_prometheus_errors_are_tool_errors(prom_api: respx.Router, harness: _Harness) -> None:
    prom_api.post("/api/v1/query").mock(return_value=api_error(400, "bad_data", "1:3: parse error"))
    result = await harness.call("prom_query", connection="prom", promql="up{")
    assert (result.isError, _text(result)) == (True, "Error: Prometheus error (bad_data): 1:3: parse error")
    assert harness.sink.events[0].result == "error"


async def test_forbidden_and_unknown_connections_look_the_same(prom_api: respx.Router, harness: _Harness) -> None:
    forbidden = await harness.call("prom_alerts", connection="secret-prom")
    unknown = await harness.call("prom_alerts", connection="ghost")
    assert _text(forbidden) == "Error: Connection 'secret-prom' not found."
    assert _text(unknown) == "Error: Connection 'ghost' not found."
    assert prom_api.calls.call_count == 0


async def test_a_postgres_connection_is_refused_without_opening_it(harness: _Harness) -> None:
    result = await harness.call("prom_query", connection="db", promql="up")
    assert result.isError is True
    assert "is a postgres connection; prom_query needs a prometheus connection" in _text(result)
    db = harness.backends["db"]
    assert isinstance(db, FakeBackend)
    assert db.open_calls == 0


async def test_each_tool_reaches_its_endpoint(prom_api: respx.Router, harness: _Harness) -> None:
    prom_api.post("/api/v1/query_range").mock(return_value=success({"resultType": "matrix", "result": []}))
    prom_api.get("/api/v1/label/__name__/values").mock(return_value=success(["up"]))
    prom_api.get("/api/v1/metadata").mock(return_value=success({}))
    prom_api.get("/api/v1/label/job/values").mock(return_value=success(["api"]))
    prom_api.get("/api/v1/alerts").mock(return_value=success({"alerts": []}))
    prom_api.get("/api/v1/rules").mock(return_value=success({"groups": []}))
    calls = {
        "prom_query_range": {"promql": "up", "start": "now-30m"},
        "prom_list_metrics": {"name_contains": "up"},
        "prom_label_values": {"label": "job"},
        "prom_alerts": {},
    }
    for tool, arguments in calls.items():
        result = await harness.call(tool, connection="prom", **arguments)
        assert result.isError is False, _text(result)
    assert [event.tool for event in harness.sink.events] == list(calls)


async def test_list_connections_and_health_show_prometheus(prom_api: respx.Router, harness: _Harness) -> None:
    prom_api.get("/api/v1/status/buildinfo").mock(return_value=success({"version": "3.5.0"}))
    listing = _text(await harness.call("list_connections"))
    assert "| prom | prometheus | read | Metrics |" in listing
    assert "secret-prom" not in listing
    health = _text(await harness.call("connection_health", connection="prom"))
    assert "| prom | prometheus | ok |" in health
    assert "Prometheus 3.5.0" in health
```

In `tests/unit/test_app.py` replace `test_registers_eleven_tools` with

```python
async def test_registers_sixteen_tools() -> None:
    names = [tool.name for tool in await _app().list_tools()]
    assert names[:2] == ["list_connections", "connection_health"]
    assert len(names) == 16
    assert all(name.startswith("pg_") for name in names[2:11])
    assert all(name.startswith("prom_") for name in names[11:])
```

and add `assert "prom_query_range" in (app.instructions or "")` to `test_instructions_point_to_list_connections`. In
`tests/unit/test_cli.py` (`test_serve_stdio_subprocess_speaks_json_rpc_without_leaking`) change
`assert len(tools["result"]["tools"]) == 11` to `== 16`.

- [ ] **Step 2: Run it to see it fail**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_tools.py tests/unit/test_app.py -q`
Expected: `ModuleNotFoundError: No module named 'ratatoskr.backends.prometheus.tools'`; `test_app` reports 11 tools.

- [ ] **Step 3: Tool texts**

Create `src/ratatoskr/backends/prometheus/descriptions.py`:

```python
"""Tool and argument descriptions for the Prometheus tools. They are the product UX for the LLM: keep them short,
say what the tool returns, when to use it, and what the limits are."""

from __future__ import annotations

CONNECTION = (
    "Name of a Prometheus connection (kind prometheus) exactly as returned by list_connections. "
    "Call list_connections first if you do not know the names."
)
PROMQL = 'PromQL expression, e.g. up{job="api"} or sum by (instance) (rate(http_requests_total[5m])).'
TIME = "Evaluation time: RFC3339 (2026-11-22T10:00:00Z), unix seconds, or relative (now, now-15m, now-2h). Default now."
START = "Window start: RFC3339, unix seconds or relative (now-6h). Default: one hour before end."
END = "Window end: RFC3339, unix seconds or relative (now-1h). Default: now."
STEP = "Resolution such as 15s, 1m, 5m or 1h. Omit it to get up to about 120 points over the range."
MATCH = 'Optional series selector that limits the result, e.g. {job="api"} or http_requests_total{code=~"5.."}.'
NAME_CONTAINS = "Optional case-insensitive text the metric name must contain, e.g. http or memory."
LABEL = "Label name, e.g. job, instance, namespace, or __name__ for metric names."
TRUNCATION_HINT = (
    "Narrow the request: add label matchers, aggregate (sum by, topk), shorten the range or raise the step."
)

PROM_QUERY = (
    "Evaluate a PromQL expression at one instant (default now) and get each series' labels and value, or a scalar. "
    "Use it for the current state: up, error ratios, top consumers with topk. Shows at most the connection's series "
    "limit (default 100) and says how many matched; aggregate (sum by, topk) to stay under it. Find metric and label "
    "names with prom_list_metrics and prom_label_values first."
)
PROM_QUERY_RANGE = (
    "Evaluate a PromQL expression over a time window (default the last hour) and get per series: number of points, "
    "min, max, average, last value and up to 60 evenly spaced samples (fewer when there are many series). Use it for "
    "trends and incident windows. Without step it picks one that gives up to about 120 points; the connection caps "
    "points per series and the window length. At most the series limit (default 100) is shown."
)
PROM_LIST_METRICS = (
    "List metric names that have data in a time window (default the last hour), with type and help text when the "
    "server keeps metadata. Narrow with name_contains (e.g. 'http') or a match selector (e.g. {job=\"api\"}). Use it "
    "to find the right metric before prom_query. Shows at most the connection's list limit (default 500)."
)
PROM_LABEL_VALUES = (
    "List the values of one label (e.g. job, instance, namespace) on series with data in a time window (default the "
    "last hour), optionally only on series matching a selector. Use it to write exact label matchers for prom_query. "
    "Shows at most the connection's list limit (default 500)."
)
PROM_ALERTS = (
    "Show the alerts that are firing or pending now (name, state, since when, severity, labels, summary) and the "
    "state of every rule group (rule counts, firing and pending rules, unhealthy rules with their last error, last "
    "evaluation). Start here when investigating an incident."
)
```

- [ ] **Step 4: Registration**

Create `src/ratatoskr/backends/prometheus/tools.py`:

```python
"""Register the five Prometheus tools (spec 6.3). Every tool goes through ToolRuntime.run with read access."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, ToolAnnotations
from pydantic import Field

from ratatoskr.backends import errors
from ratatoskr.backends.base import Backend
from ratatoskr.backends.prometheus import alerts, discovery, querying
from ratatoskr.backends.prometheus import descriptions as d
from ratatoskr.backends.prometheus.backend import PrometheusBackend
from ratatoskr.config.models import Access
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime

ConnectionArg = Annotated[str, Field(description=d.CONNECTION)]
PromqlArg = Annotated[str, Field(description=d.PROMQL)]
TimeArg = Annotated[str | None, Field(description=d.TIME)]
StartArg = Annotated[str | None, Field(description=d.START)]
EndArg = Annotated[str | None, Field(description=d.END)]
StepArg = Annotated[str | None, Field(description=d.STEP)]
MatchArg = Annotated[str | None, Field(description=d.MATCH)]
NameContainsArg = Annotated[str | None, Field(description=d.NAME_CONTAINS)]
LabelArg = Annotated[str, Field(description=d.LABEL)]

Call = Callable[[PrometheusBackend], Awaitable[ToolOutput]]


def _prometheus(backend: Backend) -> PrometheusBackend:
    if not isinstance(backend, PrometheusBackend):
        raise errors.InvalidRequestError(f"Connection '{backend.name}' is not a Prometheus connection.")
    return backend


def _read_only(title: str) -> ToolAnnotations:
    return ToolAnnotations(
        title=title, readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False
    )


def register_prometheus_tools(mcp: FastMCP[Any], runtime: ToolRuntime) -> None:
    async def run(tool: str, connection: str, call: Call, query_text: str | None = None) -> CallToolResult:
        async def wrapped(backend: Backend, access: Access) -> ToolOutput:
            return await call(_prometheus(backend))

        result = await runtime.run(
            tool=tool,
            connection=connection,
            need=Access.READ,
            call=wrapped,
            query_text=query_text,
            kind=PrometheusBackend.kind,
            truncation_hint=d.TRUNCATION_HINT,
        )
        return result.to_call_tool_result()

    async def prom_query(connection: ConnectionArg, promql: PromqlArg, time: TimeArg = None) -> CallToolResult:
        return await run(
            "prom_query", connection, lambda backend: querying.instant_query(backend, promql, time), promql
        )

    async def prom_query_range(
        connection: ConnectionArg,
        promql: PromqlArg,
        start: StartArg = None,
        end: EndArg = None,
        step: StepArg = None,
    ) -> CallToolResult:
        return await run(
            "prom_query_range",
            connection,
            lambda backend: querying.range_query(backend, promql, start, end, step),
            promql,
        )

    async def prom_list_metrics(
        connection: ConnectionArg,
        name_contains: NameContainsArg = None,
        match: MatchArg = None,
        start: StartArg = None,
        end: EndArg = None,
    ) -> CallToolResult:
        return await run(
            "prom_list_metrics",
            connection,
            lambda backend: discovery.list_metrics(
                backend, match=match, name_contains=name_contains, start=start, end=end
            ),
            match,
        )

    async def prom_label_values(
        connection: ConnectionArg,
        label: LabelArg,
        match: MatchArg = None,
        start: StartArg = None,
        end: EndArg = None,
    ) -> CallToolResult:
        return await run(
            "prom_label_values",
            connection,
            lambda backend: discovery.label_values(backend, label=label, match=match, start=start, end=end),
            match,
        )

    async def prom_alerts(connection: ConnectionArg) -> CallToolResult:
        return await run("prom_alerts", connection, alerts.alerts_overview)

    tools = (
        (prom_query, d.PROM_QUERY, _read_only("PromQL instant query")),
        (prom_query_range, d.PROM_QUERY_RANGE, _read_only("PromQL range query")),
        (prom_list_metrics, d.PROM_LIST_METRICS, _read_only("List metrics")),
        (prom_label_values, d.PROM_LABEL_VALUES, _read_only("List label values")),
        (prom_alerts, d.PROM_ALERTS, _read_only("Alerts and rule groups")),
    )
    for fn, description, hints in tools:
        mcp.add_tool(fn, description=description, annotations=hints, structured_output=False)
```

- [ ] **Step 5: Wire into the app**

In `src/ratatoskr/app.py` add `from ratatoskr.backends.prometheus.tools import register_prometheus_tools`, call
`register_prometheus_tools(mcp, runtime)` right after `register_postgres_tools(mcp, runtime)`, and replace
`INSTRUCTIONS` with

```python
INSTRUCTIONS = (
    "Ratatoskr connects you to several named data sources: PostgreSQL databases and Prometheus servers. "
    "Call list_connections first to see which connections you may use, their kind and whether you can read or "
    "write; every other tool takes one of those names as its `connection` argument. PostgreSQL (pg_*): explore "
    "with pg_list_schemas, pg_list_tables and pg_describe_table before writing SQL, and prefer pg_query for reads; "
    "pg_execute changes data and needs write access. Prometheus (prom_*): find metrics with prom_list_metrics and "
    "prom_label_values, then use prom_query for the current state and prom_query_range for trends; prom_alerts "
    "shows what is firing."
)
```

In `src/ratatoskr/tools/common.py` replace `LIST_CONNECTIONS` with

```python
LIST_CONNECTIONS = (
    "List the data connections you can use: name, kind (postgres or prometheus), description and your access "
    "level (read or write). Call this first: every other tool takes one of these names as its `connection` "
    "argument, and pg_* tools need a postgres connection, prom_* tools a prometheus one."
)
```

- [ ] **Step 6: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_prom_tools.py tests/unit/test_app.py tests/unit/test_common_tools.py tests/unit/test_mcp_protocol.py tests/unit/test_cli.py -q`
Expected: all pass. Then the whole unit suite, mypy, ruff check, ruff format --check: clean.

- [ ] **Step 7: Commit**

```bash
git add src/ratatoskr/backends/prometheus/descriptions.py src/ratatoskr/backends/prometheus/tools.py src/ratatoskr/app.py src/ratatoskr/tools/common.py tests/unit/test_prom_tools.py tests/unit/test_app.py tests/unit/test_cli.py
git commit -m "Register the five Prometheus tools" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 15: Integration tests against a real Prometheus

**Files:**
- Modify: `tests/integration/conftest.py`, `tests/integration/helpers.py`
- Test: `tests/integration/test_prom_tools.py`

The container (`prom/prometheus:v3.16.0`, bound to 127.0.0.1 on a random port) gets a config that scrapes itself every
second and a rules file with one always-firing alert, one pending alert (`for: 1h`) and one recording rule, copied in
before start (`with_copy_into_container`; no bind mounts, so Docker Desktop file sharing does not matter). The fixture
waits for `/-/ready`, then until `up` has 5 samples and both alerts are active (~6 s). The first run pulls the image.

- [ ] **Step 1: Helpers**

In `tests/integration/helpers.py` add `import time` and `import httpx` to the imports, and after `UNREACHABLE_DSN`:

```python
PROMETHEUS_IMAGE = "prom/prometheus:v3.16.0"
PROMETHEUS_CONFIG = """
global:
  scrape_interval: 1s
  evaluation_interval: 1s
rule_files: [/etc/prometheus/rules.yml]
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["localhost:9090"]
"""
PROMETHEUS_RULES = """
groups:
  - name: ratatoskr-test
    rules:
      - alert: AlwaysFiring
        expr: vector(1)
        labels: {severity: info}
        annotations: {summary: Integration test alert that always fires}
      - alert: AlwaysPending
        expr: vector(1)
        for: 1h
        labels: {severity: warning}
      - record: job:up:sum
        expr: sum by (job) (up)
"""
# Nothing listens here: tests for an unreachable Prometheus.
UNREACHABLE_PROMETHEUS = "http://127.0.0.1:1"


def wait_for_prometheus_data(url: str, *, timeout: float = 60.0) -> None:
    """Block until Prometheus holds at least 5 samples of `up` and both test alerts are active."""
    deadline = time.monotonic() + timeout
    with httpx.Client(base_url=url, timeout=5.0, trust_env=False) as client:
        while time.monotonic() < deadline:
            samples = client.get("/api/v1/query", params={"query": "count_over_time(up[1m])"}).json()
            alerts = client.get("/api/v1/alerts").json()
            result = samples["data"]["result"]
            if result and float(result[0]["value"][1]) >= 5 and len(alerts["data"]["alerts"]) >= 2:
                return
            time.sleep(0.5)
    raise RuntimeError("Prometheus did not collect samples in time")


def make_prom_config(url: str, **values: Any) -> RatatoskrConfig:
    """Connection 'prom' for the local container (10 s timeout); role 'admins' has '*': write."""
    connection: dict[str, Any] = {"kind": "prometheus", "url": url, "timeout": "10s", **values}
    return RatatoskrConfig.model_validate({"roles": {"admins": {"*": "write"}}, "connections": {"prom": connection}})
```

`ToolHarness.call_result` defaults `connection` to `'db'`; the Prometheus tests pass `connection="prom"` explicitly.

- [ ] **Step 2: Fixture**

In `tests/integration/conftest.py` replace the imports with

```python
from collections.abc import AsyncIterator, Iterator

import pytest
from testcontainers.community.postgres import PostgresContainer
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import HttpWaitStrategy

from ratatoskr.config.models import RatatoskrConfig
from tests.integration.helpers import (
    PROMETHEUS_CONFIG,
    PROMETHEUS_IMAGE,
    PROMETHEUS_RULES,
    MakeHarness,
    ToolHarness,
    seed,
    wait_for_prometheus_data,
)
```

and add after the `pg_dsn` fixture:

```python
@pytest.fixture(scope="session")
def prometheus_url() -> Iterator[str]:
    """URL of a throwaway Prometheus bound to 127.0.0.1 that scrapes itself every second and evaluates two alerts."""
    container = (
        DockerContainer(PROMETHEUS_IMAGE)
        .with_copy_into_container(PROMETHEUS_CONFIG.encode(), "/etc/prometheus/prometheus.yml")
        .with_copy_into_container(PROMETHEUS_RULES.encode(), "/etc/prometheus/rules.yml")
        .waiting_for(HttpWaitStrategy(9090, "/-/ready").for_status_code(200))
    )
    container.ports["9090"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        url = f"http://127.0.0.1:{container.get_exposed_port(9090)}"
        wait_for_prometheus_data(url)
        yield url
```

- [ ] **Step 3: The tests**

Create `tests/integration/test_prom_tools.py`:

```python
"""The five Prometheus tools, list_connections and connection_health against a real Prometheus container."""

import pytest

from tests.integration.helpers import UNREACHABLE_PROMETHEUS, MakeHarness, make_prom_config

pytestmark = pytest.mark.integration


async def test_instant_query(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call("prom_query", connection="prom", promql='up{job="prometheus"}')
    assert text.startswith("vector: 1 series at ")
    assert 'up{instance="localhost:9090", job="prometheus"} 1' in text
    [event] = harness.sink.events
    assert (event.tool, event.query_text, event.result, event.rows) == ("prom_query", 'up{job="prometheus"}', "ok", 1)


async def test_scalar_query(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    assert (await harness.call("prom_query", connection="prom", promql="1 + 1")).startswith("scalar: 2 at ")


async def test_bad_promql_is_a_tool_error_without_the_address(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    result = await harness.call_result("prom_query", connection="prom", promql="sum(up")
    assert result.is_error
    assert result.text.startswith("Error: Prometheus error (bad_data): ")
    assert "127.0.0.1" not in result.text
    assert prometheus_url.rsplit(":", 1)[1] not in result.text
    assert harness.sink.events[0].result == "error"


async def test_series_limit_is_explicit(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url, limits={"max_series": 2}))
    text = await harness.call("prom_query", connection="prom", promql="prometheus_http_requests_total")
    assert "[Showing 2 of " in text
    assert "series: the limit is 2." in text


async def test_range_query_summarises_each_series(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call(
        "prom_query_range", connection="prom", promql='up{job="prometheus"}', start="now-1m", step="1s"
    )
    assert "step 1s (up to 61 points per series; times are UTC)" in text
    assert 'up{instance="localhost:9090", job="prometheus"}' in text
    assert "min 1, max 1, avg 1, last 1 at " in text
    assert "  samples: " in text


async def test_range_query_point_cap_is_enforced_before_prometheus(
    prometheus_url: str, make_harness: MakeHarness
) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    result = await harness.call_result("prom_query_range", connection="prom", promql="up", start="now-1d", step="1s")
    assert result.is_error
    assert "points per series over 1d; this connection allows 1000" in result.text


async def test_list_metrics_with_metadata(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call("prom_list_metrics", connection="prom", name_contains="prometheus_http_requests")
    assert "| prometheus_http_requests_total | counter | " in text


async def test_label_values(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call("prom_label_values", connection="prom", label="job", match="up")
    assert text.splitlines()[1:] == ["prometheus"]


async def test_alerts_and_rule_groups(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url))
    text = await harness.call("prom_alerts", connection="prom")
    assert "Alerts: 1 firing, 1 pending." in text
    assert "| firing | AlwaysFiring |" in text
    assert "| pending | AlwaysPending |" in text
    assert "| ratatoskr-test | rules.yml | 1s | 2 | 1 | 1 | 1 | 0 |" in text


async def test_list_connections_and_health(prometheus_url: str, make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(prometheus_url, description="Test metrics"))
    assert "| prom | prometheus | read | Test metrics |" in await harness.call("list_connections")
    health = await harness.call("connection_health", connection="prom")
    assert "| prom | prometheus | ok |" in health
    assert "Prometheus 3." in health


async def test_unreachable_prometheus_hides_the_address(make_harness: MakeHarness) -> None:
    harness = make_harness(make_prom_config(UNREACHABLE_PROMETHEUS))
    result = await harness.call_result("prom_query", connection="prom", promql="up")
    assert result.is_error
    assert "Connection 'prom' is unavailable" in result.text
    assert "127.0.0.1" not in result.text
```

- [ ] **Step 4: Run them**

Docker Desktop must be running. Run: `.venv/Scripts/python -m pytest -m integration tests/integration/test_prom_tools.py -q`
Expected: 11 passed (about 20 s plus the first image pull). Then the full integration suite
`.venv/Scripts/python -m pytest -m integration -q`: 154 passed. If a test fails only because a newer Prometheus changed
an output detail (for example the rule-group interval column), check the real answer with
`curl http://127.0.0.1:<port>/api/v1/rules` while the container runs before touching the assertion.

- [ ] **Step 5: Commit**

```bash
git add tests/integration/conftest.py tests/integration/helpers.py tests/integration/test_prom_tools.py
git commit -m "Test the Prometheus tools against a real Prometheus container" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 16: Docs: example config, README, CLAUDE.md, pyproject, contract notes

**Files:**
- Modify: `config.example.yaml`, `tests/unit/test_example_config.py`, `README.md`, `CLAUDE.md`, `pyproject.toml`,
  `docs/superpowers/plans/2026-11-21-phase1-interfaces.md`

Docs describe what the code does now (repo rule); nothing below documents an unimplemented setting.

- [ ] **Step 1: Write the failing example-config test**

In `tests/unit/test_example_config.py` add the imports

```python
from ratatoskr.config.http_models import BearerAuth
from ratatoskr.config.prometheus_models import PrometheusConnection
```

and, before `_uncomment_http`:

```python
def test_commented_prometheus_connection_example_is_valid(tmp_path: Path) -> None:
    lines = EXAMPLE.read_text(encoding="utf-8").splitlines()
    start = next(index for index, line in enumerate(lines) if line.startswith("  # metrics:"))
    stop = lines.index("  # staging-db:")
    block = [line.replace("  # ", "  ", 1) for line in lines[start:stop] if line.startswith("  # ")]
    path = tmp_path / "config.yaml"
    path.write_text("\n".join(lines[:start] + block) + "\n", encoding="utf-8")
    env = {"APP_DB_DSN": "postgresql://reader:pw@localhost/app", "PROM_TOKEN": "prom-token", "PROM_TENANT": "team-a"}
    metrics = load_config(path, env=env).connections["metrics"]
    assert isinstance(metrics, PrometheusConnection)
    assert metrics.mode == "read"
    assert isinstance(metrics.auth, BearerAuth)
    assert metrics.headers["X-Scope-OrgID"].get_secret_value() == "team-a"
    assert (metrics.limits.max_series, metrics.limits.max_points) == (100, 1000)
```

Run: `.venv/Scripts/python -m pytest tests/unit/test_example_config.py -q` — expected: `StopIteration` (no
`  # metrics:` line yet).

- [ ] **Step 2: `config.example.yaml`**

After the header line `# Durations accept a number of seconds or "30s", "5m", "1h", "30d".` add

```yaml
# Proxies: outgoing HTTP (OIDC, Prometheus) honours HTTPS_PROXY / HTTP_PROXY; list internal hosts in NO_PROXY.
```

and insert this block between the `app-db` connection (after its `#   key_file: ...` line and the blank line) and
`  # staging-db:` (it must stay before `staging-db`: the staging test uncomments everything after that line):

```yaml
  # metrics:                    # Prometheus HTTP API: Prometheus, Mimir, Thanos Query, VictoriaMetrics (see README)
  #   kind: prometheus          # always read-only (leave mode out); PromQL itself is not restricted
  #   description: "Production metrics"
  #   url: http://prometheus:9090   # API root (<url>/api/v1/...); for Mimir include its prefix: https://mimir/prometheus
  #   auth:                     # none (default) | basic (username, password) | bearer (token)
  #     type: bearer
  #     token: ${PROM_TOKEN}
  #   headers:                  # extra request headers, e.g. a Mimir/Cortex tenant; not Authorization or Host
  #     X-Scope-OrgID: ${PROM_TENANT}
  #   timeout: 30s              # per request; also sent to Prometheus as the query evaluation timeout
  #   tls: { verify: true }     # https only; ca_file: /config/certs/prom-ca.pem trusts only that CA
  #   limits: { max_series: 100, max_values: 500, max_points: 1000, max_range: 31d, max_response_bytes: 65536 }

```

Run: `.venv/Scripts/python -m pytest tests/unit/test_example_config.py -q` — 5 passed.

- [ ] **Step 3: README**

Make these edits in `README.md`:

1. Intro: replace "**several PostgreSQL databases at once**, with per-group access levels and an audit trail.
   Prometheus and Loki backends are planned." with "**several PostgreSQL databases and Prometheus servers at once**,
   with per-group access levels and an audit trail. A Loki backend is planned."
2. Features, first bullet → "Any number of named PostgreSQL (12 or newer) and Prometheus connections in one server;
   the tool set stays the same (16 tools). Prometheus connections also work with Mimir, Thanos Query and
   VictoriaMetrics." In the audit bullet replace "(SQL with secrets masked" with "(the SQL or PromQL with secrets
   masked".
3. Configuration table: the `connections.<name>.kind` row becomes "`postgres` or `prometheus`. Names:
   `^[a-z0-9][a-z0-9_-]{0,62}$`." and the following rows (`dsn` … `tls`) get "PostgreSQL:" at the start of their
   meaning. After the TLS notes add:

```markdown
### Prometheus connections

| Key | Default | Meaning |
|---|---|---|
| `url` | required | API root; requests go to `<url>/api/v1/...`. For Mimir include its prefix (`https://mimir.example.com/prometheus`). No credentials, query string or fragment. |
| `mode` | `read` | Always `read`: every Prometheus tool is a read, and `mode: write` is rejected. |
| `auth` | `{type: none}` | `none`, `basic` (`username`, `password`) or `bearer` (`token`); secrets via `${VAR}` / `${file:...}`. |
| `headers` | `{}` | Extra request headers, e.g. `X-Scope-OrgID` for a Mimir/Cortex tenant. Values are treated as secrets. `Authorization`, `Proxy-Authorization`, `Host` and framing headers are refused. |
| `timeout` | `30s` | Per request (1s to 10m); also sent to Prometheus as the query evaluation timeout. |
| `tls` | `verify: true` | `verify: false` turns verification off; `ca_file` trusts only that CA. Default trust: certifi, or `SSL_CERT_FILE` / `SSL_CERT_DIR`. No client certificates. |
| `limits.max_series` | `100` | Series (and alerts) shown per response. |
| `limits.max_values` | `500` | Metric names and label values shown per response. |
| `limits.max_points` | `1000` | Points per series in `prom_query_range` (at most 11000); a step that needs more is refused with the smallest step that fits. |
| `limits.max_range` | `31d` | Longest window for range queries and for name/value listings. |
| `limits.max_query_length` | `20000` | Characters of PromQL or of a `match` selector. |
| `limits.max_response_bytes` | `65536` | Text returned to Claude. |
| `limits.max_body_bytes` | `16777216` | Bytes read from Prometheus per request (at least 65536). |

Outgoing HTTP (OIDC issuer, Prometheus) honours `HTTPS_PROXY` / `HTTP_PROXY`; put in-cluster hosts in `NO_PROXY`.

**Compatible servers.** Mimir/Cortex: `url: https://mimir.example.com/prometheus`, tenant in
`headers: {X-Scope-OrgID: ...}`. Thanos Query: `prom_alerts` needs the rules API (Ruler or sidecar); metadata may be
partial. VictoriaMetrics: metadata may be empty (names are still listed) and alerts/rule groups need
`-vmalert.proxyURL`. `connection_health` uses `/api/v1/status/buildinfo` and falls back to a trivial query.
```

4. Tools table: append

```markdown
| `prom_query` | read | PromQL at one instant (default now): each series with its value, or a scalar. |
| `prom_query_range` | read | PromQL over a window (default the last hour): per series points, min/max/avg/last and sampled points. |
| `prom_list_metrics` | read | Metric names with data in a window, with type and help; `name_contains` and `match` filters. |
| `prom_label_values` | read | Values of one label, optionally only on series matching a selector. |
| `prom_alerts` | read | Firing and pending alerts, and the state of every rule group. |
```

   and below the table: "Prometheus times accept RFC3339 (`2026-11-22T10:00:00Z`), unix seconds, or `now`,
   `now-15m`, `now-2h`; windows default to the last hour. Without `step`, `prom_query_range` picks one that gives up to
   about 120 points."
5. Security model: before `### HTTP transport` add

```markdown
### Prometheus connections

- Read-only by design: Ratatoskr calls only the query, query_range, label values, metadata, alerts, rules and
  buildinfo endpoints, never the admin or write APIs, whatever flags the server runs with.
- **PromQL is not restricted.** Anyone with read access to the connection can run any query, including expensive
  ones. Ratatoskr limits the window (`max_range`), the points per series (`max_points`), sends the evaluation
  `timeout` to Prometheus and enforces its own deadline, caps what it reads (`max_body_bytes`) and what it returns.
  Keep Prometheus' own `--query.timeout`, `--query.max-samples` and `--query.max-concurrency` (or the Mimir/Thanos
  per-tenant limits) in place, and give each connection a credential or tenant that only sees what its users may see.
- Credentials (`auth`, header values) never appear in errors, logs or `check-config` output. Error texts and warnings
  from the server are passed on with URLs, IP addresses, `host:port` pairs and internal host names removed (best
  effort); query results are returned unchanged. `serve` and `check-config` warn when credentials would go over
  plain `http` to a host other than loopback.
```

6. Development: change the integration comment to `# needs Docker: starts PostgreSQL and Prometheus with testcontainers`.

- [ ] **Step 4: CLAUDE.md**

1. In the intro, after "…`Dockerfile`)." add "Stage 2 adds Prometheus connections
   (`docs/superpowers/plans/2026-11-22-phase2-prometheus.md`)."
2. Commands: the integration line says testcontainers starts `postgres:17` **and `prom/prometheus:v3.16.0`**.
3. Layout: in the `config/` bullet add "`http_models.py` (auth/headers/TLS of HTTP kinds), `prometheus_models.py`,
   `shared.py`"; in the `backends/` bullet add "`timeparse.py` (RFC3339 / unix / `now-15m`, ranges, steps; shared with
   Loki)"; add two bullets after `backends/postgres/`:

```markdown
- `backends/http/` shared by HTTP backends: `client.py` (lazy httpx client, deadline, capped read, safe errors),
  `options.py` (auth headers, TLS trust), `scrub.py` (addresses out of server messages).
- `backends/prometheus/` endpoints and error envelope (`api.py`), backend (`backend.py`), result parsing (`series.py`),
  text (`formatting.py`, `summarize.py`), tool logic (`querying.py`, `discovery.py`, `alerts.py`), registration
  (`tools.py`) and tool texts (`descriptions.py`).
```

   and in the Tests bullet mention "`tests/unit/prom_helpers.py` with the `prom_api` (respx) and `prom_backend`
   fixtures in `tests/unit/conftest.py`".
4. Rules: add

```markdown
- Prometheus: only the read endpoints in `backends/prometheus/api.py` (query, query_range, label values, metadata,
  alerts, rules, buildinfo); never admin or write APIs; `mode` is always `read`. Server messages (errors, warnings,
  rule errors) go through `scrub_upstream_text`; successful output is not scrubbed. Never put the URL, a header value
  or a credential into a message. Prometheus tools pass `kind=` and `truncation_hint=` to `ToolRuntime.run`.
- Time arguments are parsed only by `backends/timeparse.py` (errors are `InvalidRequestError`); HTTP backends talk to
  their servers only through `backends/http/client.py`.
```

- [ ] **Step 5: pyproject.toml**

`description = "Ratatoskr: a secure, multi-connection MCP server that lets Claude query PostgreSQL and Prometheus."`,
add the classifier `"Topic :: System :: Monitoring",` after `"Topic :: Database",`, and change the marker to
`markers = ["integration: needs Docker; starts PostgreSQL and Prometheus containers via testcontainers"]`.

- [ ] **Step 6: Contract notes**

Append to `docs/superpowers/plans/2026-11-21-phase1-interfaces.md`:

```markdown
## Aşama 2 (Prometheus) ekleri

Plan: `docs/superpowers/plans/2026-11-22-phase2-prometheus.md`. Sözleşmeyi bozmadan eklenenler; Loki (aşama 3) bunları
aynen kullanır:

- `config/shared.py`: `DEFAULT_MAX_RESPONSE_BYTES`, `duration_value` (`models.py`'den taşındı; mypy strict yeniden
  dışa aktarmadığı için diğer modüller sabiti `config.shared`'dan alır).
- `config/http_models.py`: `HttpAuth = NoAuth | BasicAuth | BearerAuth` (`type` ile ayrılır), `HttpTlsSettings(verify=True,
  ca_file=None)`, `check_base_url`, `check_headers`, `stringify_header_values`, `RESERVED_HEADERS`. Header değerleri
  `SecretStr`.
- `config/prometheus_models.py`: `PrometheusLimits`, `PrometheusConnection(kind="prometheus", mode: Literal["read"],
  url, auth, headers, tls, timeout, limits)`; `ConnectionConfig = PostgresConnection | PrometheusConnection`.
  Loader `union_tag_invalid` mesajını etiketi tekrarlamadan yazar.
- `backends/timeparse.py`: `parse_time(text, *, now, argument)`, `parse_duration_text(text, *, argument)`,
  `resolve_range(start, end, *, now, max_range, default_span=1h) -> TimeRange`, `auto_step`, `resolve_step(step, span,
  *, max_points)`, `point_count`, `format_time`, `format_duration`, `unix_seconds`, `step_seconds`, `utc_now`. Hatalar
  `InvalidRequestError`.
- `backends/http/`: `HttpClient(connection, *, base_url, auth, headers, tls, timeout, max_body_bytes)` —
  `open()` (istek atmaz), `aclose()`, `request(method, path, *, params, form, too_large_hint) -> HttpReply(status,
  body)`; `ResponseTooLargeError`, `EndpointNotFoundError`, `status_error`, `parse_json`, `is_certificate_error`;
  `options.build_auth/build_verify/default_ssl_context`; `scrub.scrub_upstream_text(text, *, hosts)`.
- `backends/limits.py`: `clip_input(text, limit=64)`.
- `ToolRuntime.run(..., kind: str | None = None, truncation_hint: str = TRUNCATION_HINT)`: `kind` yetkilendirmeden
  sonra, backend açılmadan önce kontrol edilir (yasak bağlantı yine "not found").
- `observability/logging.py`: `httpx` logger'ı `log_level: INFO` iken WARNING (istek satırları iç host ve PromQL
  taşır).
```

- [ ] **Step 7: Check and commit**

Run: `.venv/Scripts/python -m pytest tests/unit/test_example_config.py -q`, then
`.venv/Scripts/ratatoskr check-config --config config.example.yaml` with `APP_DB_DSN` set (expect `Config OK`).

```bash
git add config.example.yaml tests/unit/test_example_config.py README.md CLAUDE.md pyproject.toml docs/superpowers/plans/2026-11-21-phase1-interfaces.md
git commit -m "Document Prometheus connections and tools" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 17: Final verification

- [ ] **Step 1: Full checks**

```
.venv/Scripts/python -m pytest -q
.venv/Scripts/python -m pytest -m integration -q
.venv/Scripts/python -m ruff check src tests
.venv/Scripts/python -m ruff format --check src tests
.venv/Scripts/python -m mypy src
```

Expected: `1473 passed, 4 skipped, 154 deselected` (baseline 1261 + 212 new unit tests); integration `154 passed`
(143 + 11); ruff and mypy clean.

- [ ] **Step 2: Manual smoke test over stdio (optional, local Prometheus only)**

With the Task 15 container running (or any local Prometheus on 127.0.0.1), a config with
`connections: {prom: {kind: prometheus, url: http://127.0.0.1:<port>}}` and `stdio_role: admins`, ask Claude Code to
call `list_connections`, `prom_alerts` and `prom_query_range` with `promql: up`. Never point it at a production
Prometheus from a development machine.

- [ ] **Step 3: Review against the spec**

Spec §6.3: five tools with the listed arguments (plus `name_contains`, optional windows — Decisions 2); §6.5: RFC3339
and relative times, default last hour, 100 series, 64 KiB text, explicit truncation notes, no headers or internal hosts
in errors; §10: unit tests for time parsing, limits/truncation and Prometheus summaries, integration tests with sample
data and limits. `list_connections` shows `prometheus` connections with `read`.
