# Stage 4: Packaging and Open-Source Hygiene Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Ratatoskr 1.0 as an open-source project a team can run: Prometheus metrics on a separate listener,
`compose.yml` (Ratatoskr + Caddy) and `compose.dev.yml` (sample PostgreSQL, Prometheus, Loki), CI with image scan and
GHCR release, and the documentation set of spec §11, with the repository rename prepared but not performed.

**Architecture:** Metrics are derived from the audit events that `ToolRuntime` and `record_auth_event` already
emit (a `MetricsAuditSink` next to the log and SQLite sinks), kept in a `prometheus_client` registry with bounded
labels, and served by a small asyncio listener on `server.metrics_host:metrics_port` that each composition root
(stdio: new `transport/stdio.py`; HTTP: `transport/app.py` lifespan) runs for as long as it serves. Packaging is
files plus static tests that keep them consistent with the code (compose network vs `trusted_proxies`, workflow
pinning, every setting documented, one repository slug).

**Tech Stack:** Python 3.12, prometheus-client 0.26.0, asyncio streams, Docker Compose v2, Caddy 2.11.9,
PostgreSQL 17, Prometheus 3.16.0, Loki 3.7.9, GitHub Actions (checkout v7.0.1, setup-python v7.1.0, docker/*),
Trivy 0.76.2, actionlint 1.7.12.

---

## Read first

- `CLAUDE.md` (commands, rules; this plan updates it in Task 20).
- `docs/superpowers/specs/2026-11-21-multi-backend-redesign-design.md` §8 (metrics), §9 (packaging), §10 (tests),
  §11 (docs set), §12 stage 4.
- Code the metrics hook into: `src/ratatoskr/tools/runtime.py` (`_record`), `src/ratatoskr/auth/events.py`
  (`record_auth_event`, `AuthEventName`), `src/ratatoskr/observability/audit.py` (`AuditSink`,
  `CompositeAuditSink`), `src/ratatoskr/backends/registry.py`, `src/ratatoskr/transport/app.py`,
  `src/ratatoskr/cli.py`.
- Existing packaging: `Dockerfile`, `.dockerignore`, `constraints.txt`, `pyproject.toml`, `docker-compose.yml`
  (0.1, deleted here), `README.md`, `config.example.yaml`, `docs/authentik.md`.

## How this plan was verified

Every task was applied to a fresh copy of the working tree (git history with a baseline commit `bd25c09` = repo
`1739802`, one commit per task) at
`C:\Users\Kerem\AppData\Local\Temp\claude\a53b16b5e605b485\b1d07c73-93d5-4292-9b08-c158b8d4cb72\scratchpad\p4`.
The code and file contents below are copied from that tree. Results there:

| Check | Baseline | After all tasks |
|---|---|---|
| `pytest -q` (Windows, Python 3.13) | 1773 passed, 4 skipped | 1874 passed, 4 skipped |
| `pytest -q` in `python:3.12-slim` (Linux, the CI install command) | - | 1856 passed (+ ruff, format, mypy clean) |
| `pytest -m integration -q` (Docker Desktop) | 167 | 174 passed |
| `ruff check`, `ruff format --check`, `mypy --strict src` | clean | clean (108 source files) |
| `docker build` + `docker run --read-only ... --version`, `id -u` = 10001 | | ok |
| Trivy 0.76.2 `--severity HIGH,CRITICAL --ignore-unfixed` | base image: 1 HIGH (zlib1g, fixed in Debian) | 0 (after Task 11's `apt-get upgrade`) |
| `actionlint` 1.7.12 on both workflows | | 0 errors |
| `docker compose -f compose.yml config` / local `up` with `RATATOSKR_DOMAIN=localhost` | | ok: healthy, Caddy at 10.203.53.10, `/healthz` `/metrics` 404 via Caddy, HSTS, 401 on `/mcp`, `/data` owned by 10001, root read-only |
| `docker compose -f compose.dev.yml up` + stdio session via `docker compose run -T --use-aliases ratatoskr` | | 10 tool calls answered as expected (read role, write role, DDL refused by the GRANTs, unknown connection, Prometheus, alerts, Loki); dev Prometheus scraped `ratatoskr_tool_calls_total` and `ratatoskr_backend_up` from `ratatoskr:9100` |
| host run `serve --insecure-dev --config dev/ratatoskr/local-http.yaml` | | `/healthz` ok, `:9100/metrics` ok, `/metrics` on 8000 is 404; with 9100 taken: exit 1 before serving |

The workflows themselves cannot run locally; actionlint and `tests/unit/test_workflows.py` cover their syntax and
policy. Action SHAs were resolved on 2026-11-22 with anonymous `git ls-remote` of the public action repositories.

Machine note: `pip --index-url https://pypi.org/simple` does not drop the extra index configured in pip.ini on this
machine (the install hangs on `pypi.ngc.nvidia.com`). Prefix pip commands with `PIP_CONFIG_FILE=nul` (Git Bash) or
`$env:PIP_CONFIG_FILE='nul'` (PowerShell) when that happens.

## Decisions (where the spec left room)

1. **Metrics library: `prometheus-client` 0.26.0**, not a hand-written exposition writer: pure Python, no
   transitive dependencies, `py.typed`, standard text format (label escaping, histogram buckets) we would otherwise
   re-implement and test. Only its data model and `generate_latest` are used, with a private `CollectorRegistry` per
   `Metrics` instance (tests build several); its threaded `start_http_server` and ASGI app are **not** used (they
   would put `/metrics` on a thread or on the MCP app). `_created` series are disabled process-wide.
2. **Names carry a `ratatoskr_` prefix** (`ratatoskr_tool_calls_total`, `ratatoskr_tool_duration_seconds`,
   `ratatoskr_backend_up`, `ratatoskr_auth_events_total`); spec §8 lists them unprefixed. Prometheus naming
   practice, and `backend_up` alone would collide with other exporters. The spec's labels are kept exactly.
3. **One source of truth: the audit event.** `MetricsAuditSink` joins the `CompositeAuditSink`; `ToolRuntime` and the
   auth code are unchanged. Consequence (documented): arguments rejected by FastMCP's schema validation are neither
   audited nor counted. Auth events are told apart by `tool in AuthEventName`; a test asserts no tool has such a name.
4. **Label bounds.** `connection` is a configured name, `_all` (tools not bound to one connection) or `_unresolved`
   (name not configured, or the call ended in `ConnectionNotFoundError` or `PermissionError`). So unknown **and**
   forbidden connections share one value, as required; `InsufficientAccessError` keeps the name (the caller can see
   that connection). `_`-prefixed values cannot collide with connection names (`^[a-z0-9]...`). `auth_events_total`
   is pre-initialised to 0 for every event.
5. **`backend_up` is an active check at scrape time**: every configured connection, through the registry (lazy
   open, 10 s back-off shared with tool calls), `health()` bounded by 5 s, results cached 15 s behind a lock.
   With metrics on, every connection is therefore opened within one scrape of the start. Not audited. Failures are
   logged by class only (an HTTP library error can quote a header value).
6. **Listener.** New setting `server.metrics_host` (default `127.0.0.1`); `metrics_port` must be 1..65535 and, over
   HTTP, differ from `server.port`. Own asyncio TCP server: one request head of at most 8 KiB, `GET`/`HEAD /metrics`
   only, `Connection: close`, 10 s per exchange, in-flight exchanges cancelled on shutdown. Content type
   `text/plain; version=0.0.4` (Prometheus 2 and 3 parse it). Works for **stdio and HTTP**. A bind failure is fatal
   (exit 1 before serving). No warning for a non-loopback host (it is the normal container case); the docs say not to
   publish it.
7. **stdio composition root** moves from `cli.py` to `transport/stdio.py` (`asyncio.run(serve_stdio(config))`,
   `FastMCP.run_stdio_async`), so the registry and the metrics listener live exactly as long as the session. Three
   `test_cli.py` tests change their patch target accordingly.
8. **`compose.yml`.** Image `${RATATOSKR_IMAGE:-ratatoskr:local}` with `build: .` (no released image exists yet;
   after release set `RATATOSKR_IMAGE`). Fixed network `10.203.53.0/24` (outside Docker's default pools; overridable)
   with Caddy at `10.203.53.10`, passed to the container as `RATATOSKR_PROXY_IP` so `deploy/config.example.yaml` can
   trust exactly `/32`. One `.env` (compose interpolation + container env); password hashes single-quoted. Both
   services `read_only`, `cap_drop: [ALL]`, `no-new-privileges`; Caddy gets `NET_BIND_SERVICE` and a `/tmp` tmpfs.
   Caddy adds HSTS and answers `/healthz`, `/readyz`, `/metrics` with 404. `stop_grace_period: 15s`.
9. **`compose.dev.yml`.** Ratatoskr there is **stdio** (profile `stdio`, `docker compose run --rm -T --use-aliases
   ratatoskr`), usable as a Claude Code / Desktop command; `--use-aliases` lets the dev Prometheus scrape it.
   `--insecure-dev` requires a loopback bind, which a published container port cannot reach, so HTTP tries run on
   the host (`dev/ratatoskr/local-http.yaml`, dev-only literal secrets that `serve` refuses without `--insecure-dev`).
   Single-tenant Loki; the log generator is busybox `wget` in `alpine` (no external service, no package install).
   Published ports `127.0.0.1:55432/59090/53100`.
10. **Integration tests keep testcontainers** (spec §9 says compose.dev would serve them): per-session containers
    on random loopback ports, no dependency on a stack someone left running (or its data), the same in CI, and the
    167 existing tests already use them. The dev seed SQL and the `docs/postgres-roles.md` recipe are tested with
    their own containers (roles are cluster-wide and would clash with `test_pg_write_role.py`).
11. **CI.** Trivy runs as a digest-pinned `aquasec/trivy` image instead of `trivy-action` (no third-party action
    code with the token, same command locally). Dev tools pinned in a new `constraints-dev.txt`. Unit tests on 3.12
    and 3.13. `release.yml` calls `ci.yml` (`workflow_call`), refuses a tag that is not `v` + `__version__`, accepts
    only `vX.Y.Z`, scans linux/amd64 before pushing, then pushes linux/amd64 + linux/arm64 with `sbom: true` and
    `provenance: mode=max` (BuildKit attestations: no `id-token` or `attestations` permission needed). Image name
    `ghcr.io/<owner>/ratatoskr`, independent of the repository name. Permissions: `contents: read` everywhere,
    `packages: write` only on the release job.
12. **Dockerfile.** Literal `FROM python:3.12-slim@sha256:...` in both stages (Dependabot cannot update an `ARG`),
    kept equal by a test. The runtime stage runs `apt-get upgrade`: the pinned digest is the newest
    `python:3.12-slim`, yet Trivy reports a fixed HIGH in its `zlib1g`; rebuilding now pulls Debian security fixes at
    build time (builds are no longer byte-reproducible; the base layers still are).
13. **Docs.** Settings are documented only in `docs/configuration.md` (moved from the README, with metrics and
    container sections); the README's security section moves to a new `docs/security-model.md` (not in §11's list,
    added so the README stays a quick start); `tests/unit/test_docs.py` checks that every model field is documented,
    all relative links and anchors resolve, the README has no settings table, and the metrics section names every
    series and auth event. `docs/postgres-roles.md` SQL is executed by an integration test.
14. **Repository rename prep.** Links keep the current slug `keremkocatus/claude-postgresql` (they work today; after
    the rename GitHub redirects them). `tests/unit/test_repo_links.py` holds the slug, fails on any mixed link, and
    its docstring has the one-line `sed` for the switch. Nothing is renamed on GitHub.
15. **Dependabot**: github-actions, pip (`mcp` minor/major ignored: the cap is deliberate), docker (both `FROM`
    lines), docker-compose; grouped weekly.

## File structure

Created:

| Path | Responsibility |
|---|---|
| `src/ratatoskr/observability/metrics.py` | Series, label bounds, rendering |
| `src/ratatoskr/observability/metrics_sink.py` | Audit events to metrics |
| `src/ratatoskr/observability/backend_probe.py` | `ratatoskr_backend_up`, cached health checks |
| `src/ratatoskr/observability/metrics_http.py` | One HTTP request head to one response |
| `src/ratatoskr/observability/metrics_server.py` | asyncio listener, `MetricsStartupError` |
| `src/ratatoskr/observability/metrics_service.py` | `build_metrics`: composition for one process |
| `src/ratatoskr/transport/stdio.py` | stdio composition root |
| `compose.yml`, `deploy/Caddyfile`, `deploy/config.example.yaml`, `.env.example` | Production compose stack |
| `compose.dev.yml`, `dev/postgres/initdb/*.sql`, `dev/prometheus/*.yml`, `dev/loki/loki.yaml`, `dev/loggen/loggen.sh`, `dev/ratatoskr/{stdio,local-http}.yaml` | Dev stack |
| `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/dependabot.yml`, `constraints-dev.txt` | CI/CD |
| `docs/configuration.md`, `docs/security-model.md`, `docs/postgres-roles.md`, `docs/connectors.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `MIGRATION.md` | Docs set |
| tests: `unit/test_config_metrics.py`, `test_constraints.py`, `test_metrics.py`, `test_metrics_sink.py`, `test_backend_probe.py`, `test_metrics_http.py`, `test_metrics_server.py`, `test_metrics_service.py`, `test_stdio_serve.py`, `secure_http/e2e/test_http_metrics.py`, `test_dockerfile.py`, `test_deploy_files.py`, `test_dev_stack_files.py`, `test_workflows.py`, `test_docs.py`, `test_repo_links.py`; `integration/test_metrics_listener.py`, `test_postgres_roles_doc.py`, `test_dev_seed.py` | |

Modified: `src/ratatoskr/config/models.py`, `config/notices.py`, `cli.py`, `transport/app.py`, `pyproject.toml`,
`constraints.txt`, `Dockerfile`, `.gitignore`, `.gitattributes`, `README.md`, `config.example.yaml`,
`docs/authentik.md`, `CLAUDE.md`, `tests/unit/test_cli.py`, `tests/unit/test_example_config.py`,
`tests/unit/secure_http/test_cli_http.py`, `tests/unit/secure_http/test_transport_settings.py`.

Deleted: `docker-compose.yml` (`railway.json` is already gone).

## Conventions for every task

- Work on branch `feature/packaging` in the repo root; Windows venv: `.venv/Scripts/python`.
- Commit at the end of each task with an imperative subject and the trailer:
  `git commit -m "<subject>" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`.
- Do not push, do not log in to registries, do not touch GitHub settings (the owner does that, see the end).
- Files under `dev/` and the `.sh` script must keep LF line endings (Task 13 adds the `.gitattributes` rule; write
  them with LF).

---

### Task 1: `server.metrics_host`, `metrics_port` validation, no more "not implemented"

**Files:**
- Modify: `src/ratatoskr/config/models.py` (`ServerSettings`, `RatatoskrConfig._check_transport`)
- Modify: `src/ratatoskr/config/notices.py`, `src/ratatoskr/cli.py` (`summarize`)
- Test: `tests/unit/test_config_metrics.py` (new), `tests/unit/secure_http/test_cli_http.py`,
  `tests/unit/secure_http/test_transport_settings.py`

- [ ] **Step 1: Write the failing test**

```python
"""server.metrics_host / server.metrics_port: a separate, unauthenticated listener for /metrics."""

from typing import Any

import pytest
from pydantic import ValidationError

from ratatoskr.cli import summarize
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.config.notices import config_warnings


def _config(**server: Any) -> RatatoskrConfig:
    connections = {"main": {"kind": "postgres", "dsn": "postgresql://u:p@h/db"}}
    return RatatoskrConfig.model_validate({"server": server, "connections": connections})


def _http(**server: Any) -> dict[str, Any]:
    auth = {"mode": "local", "local": {"users": [{"username": "kerem", "password_hash": "x"}]}}
    values = {"transport": "streamable-http", "public_url": "https://mcp.example.com", "secret_key": "k" * 32}
    return {
        "server": {**values, **server},
        "auth": auth,
        "connections": {"main": {"kind": "postgres", "dsn": "postgresql://u:p@h/db"}},
    }


def test_metrics_are_off_and_loopback_by_default() -> None:
    server = _config().server
    assert server.metrics_port is None
    assert server.metrics_host == "127.0.0.1"


@pytest.mark.parametrize("port", [0, -1, 65536])
def test_metrics_port_must_be_a_tcp_port(port: int) -> None:
    with pytest.raises(ValidationError, match="metrics_port"):
        _config(metrics_port=port)


def test_metrics_port_must_differ_from_the_http_port() -> None:
    with pytest.raises(ValidationError, match=r"server\.metrics_port must differ from server\.port"):
        RatatoskrConfig.model_validate(_http(port=8000, metrics_port=8000))


def test_stdio_ignores_server_port_for_the_metrics_check() -> None:
    assert _config(port=9100, metrics_port=9100).server.metrics_port == 9100


def test_metrics_port_no_longer_warns() -> None:
    assert config_warnings(_config(metrics_port=9100)) == []


def test_check_config_summary_shows_the_metrics_listener() -> None:
    assert "metrics: off" in summarize(_config())
    assert "metrics: http://0.0.0.0:9100/metrics" in summarize(_config(metrics_host="0.0.0.0", metrics_port=9100))
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_metrics.py -q`
Expected: 7 failed, 1 passed (`metrics_host` missing, no range check, the notice still warns, no `metrics:` line).

- [ ] **Step 3: Implement**

```diff
diff --git a/src/ratatoskr/config/models.py b/src/ratatoskr/config/models.py
index 54495f8..8026616 100644
--- a/src/ratatoskr/config/models.py
+++ b/src/ratatoskr/config/models.py
@@ -68,7 +68,9 @@ class ServerSettings(BaseModel):
     public_url: AnyHttpUrl | None = None
     host: str = "127.0.0.1"
     port: int = 8000
-    metrics_port: int | None = None
+    # Prometheus /metrics on a separate listener without authentication: never the public port or the proxy.
+    metrics_host: str = "127.0.0.1"
+    metrics_port: int | None = Field(default=None, ge=1, le=65535)
     state_path: Path = Path("/data/state.db")
     secret_key: SecretStr | None = None
     allowed_redirect_hosts: list[str] = ["claude.ai", "claude.com", "localhost", "127.0.0.1"]
@@ -314,6 +316,8 @@ class RatatoskrConfig(BaseModel):
             problems.append("server.public_url is required")
         elif server.public_url.scheme != "https" and not insecure_dev:
             problems.append("server.public_url must use https (plain http is allowed only with --insecure-dev)")
+        if server.metrics_port is not None and server.metrics_port == server.port:
+            problems.append("server.metrics_port must differ from server.port")
         if problems:
             raise ValueError("transport streamable-http: " + "; ".join(problems))
         return self
```

```diff
diff --git a/src/ratatoskr/config/notices.py b/src/ratatoskr/config/notices.py
index ce2d172..18bd762 100644
--- a/src/ratatoskr/config/notices.py
+++ b/src/ratatoskr/config/notices.py
@@ -1,5 +1,5 @@
-"""Start-up warnings ``serve`` and ``check-config`` report: settings accepted but not implemented yet, and risky but
-allowed choices such as credentials sent over plain http."""
+"""Start-up warnings ``serve`` and ``check-config`` report: risky but allowed choices such as credentials sent over
+plain http."""
 
 from __future__ import annotations
 
@@ -9,11 +9,6 @@ from ratatoskr.config.models import LOOPBACK_HOSTS, RatatoskrConfig
 
 def config_warnings(config: RatatoskrConfig) -> list[str]:
     warnings: list[str] = []
-    if config.server.metrics_port is not None:
-        warnings.append(
-            f"server.metrics_port is set ({config.server.metrics_port}) but metrics are not implemented yet;"
-            " nothing listens on that port"
-        )
     for name, connection in sorted(config.connections.items()):
         if (
             isinstance(connection, HttpConnection)
```

```diff
diff --git a/src/ratatoskr/cli.py b/src/ratatoskr/cli.py
index 6ced2a6..52f2cab 100644
--- a/src/ratatoskr/cli.py
+++ b/src/ratatoskr/cli.py
@@ -65,10 +65,18 @@ def build_parser() -> argparse.ArgumentParser:
     return parser
 
 
+def _metrics_summary(config: RatatoskrConfig) -> str:
+    server = config.server
+    if server.metrics_port is None:
+        return "off"
+    host = f"[{server.metrics_host}]" if ":" in server.metrics_host else server.metrics_host
+    return f"http://{host}:{server.metrics_port}/metrics"
+
+
 def summarize(config: RatatoskrConfig) -> str:
     """A secret-free overview of the configuration."""
     server = config.server
-    lines = [f"transport: {server.transport}"]
+    lines = [f"transport: {server.transport}", f"metrics: {_metrics_summary(config)}"]
     if server.transport == "stdio":
         lines.append(f"stdio_role: {server.stdio_role or '(not set: the stdio user cannot see any connection)'}")
     lines.append(f"auth: {config.auth.mode if config.auth else 'none'}")
```

- [ ] **Step 4: Update the two tests that asserted the old warning**

```diff
diff --git a/tests/unit/secure_http/test_cli_http.py b/tests/unit/secure_http/test_cli_http.py
index dbcc1d2..4a87654 100644
--- a/tests/unit/secure_http/test_cli_http.py
+++ b/tests/unit/secure_http/test_cli_http.py
@@ -146,14 +146,14 @@ def test_weak_hash_warning_is_reported_exactly_once(write_config, monkeypatch, c
 
 
 @pytest.mark.parametrize("command", ["serve", "check-config"])
-def test_metrics_port_is_reported_as_not_implemented(write_config, monkeypatch, capsys, command) -> None:
+def test_metrics_port_is_accepted_without_a_warning(write_config, monkeypatch, capsys, command) -> None:
     monkeypatch.setattr(uvicorn.Server, "run", lambda self, sockets=None: None)
     path = Path(write_config())
     path.write_text(path.read_text(encoding="utf-8").replace("  host:", "  metrics_port: 9100\n  host:"), "utf-8")
     assert main([command, "--config", str(path)]) == 0
     captured = capsys.readouterr()
-    assert (captured.out + captured.err).count("server.metrics_port") == 1
-    assert "not implemented" in captured.out + captured.err
+    assert "server.metrics_port" not in captured.out + captured.err
+    assert "not implemented" not in captured.out + captured.err
 
 
 def test_check_config_reports_an_unwritable_state_directory(write_config, tmp_path, capsys) -> None:
```

```diff
diff --git a/tests/unit/secure_http/test_transport_settings.py b/tests/unit/secure_http/test_transport_settings.py
index 26077f1..5da3d97 100644
--- a/tests/unit/secure_http/test_transport_settings.py
+++ b/tests/unit/secure_http/test_transport_settings.py
@@ -417,6 +417,6 @@ def test_missing_state_dir_under_unwritable_parent_says_where_to_check(make_conf
     assert "does not exist" in message and "where `serve` runs" in message and "chown" not in message
 
 
-def test_metrics_port_warns_that_it_is_not_implemented(make_config) -> None:
+def test_metrics_port_adds_no_warning(make_config) -> None:
     settings = check_http_preconditions(with_server(make_config(), metrics_port=9100), insecure_dev=False)
-    assert any("server.metrics_port" in w and "not implemented" in w for w in settings.warnings)
+    assert not any("metrics" in w for w in settings.warnings)
```

- [ ] **Step 5: Run**

Run: `.venv/Scripts/python -m pytest tests/unit/test_config_metrics.py tests/unit/secure_http/test_cli_http.py tests/unit/secure_http/test_transport_settings.py tests/unit/test_cli.py tests/unit/test_config_models.py -q`
Expected: all pass (141 at the time of writing).

- [ ] **Step 6: Commit** — `Add server.metrics_host and validate metrics_port; drop the not-implemented notice`

### Task 2: Depend on prometheus-client

**Files:**
- Modify: `pyproject.toml` (`dependencies`), `constraints.txt`
- Test: `tests/unit/test_constraints.py` (new)

- [ ] **Step 1: Write the test** (it passes for today's dependencies and fails as soon as one is unpinned)

```python
"""constraints.txt pins every direct runtime dependency of pyproject.toml at a version its specifier allows."""

import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

ROOT = Path(__file__).resolve().parents[2]


def _pins() -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (ROOT / "constraints.txt").read_text(encoding="utf-8").splitlines():
        line = line.split(";", 1)[0].strip()
        if line and not line.startswith("#"):
            name, version = line.split("==")
            pins[canonicalize_name(name)] = version.strip()
    return pins


def test_every_direct_dependency_is_pinned_within_its_range() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    pins = _pins()
    for spec in project["dependencies"]:
        requirement = Requirement(spec)
        name = canonicalize_name(requirement.name)
        assert name in pins, f"{name} is missing from constraints.txt"
        assert requirement.specifier.contains(pins[name]), f"{name}=={pins[name]} is outside {requirement.specifier}"
```

- [ ] **Step 2: Add the dependency and the pin**

```diff
diff --git a/pyproject.toml b/pyproject.toml
index c0b1117..f67479f 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -37,6 +37,8 @@ dependencies = [
     "uvicorn>=0.35",
     # Not imported directly: uvicorn's HTTP/1.1 parser. 0.16 fixes request smuggling (CVE-2025-43859).
     "h11>=0.16",
+    # /metrics data model and text exposition (no transitive dependencies); served by our own listener.
+    "prometheus-client>=0.26,<1",
 ]
 
 [project.urls]
```

```diff
diff --git a/constraints.txt b/constraints.txt
index e894a98..0516b3a 100644
--- a/constraints.txt
+++ b/constraints.txt
@@ -21,6 +21,7 @@ joserfc==1.8.0
 jsonschema==4.26.0
 jsonschema-specifications==2025.9.1
 mcp==1.30.0
+prometheus-client==0.26.0
 pycparser==3.12
 pydantic==2.14.4
 pydantic-core==2.50.5
```

- [ ] **Step 3: Install and run**

Run: `.venv/Scripts/python -m pip install --index-url https://pypi.org/simple -c constraints.txt -e ".[dev]"` then
`.venv/Scripts/python -m pytest tests/unit/test_constraints.py tests/unit/test_package.py -q`
Expected: 3 passed. The guard fails (`prometheus-client is missing from constraints.txt`) if the `pyproject.toml`
line is added without the pin.

- [ ] **Step 4: Commit** — `Depend on prometheus-client for the metrics exposition`

### Task 3: Metrics registry with bounded labels

**Files:**
- Create: `src/ratatoskr/observability/metrics.py`
- Test: `tests/unit/test_metrics.py`

- [ ] **Step 1: Write the failing test**

```python
"""Metrics: four Ratatoskr series with bounded labels, rendered in the Prometheus text format."""

from prometheus_client.parser import text_string_to_metric_families

from ratatoskr.auth.events import AuthEventName
from ratatoskr.observability.metrics import GLOBAL_CONNECTION, UNRESOLVED_CONNECTION, Metrics


def _samples(metrics: Metrics) -> dict[tuple[str, tuple[tuple[str, str], ...]], float]:
    out: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
    for family in text_string_to_metric_families(metrics.render().decode("utf-8")):
        for sample in family.samples:
            out[(sample.name, tuple(sorted(sample.labels.items())))] = sample.value
    return out


def test_tool_calls_are_counted_per_tool_connection_and_result() -> None:
    metrics = Metrics(["prod", "dev"])
    metrics.observe_tool("pg_query", "prod", "ok", 0.2)
    metrics.observe_tool("pg_query", "prod", "ok", 0.3)
    metrics.observe_tool("pg_query", "prod", "denied", 0.0)
    samples = _samples(metrics)
    key = ("connection", "prod"), ("result", "ok"), ("tool", "pg_query")
    assert samples[("ratatoskr_tool_calls_total", key)] == 2
    assert samples[("ratatoskr_tool_duration_seconds_count", (("connection", "prod"), ("tool", "pg_query")))] == 3
    assert samples[("ratatoskr_tool_duration_seconds_sum", (("connection", "prod"), ("tool", "pg_query")))] == 0.5


def test_auth_events_start_at_zero_for_every_known_event() -> None:
    metrics = Metrics([])
    metrics.count_auth_event("login_failed")
    samples = _samples(metrics)
    for event in AuthEventName.__args__:
        expected = 1 if event == "login_failed" else 0
        assert samples[("ratatoskr_auth_events_total", (("event", event),))] == expected


def test_backend_up_is_a_gauge_per_configured_connection() -> None:
    metrics = Metrics(["prod", "dev"])
    metrics.set_backend_up("prod", True)
    metrics.set_backend_up("dev", False)
    samples = _samples(metrics)
    assert samples[("ratatoskr_backend_up", (("connection", "prod"),))] == 1
    assert samples[("ratatoskr_backend_up", (("connection", "dev"),))] == 0


def test_unconfigured_names_never_become_label_values() -> None:
    metrics = Metrics(["prod"])
    assert metrics.connection_label("prod", None) == "prod"
    assert metrics.connection_label("ghost", "ConnectionNotFoundError") == UNRESOLVED_CONNECTION
    assert metrics.connection_label("../../etc/passwd", None) == UNRESOLVED_CONNECTION
    assert metrics.connection_label(None, None) == GLOBAL_CONNECTION
    metrics.set_backend_up("ghost", True)  # ignored: not a configured connection
    assert "ghost" not in metrics.render().decode("utf-8")


def test_forbidden_and_unauthenticated_calls_hide_the_name() -> None:
    metrics = Metrics(["prod"])
    assert metrics.connection_label("prod", "ConnectionNotFoundError") == UNRESOLVED_CONNECTION
    assert metrics.connection_label("prod", "PermissionError") == UNRESOLVED_CONNECTION
    assert metrics.connection_label("prod", "InsufficientAccessError") == "prod"


def test_fixed_labels_cannot_collide_with_connection_names() -> None:
    from ratatoskr.config.models import CONNECTION_NAME_RE

    assert CONNECTION_NAME_RE.fullmatch(GLOBAL_CONNECTION) is None
    assert CONNECTION_NAME_RE.fullmatch(UNRESOLVED_CONNECTION) is None


def test_no_created_series_are_exported() -> None:
    metrics = Metrics(["prod"])
    metrics.observe_tool("pg_query", "prod", "ok", 0.1)
    assert "_created" not in metrics.render().decode("utf-8")


def test_two_instances_do_not_share_state() -> None:
    first, second = Metrics(["prod"]), Metrics(["prod"])
    first.observe_tool("pg_query", "prod", "ok", 0.1)
    assert ("ratatoskr_tool_calls_total", (("connection", "prod"), ("result", "ok"), ("tool", "pg_query"))) not in (
        _samples(second)
    )
```

- [ ] **Step 2: Run it**

Run: `.venv/Scripts/python -m pytest tests/unit/test_metrics.py -q`
Expected: collection error, `ModuleNotFoundError: No module named 'ratatoskr.observability.metrics'`.

- [ ] **Step 3: Implement**

```python
"""Prometheus metrics (spec §8): tool calls and their latency, backend reachability and auth events.

Label values are bounded: ``tool`` and ``event`` come from code, ``result`` from the audit taxonomy and
``connection`` only from the configured connection names. A name a caller typed that is not configured, or that the
caller may not see (the call ended in ``ConnectionNotFoundError`` or had no identity), is exported as
:data:`UNRESOLVED_CONNECTION`, so neither user input nor the existence of hidden connections reaches a label.
No subject, query or secret is ever a label.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import get_args

from prometheus_client import (
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    PlatformCollector,
    ProcessCollector,
    disable_created_metrics,
    generate_latest,
)

from ratatoskr.auth.events import AuthEventName
from ratatoskr.observability.audit import AuditResult

# Neither can be a connection name: those match ^[a-z0-9][a-z0-9_-]{0,62}$.
GLOBAL_CONNECTION = "_all"
"""``connection`` of tools not bound to one connection (list_connections, connection_health without argument)."""
UNRESOLVED_CONNECTION = "_unresolved"
"""``connection`` of calls whose name is unknown, forbidden or was given without an identity."""

AUTH_EVENTS: tuple[str, ...] = get_args(AuthEventName)
DURATION_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0)
_HIDDEN_ERROR_CLASSES = frozenset({"ConnectionNotFoundError", "PermissionError"})

# `_created` series double every counter and histogram for no use here; process-wide, set once on import.
disable_created_metrics()  # type: ignore[no-untyped-call]  # untyped in prometheus-client 0.26


class Metrics:
    """One registry per instance (tests build several); ``render`` gives the text exposition format."""

    def __init__(self, connection_names: Iterable[str]) -> None:
        self._known = frozenset(connection_names)
        self.registry = CollectorRegistry()
        ProcessCollector(registry=self.registry)  # process_* series; only where /proc exists (Linux)
        PlatformCollector(registry=self.registry)  # python_info
        self._calls = Counter(
            "ratatoskr_tool_calls",
            "Tool calls by tool, connection and result (ok, denied, error, timeout).",
            ("tool", "connection", "result"),
            registry=self.registry,
        )
        self._duration = Histogram(
            "ratatoskr_tool_duration_seconds",
            "Tool call duration in seconds, from the start of the call to its result.",
            ("tool", "connection"),
            buckets=DURATION_BUCKETS,
            registry=self.registry,
        )
        self._backend_up = Gauge(
            "ratatoskr_backend_up",
            "1 if the connection answered its last health check, else 0 (checked at most every 15 s, on scrape).",
            ("connection",),
            registry=self.registry,
        )
        self._auth_events = Counter(
            "ratatoskr_auth_events",
            "Authentication events (sign-ins, refused sign-ins, rate limits, token reuse, revocations).",
            ("event",),
            registry=self.registry,
        )
        for event in AUTH_EVENTS:
            self._auth_events.labels(event=event)

    def connection_label(self, connection: str | None, error_class: str | None) -> str:
        if connection is None:
            return GLOBAL_CONNECTION
        if connection not in self._known or error_class in _HIDDEN_ERROR_CLASSES:
            return UNRESOLVED_CONNECTION
        return connection

    def observe_tool(self, tool: str, connection: str, result: AuditResult, seconds: float) -> None:
        """``connection`` must already be a label value (see :meth:`connection_label`)."""
        self._calls.labels(tool=tool, connection=connection, result=result).inc()
        self._duration.labels(tool=tool, connection=connection).observe(seconds)

    def count_auth_event(self, event: str) -> None:
        if event in AUTH_EVENTS:
            self._auth_events.labels(event=event).inc()

    def set_backend_up(self, connection: str, up: bool) -> None:
        if connection in self._known:
            self._backend_up.labels(connection=connection).set(1 if up else 0)

    def render(self) -> bytes:
        return generate_latest(self.registry)
```

- [ ] **Step 4: Run**

Run: `.venv/Scripts/python -m pytest tests/unit/test_metrics.py -q` and `.venv/Scripts/python -m mypy src`
Expected: 8 passed; mypy clean (the `type: ignore[no-untyped-call]` is needed: `disable_created_metrics` is untyped
in 0.26).

- [ ] **Step 5: Commit** — `Add the metrics registry with bounded labels`

### Task 4: MetricsAuditSink

**Files:**
- Create: `src/ratatoskr/observability/metrics_sink.py`
- Test: `tests/unit/test_metrics_sink.py`

- [ ] **Step 1: Write the failing test**

```python
"""MetricsAuditSink: every audit event becomes a tool-call or an auth-event sample."""

import pytest

from ratatoskr.auth.events import record_auth_event
from ratatoskr.auth.policy import Policy
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.base import Backend
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import Access
from ratatoskr.observability.audit import build_event
from ratatoskr.observability.metrics import GLOBAL_CONNECTION, UNRESOLVED_CONNECTION, Metrics
from ratatoskr.observability.metrics_sink import MetricsAuditSink
from ratatoskr.tools.runtime import ToolOutput, ToolRuntime
from tests.fakes import FakeFactory, make_config

CONFIG = make_config(connections={"prod": {"mode": "read"}}, roles={"team": {"prod": "read"}})


def _value(metrics: Metrics, name: str, **labels: str) -> float | None:
    return metrics.registry.get_sample_value(name, labels)


def _runtime(role: str | None = "team") -> tuple[ToolRuntime, Metrics]:
    metrics = Metrics(["prod"])
    registry = BackendRegistry(CONFIG, factory=FakeFactory())
    return ToolRuntime(Policy(CONFIG), registry, StdioPrincipalResolver(role), MetricsAuditSink(metrics)), metrics


async def _ok(backend: Backend, access: Access) -> ToolOutput:
    return ToolOutput(text="fine", rows=1)


async def test_tool_calls_through_the_runtime_are_counted() -> None:
    runtime, metrics = _runtime()
    await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=_ok)
    await runtime.run(tool="pg_execute", connection="prod", need=Access.WRITE, call=_ok)
    labels = {"tool": "pg_query", "connection": "prod"}
    assert _value(metrics, "ratatoskr_tool_calls_total", **labels, result="ok") == 1
    assert _value(metrics, "ratatoskr_tool_calls_total", tool="pg_execute", connection="prod", result="denied") == 1
    assert _value(metrics, "ratatoskr_tool_duration_seconds_count", **labels) == 1


async def test_unknown_and_forbidden_connections_share_one_label() -> None:
    runtime, metrics = _runtime(role=None)
    await runtime.run(tool="pg_query", connection="ghost", need=Access.READ, call=_ok)
    await runtime.run(tool="pg_query", connection="prod", need=Access.READ, call=_ok)
    labels = {"tool": "pg_query", "connection": UNRESOLVED_CONNECTION, "result": "denied"}
    assert _value(metrics, "ratatoskr_tool_calls_total", **labels) == 2
    text = metrics.render().decode("utf-8")
    assert "ghost" not in text
    assert 'connection="prod"' not in text


async def test_global_tools_use_the_global_label() -> None:
    runtime, metrics = _runtime()

    async def call(principal: object) -> ToolOutput:
        return ToolOutput(text="x")

    await runtime.run_global(tool="list_connections", call=call)
    labels = {"tool": "list_connections", "connection": GLOBAL_CONNECTION, "result": "ok"}
    assert _value(metrics, "ratatoskr_tool_calls_total", **labels) == 1


def test_auth_events_are_counted_by_name_only() -> None:
    metrics = Metrics([])
    sink = MetricsAuditSink(metrics)
    record_auth_event(sink, "login_failed", subject="alice@example.com", auth_source="local", result="denied")
    assert _value(metrics, "ratatoskr_auth_events_total", event="login_failed") == 1
    assert (
        _value(metrics, "ratatoskr_tool_calls_total", tool="login_failed", connection="_all", result="denied") is None
    )
    assert "alice" not in metrics.render().decode("utf-8")


async def test_no_tool_is_named_like_an_auth_event() -> None:
    from ratatoskr.app import build_app
    from ratatoskr.observability.metrics import AUTH_EVENTS
    from tests.fakes import RecordingSink

    app = build_app(CONFIG, resolver=StdioPrincipalResolver("team"), audit=RecordingSink())
    names = {tool.name for tool in await app.list_tools()}
    assert names and not names & set(AUTH_EVENTS)


def test_a_failing_metrics_call_never_reaches_the_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    metrics = Metrics(["prod"])

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(metrics, "observe_tool", broken)
    event = build_event(
        subject="s",
        auth_source="stdio",
        connection="prod",
        tool="pg_query",
        query_text=None,
        duration_ms=1.0,
        rows=None,
        result="ok",
        error_class=None,
    )
    MetricsAuditSink(metrics).record(event)  # does not raise
```

- [ ] **Step 2: Run it** — `.venv/Scripts/python -m pytest tests/unit/test_metrics_sink.py -q`; expected: collection
  error (`ratatoskr.observability.metrics_sink` missing).

- [ ] **Step 3: Implement**

```python
"""An audit sink that turns audit events into metrics, so tool calls and auth events are counted in one place.

``ToolRuntime`` emits one audit event per tool call and ``record_auth_event`` one per auth event (its ``tool`` field
carries the event name); this sink sits next to the log and SQLite sinks in the ``CompositeAuditSink``.
"""

from __future__ import annotations

import logging

from ratatoskr.observability.audit import AuditEvent
from ratatoskr.observability.metrics import AUTH_EVENTS, Metrics

_logger = logging.getLogger("ratatoskr.observability")


class MetricsAuditSink:
    def __init__(self, metrics: Metrics) -> None:
        self._metrics = metrics

    def record(self, event: AuditEvent) -> None:
        try:
            if event.tool in AUTH_EVENTS:
                self._metrics.count_auth_event(event.tool)
                return
            connection = self._metrics.connection_label(event.connection, event.error_class)
            self._metrics.observe_tool(event.tool, connection, event.result, event.duration_ms / 1000)
        except Exception:  # an audit sink must never break a tool call
            _logger.debug("MetricsAuditSink failed", exc_info=True)
```

- [ ] **Step 4: Run** — same command; expected: 6 passed.

- [ ] **Step 5: Commit** — `Count tool calls and auth events from audit events`

### Task 5: BackendProbe for `ratatoskr_backend_up`

**Files:**
- Create: `src/ratatoskr/observability/backend_probe.py`
- Test: `tests/unit/test_backend_probe.py`

- [ ] **Step 1: Write the failing test**

```python
"""BackendProbe: backend_up from a bounded, cached health check of every configured connection."""

import asyncio

from ratatoskr.backends.base import HealthResult
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.observability.backend_probe import BackendProbe
from ratatoskr.observability.metrics import Metrics
from tests.fakes import FakeClock, FakeFactory, make_config

CONFIG = make_config(connections={"prod": {"mode": "read"}, "dev": {"mode": "read"}})


def _setup(**kwargs: float) -> tuple[BackendProbe, Metrics, FakeFactory, FakeClock]:
    factory, clock = FakeFactory(), FakeClock()
    registry = BackendRegistry(CONFIG, factory=factory, clock=clock)
    metrics = Metrics(registry.names())
    return BackendProbe(registry, metrics, clock=clock, **kwargs), metrics, factory, clock


def _up(metrics: Metrics, name: str) -> float | None:
    return metrics.registry.get_sample_value("ratatoskr_backend_up", {"connection": name})


async def test_reports_each_connection() -> None:
    probe, metrics, factory, _ = _setup()
    factory.backends["dev"].health_result = HealthResult(ok=False, latency_ms=None, version=None, error="refused")
    await probe.refresh()
    assert (_up(metrics, "prod"), _up(metrics, "dev")) == (1, 0)


async def test_a_backend_that_cannot_be_opened_is_down() -> None:
    probe, metrics, factory, _ = _setup()
    factory.backends["dev"].fail_open = OSError("connection refused")
    await probe.refresh()
    assert (_up(metrics, "prod"), _up(metrics, "dev")) == (1, 0)


async def test_results_are_cached_for_the_interval() -> None:
    probe, _, factory, clock = _setup(interval=15.0)
    calls: list[str] = []
    original = factory.backends["prod"].health

    async def counting() -> HealthResult:
        calls.append("prod")
        return await original()

    factory.backends["prod"].health = counting  # type: ignore[method-assign]
    await probe.refresh()
    await probe.refresh()
    clock.now += 14.9
    await probe.refresh()
    assert calls == ["prod"]
    clock.now += 0.2
    await probe.refresh()
    assert calls == ["prod", "prod"]


async def test_a_hanging_backend_is_down_after_the_timeout() -> None:
    probe, metrics, factory, _ = _setup(timeout=0.05)

    async def hang() -> HealthResult:
        await asyncio.sleep(10)
        raise AssertionError("not reached")

    factory.backends["dev"].health = hang  # type: ignore[method-assign]
    await probe.refresh()
    assert (_up(metrics, "prod"), _up(metrics, "dev")) == (1, 0)


async def test_an_unexpected_error_is_down_not_raised() -> None:
    probe, metrics, factory, _ = _setup()

    async def broken() -> HealthResult:
        raise RuntimeError("bug")

    factory.backends["prod"].health = broken  # type: ignore[method-assign]
    await probe.refresh()
    assert _up(metrics, "prod") == 0


async def test_concurrent_scrapes_share_one_check() -> None:
    probe, _, factory, _ = _setup()
    calls: list[str] = []
    original = factory.backends["prod"].health

    async def counting() -> HealthResult:
        calls.append("prod")
        await asyncio.sleep(0)
        return await original()

    factory.backends["prod"].health = counting  # type: ignore[method-assign]
    await asyncio.gather(probe.refresh(), probe.refresh(), probe.refresh())
    assert calls == ["prod"]
```

- [ ] **Step 2: Run it** — `.venv/Scripts/python -m pytest tests/unit/test_backend_probe.py -q`; expected: collection
  error.

- [ ] **Step 3: Implement**

```python
"""``ratatoskr_backend_up``: a health check of every configured connection, run when Prometheus scrapes.

Each check opens the connection through the registry if needed (the same lazy open and 10 s back-off as tool calls)
and calls ``Backend.health()``, bounded by :data:`PROBE_TIMEOUT_SECONDS`. Results are cached for
:data:`PROBE_INTERVAL_SECONDS` behind a lock, so concurrent or frequent scrapes cost at most one round of checks per
interval. The checks are not tool calls: they are neither authorized nor audited.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.observability.metrics import Metrics

PROBE_INTERVAL_SECONDS = 15.0
PROBE_TIMEOUT_SECONDS = 5.0

logger = logging.getLogger("ratatoskr.metrics")


class BackendProbe:
    def __init__(
        self,
        registry: BackendRegistry,
        metrics: Metrics,
        *,
        clock: Callable[[], float] = time.monotonic,
        interval: float = PROBE_INTERVAL_SECONDS,
        timeout: float = PROBE_TIMEOUT_SECONDS,
    ) -> None:
        self._registry = registry
        self._metrics = metrics
        self._clock = clock
        self._interval = interval
        self._timeout = timeout
        self._lock = asyncio.Lock()
        self._checked_at: float | None = None

    async def refresh(self) -> None:
        async with self._lock:
            if self._checked_at is not None and self._clock() - self._checked_at < self._interval:
                return
            names = self._registry.names()
            results = await asyncio.gather(*(self._is_up(name) for name in names))
            for name, up in zip(names, results, strict=True):
                self._metrics.set_backend_up(name, up)
            self._checked_at = self._clock()

    async def _is_up(self, name: str) -> bool:
        try:
            async with asyncio.timeout(self._timeout):
                backend = await self._registry.get(name)
                return (await backend.health()).ok
        except TimeoutError:
            return False
        except Exception as exc:  # BackendError or a bug: down either way; the registry logs failed opens
            # Class only, no traceback: an HTTP library error can quote a header value (token, tenant).
            logger.debug("health check of connection %s failed (%s)", name, type(exc).__name__)
            return False
```

- [ ] **Step 4: Run** — expected: 6 passed; `mypy src` clean.

- [ ] **Step 5: Commit** — `Check backend reachability for ratatoskr_backend_up`

### Task 6: The metrics HTTP exchange

**Files:**
- Create: `src/ratatoskr/observability/metrics_http.py`
- Test: `tests/unit/test_metrics_http.py`

- [ ] **Step 1: Write the failing test**

```python
"""metrics_http.answer: the whole HTTP exchange of the metrics listener, without a socket."""

from collections.abc import Awaitable, Callable

import pytest

from ratatoskr.observability.metrics_http import CONTENT_TYPE, answer

BODY = b"# HELP x y\nx 1.0\n"


def _render(calls: list[int]) -> Callable[[], Awaitable[bytes]]:
    async def render() -> bytes:
        calls.append(1)
        return BODY

    return render


def _split(response: bytes) -> tuple[str, dict[str, str], bytes]:
    head, _, body = response.partition(b"\r\n\r\n")
    status, *header_lines = head.decode("ascii").split("\r\n")
    headers = dict(line.split(": ", 1) for line in header_lines)
    return status, headers, body


async def test_get_metrics_returns_the_exposition() -> None:
    calls: list[int] = []
    status, headers, body = _split(await answer(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", _render(calls)))
    assert status == "HTTP/1.1 200 OK"
    assert headers["Content-Type"] == CONTENT_TYPE == "text/plain; version=0.0.4; charset=utf-8"
    assert headers["Content-Length"] == str(len(BODY))
    assert headers["Connection"] == "close"
    assert headers["Cache-Control"] == "no-store"
    assert body == BODY and calls == [1]


async def test_query_string_is_ignored() -> None:
    status, _, body = _split(await answer(b"GET /metrics?name[]=up HTTP/1.1\r\n\r\n", _render([])))
    assert status == "HTTP/1.1 200 OK" and body == BODY


async def test_head_has_no_body() -> None:
    status, headers, body = _split(await answer(b"HEAD /metrics HTTP/1.1\r\n\r\n", _render([])))
    assert status == "HTTP/1.1 200 OK" and headers["Content-Length"] == str(len(BODY)) and body == b""


@pytest.mark.parametrize(
    ("head", "status"),
    [
        (b"GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 404 Not Found"),
        (b"GET /metricsx HTTP/1.1\r\n\r\n", "HTTP/1.1 404 Not Found"),
        (b"POST /metrics HTTP/1.1\r\n\r\n", "HTTP/1.1 405 Method Not Allowed"),
        (b"garbage\r\n\r\n", "HTTP/1.1 400 Bad Request"),
        (b"GET /metrics\r\n\r\n", "HTTP/1.1 400 Bad Request"),
        (b"\xff\xfe /metrics HTTP/1.1\r\n\r\n", "HTTP/1.1 400 Bad Request"),
    ],
)
async def test_anything_else_is_refused_without_rendering(head: bytes, status: str) -> None:
    calls: list[int] = []
    got, headers, _ = _split(await answer(head, _render(calls)))
    assert got == status and calls == []
    assert headers["Connection"] == "close"
    if status.endswith("405 Method Not Allowed"):
        assert headers["Allow"] == "GET, HEAD"


async def test_a_failing_render_is_a_500_without_details(caplog: pytest.LogCaptureFixture) -> None:
    async def broken() -> bytes:
        raise RuntimeError("postgresql://u:hunter2@db.internal/app")

    status, _, body = _split(await answer(b"GET /metrics HTTP/1.1\r\n\r\n", broken))
    assert status == "HTTP/1.1 500 Internal Server Error"
    assert b"hunter2" not in body
    assert "hunter2" not in caplog.text
```

- [ ] **Step 2: Run it** — `.venv/Scripts/python -m pytest tests/unit/test_metrics_http.py -q`; expected: collection
  error.

- [ ] **Step 3: Implement**

```python
"""The metrics listener's HTTP exchange: one request head in, one complete response out, then the connection closes.

Only ``GET`` and ``HEAD`` of ``/metrics`` (any query string) are answered; nothing else renders the metrics. The
classic text format 0.0.4 is announced: every Ratatoskr metric and label name is a legacy Prometheus name, so the
body is the same in both text formats and Prometheus 2 and 3 parse it.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
METRICS_PATH = "/metrics"

logger = logging.getLogger("ratatoskr.metrics")

_REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed", 500: "Internal Server Error"}


def _response(
    status: int,
    body: bytes,
    *,
    content_type: str = "text/plain; charset=utf-8",
    head_only: bool = False,
    extra: tuple[tuple[str, str], ...] = (),
) -> bytes:
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Connection", "close"),
        *extra,
    ]
    lines = [f"HTTP/1.1 {status} {_REASONS[status]}", *(f"{name}: {value}" for name, value in headers)]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + (b"" if head_only else body)


def _request_line(head: bytes) -> tuple[str, str] | None:
    try:
        line = head.split(b"\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = line.split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        return None
    return parts[0], parts[1].split("?", 1)[0]


async def answer(head: bytes, render: Callable[[], Awaitable[bytes]]) -> bytes:
    """``head`` is the request up to and including the blank line; any body is ignored."""
    request = _request_line(head)
    if request is None:
        return _response(400, b"bad request\n")
    method, path = request
    if path != METRICS_PATH:
        return _response(404, b"not found; metrics are at /metrics\n")
    if method not in ("GET", "HEAD"):
        return _response(405, b"method not allowed\n", extra=(("Allow", "GET, HEAD"),))
    try:
        body = await render()
    except Exception as exc:
        logger.warning("rendering metrics failed (%s)", type(exc).__name__)
        return _response(500, b"metrics unavailable\n")
    return _response(200, body, content_type=CONTENT_TYPE, head_only=method == "HEAD")
```

- [ ] **Step 4: Run** — expected: 10 passed.

- [ ] **Step 5: Commit** — `Answer GET /metrics and refuse everything else`

### Task 7: The metrics listener

**Files:**
- Create: `src/ratatoskr/observability/metrics_server.py`
- Test: `tests/unit/test_metrics_server.py` (in-memory streams), `tests/integration/test_metrics_listener.py`
  (real loopback socket; marked `integration` because unit tests open no sockets)

- [ ] **Step 1: Write the failing tests**

```python
"""MetricsServer: the listener glue, with asyncio streams in memory (no socket is opened here)."""

import asyncio
from typing import Any

import pytest

from ratatoskr.observability import metrics_server
from ratatoskr.observability.metrics_server import MAX_REQUEST_HEAD_BYTES, MetricsServer, MetricsStartupError


class FakeWriter:
    def __init__(self) -> None:
        self.data = b""
        self.closed = False

    def write(self, data: bytes) -> None:
        self.data += data

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


async def _render() -> bytes:
    return b"up 1\n"


def _reader(data: bytes, *, eof: bool = True) -> asyncio.StreamReader:
    reader = asyncio.StreamReader(limit=MAX_REQUEST_HEAD_BYTES)
    reader.feed_data(data)
    if eof:
        reader.feed_eof()
    return reader


async def test_answers_one_request_and_closes() -> None:
    writer = FakeWriter()
    server = MetricsServer("127.0.0.1", 9100, _render)
    await server.serve_connection(_reader(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"), writer)  # type: ignore[arg-type]
    assert writer.data.startswith(b"HTTP/1.1 200 OK\r\n") and writer.data.endswith(b"up 1\n")
    assert writer.closed


async def test_an_oversized_head_is_dropped() -> None:
    writer = FakeWriter()
    server = MetricsServer("127.0.0.1", 9100, _render)
    head = b"GET /metrics HTTP/1.1\r\nX: " + b"a" * MAX_REQUEST_HEAD_BYTES + b"\r\n\r\n"
    await server.serve_connection(_reader(head), writer)  # type: ignore[arg-type]
    assert writer.data == b"" and writer.closed


async def test_a_client_that_hangs_up_early_is_dropped() -> None:
    writer = FakeWriter()
    server = MetricsServer("127.0.0.1", 9100, _render)
    await server.serve_connection(_reader(b"GET /metr"), writer)  # type: ignore[arg-type]
    assert writer.data == b"" and writer.closed


async def test_a_slow_client_is_dropped_after_the_timeout() -> None:
    writer = FakeWriter()
    server = MetricsServer("127.0.0.1", 9100, _render, timeout=0.05)
    await server.serve_connection(_reader(b"GET /metrics HTTP/1.1\r\n", eof=False), writer)  # type: ignore[arg-type]
    assert writer.data == b"" and writer.closed


class FakeAsyncioServer:
    sockets: tuple[object, ...] = ()

    def __init__(self) -> None:
        self.closed = False
        self.waited = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        self.waited = True


async def test_running_binds_the_configured_address_and_closes(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeAsyncioServer()
    seen: dict[str, Any] = {}

    async def start_server(callback: Any, host: str, port: int, **kwargs: Any) -> FakeAsyncioServer:
        seen.update(host=host, port=port, **kwargs)
        return fake

    monkeypatch.setattr(metrics_server.asyncio, "start_server", start_server)
    server = MetricsServer("0.0.0.0", 9100, _render)
    async with server.running():
        assert seen == {"host": "0.0.0.0", "port": 9100, "limit": MAX_REQUEST_HEAD_BYTES}
        assert not fake.closed
    assert fake.closed and fake.waited


async def test_a_port_in_use_is_a_startup_error(monkeypatch: pytest.MonkeyPatch) -> None:
    async def start_server(*args: Any, **kwargs: Any) -> None:
        raise OSError(98, "Address already in use")

    monkeypatch.setattr(metrics_server.asyncio, "start_server", start_server)
    with pytest.raises(MetricsStartupError, match=r"127\.0\.0\.1:9100 \(Address already in use\)"):
        async with MetricsServer("127.0.0.1", 9100, _render).running():
            pass
```

```python
"""The metrics listener on a real loopback socket (no container): scrape, refusal, address in use, shutdown."""

import httpx
import pytest

from ratatoskr.observability.metrics_server import MetricsServer, MetricsStartupError

pytestmark = pytest.mark.integration


async def _render() -> bytes:
    return b'ratatoskr_backend_up{connection="prod"} 1.0\n'


async def test_scrape_over_loopback() -> None:
    server = MetricsServer("127.0.0.1", 0, _render)
    async with server.running(), httpx.AsyncClient(base_url=f"http://127.0.0.1:{server.bound_port}") as client:
        metrics = await client.get("/metrics")
        other = await client.get("/mcp")
    assert metrics.status_code == 200
    assert metrics.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
    assert 'connection="prod"' in metrics.text
    assert other.status_code == 404


async def test_second_listener_on_the_same_port_fails_cleanly() -> None:
    first = MetricsServer("127.0.0.1", 0, _render)
    async with first.running():
        assert first.bound_port is not None
        with pytest.raises(MetricsStartupError, match=f"127.0.0.1:{first.bound_port}"):
            async with MetricsServer("127.0.0.1", first.bound_port, _render).running():
                pass


async def test_port_is_free_again_after_exit() -> None:
    server = MetricsServer("127.0.0.1", 0, _render)
    async with server.running():
        port = server.bound_port
    assert port is not None
    async with MetricsServer("127.0.0.1", port, _render).running():
        pass
```

- [ ] **Step 2: Run them** — `.venv/Scripts/python -m pytest tests/unit/test_metrics_server.py -q`; expected: collection
  error.

- [ ] **Step 3: Implement**

```python
"""The metrics listener: a small asyncio TCP server on ``server.metrics_host:metrics_port``, apart from the MCP port.

It reads one request head (at most :data:`MAX_REQUEST_HEAD_BYTES`), writes one response from
:func:`ratatoskr.observability.metrics_http.answer` and closes the connection; the whole exchange is bounded by
``timeout``. There is no authentication: bind it to loopback or an internal network and never publish or proxy it.
On exit the listener stops accepting, cancels exchanges in flight and waits for them.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from ratatoskr.observability.metrics_http import METRICS_PATH, answer

MAX_REQUEST_HEAD_BYTES = 8192
REQUEST_TIMEOUT_SECONDS = 10.0

logger = logging.getLogger("ratatoskr.metrics")


class MetricsStartupError(RuntimeError):
    """The metrics listener could not bind; the message names the address (never a secret)."""


class MetricsServer:
    def __init__(
        self,
        host: str,
        port: int,
        render: Callable[[], Awaitable[bytes]],
        *,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self.host = host
        self.port = port
        self.render = render
        self._timeout = timeout
        self._exchanges: set[asyncio.Task[None]] = set()
        self.bound_port: int | None = None

    @asynccontextmanager
    async def running(self) -> AsyncIterator[None]:
        try:
            server = await asyncio.start_server(
                self.serve_connection, self.host, self.port, limit=MAX_REQUEST_HEAD_BYTES
            )
        except OSError as exc:
            reason = exc.strerror or type(exc).__name__
            raise MetricsStartupError(f"cannot listen for metrics on {self.host}:{self.port} ({reason})") from None
        self.bound_port = server.sockets[0].getsockname()[1] if server.sockets else self.port
        logger.info("serving metrics at http://%s:%d%s", self.host, self.bound_port, METRICS_PATH)
        try:
            yield
        finally:
            server.close()
            for task in list(self._exchanges):
                task.cancel()
            await server.wait_closed()

    async def serve_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._exchanges.add(task)
        try:
            async with asyncio.timeout(self._timeout):
                head = await reader.readuntil(b"\r\n\r\n")
                writer.write(await answer(head, self.render))
                await writer.drain()
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, TimeoutError, ConnectionError):
            pass  # the client hung up, was too slow or sent an oversized head: just close
        finally:
            if task is not None:
                self._exchanges.discard(task)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
```

- [ ] **Step 4: Run**

Run: `.venv/Scripts/python -m pytest tests/unit/test_metrics_server.py -q` (6 passed) and
`.venv/Scripts/python -m pytest -m integration tests/integration/test_metrics_listener.py -q` (3 passed, no Docker
needed).

- [ ] **Step 5: Commit** — `Serve /metrics on a separate asyncio listener`

### Task 8: `build_metrics` composition

**Files:**
- Create: `src/ratatoskr/observability/metrics_service.py`
- Test: `tests/unit/test_metrics_service.py`

- [ ] **Step 1: Write the failing test**

```python
"""build_metrics: nothing without metrics_port; otherwise metrics, sink, probe and listener wired together."""

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.observability.metrics_service import build_metrics
from tests.fakes import FakeFactory, make_config


def test_no_metrics_without_a_port() -> None:
    config = make_config()
    assert build_metrics(config, BackendRegistry(config, factory=FakeFactory())) is None


async def test_render_checks_backends_then_exports_everything() -> None:
    config = make_config(connections={"prod": {"mode": "read"}}, metrics_port=9100)
    service = build_metrics(config, BackendRegistry(config, factory=FakeFactory()))
    assert service is not None
    assert (service.server.host, service.server.port) == ("127.0.0.1", 9100)
    text = (await service.render()).decode("utf-8")
    assert 'ratatoskr_backend_up{connection="prod"} 1.0' in text
    assert 'ratatoskr_auth_events_total{event="login_succeeded"} 0.0' in text
```

- [ ] **Step 2: Run it** — expected: collection error.

- [ ] **Step 3: Implement**

```python
"""Composition of the metrics pieces for one process; used by both the stdio and the HTTP composition roots."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.backend_probe import BackendProbe
from ratatoskr.observability.metrics import Metrics
from ratatoskr.observability.metrics_server import MetricsServer
from ratatoskr.observability.metrics_sink import MetricsAuditSink


@dataclass(frozen=True)
class MetricsService:
    metrics: Metrics
    sink: MetricsAuditSink
    render: Callable[[], Awaitable[bytes]]
    server: MetricsServer


def build_metrics(config: RatatoskrConfig, registry: BackendRegistry) -> MetricsService | None:
    """``None`` when ``server.metrics_port`` is unset. The caller adds ``sink`` to its audit sinks and enters
    ``server.running()`` for as long as the process serves; each scrape refreshes ``backend_up`` first."""
    port = config.server.metrics_port
    if port is None:
        return None
    metrics = Metrics(registry.names())
    probe = BackendProbe(registry, metrics)

    async def render() -> bytes:
        await probe.refresh()
        return metrics.render()

    server = MetricsServer(config.server.metrics_host, port, render)
    return MetricsService(metrics=metrics, sink=MetricsAuditSink(metrics), render=render, server=server)
```

- [ ] **Step 4: Run** — `.venv/Scripts/python -m pytest tests/unit/test_metrics_service.py -q`; expected: 2 passed.

- [ ] **Step 5: Commit** — `Compose metrics, sink, probe and listener per process`

### Task 9: Metrics in the HTTP composition root

**Files:**
- Modify: `src/ratatoskr/transport/app.py`
- Test: `tests/unit/secure_http/e2e/test_http_metrics.py`

- [ ] **Step 1: Write the failing test** (the listener is replaced by a recorder: no socket)

```python
"""HTTP transport with server.metrics_port: the listener runs with the app and sees its audit events."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest

from ratatoskr.observability.metrics_server import MetricsServer
from ratatoskr.transport.app import build_http_app


@pytest.fixture
def listener(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replaces the socket listener; records when it starts and stops."""
    states: list[str] = []

    @asynccontextmanager
    async def running(self: MetricsServer) -> AsyncIterator[None]:
        states.append(f"start {self.host}:{self.port}")
        try:
            yield
        finally:
            states.append("stop")

    monkeypatch.setattr(MetricsServer, "running", running)
    return states


def test_no_metrics_without_a_port(make_config) -> None:
    assert build_http_app(make_config()).metrics is None


async def test_listener_lives_as_long_as_the_app(make_config, run_app, listener) -> None:
    http_app = build_http_app(make_config(server_extra={"metrics_host": "0.0.0.0", "metrics_port": 9100}))
    assert listener == []
    async with run_app(http_app):
        assert listener == ["start 0.0.0.0:9100"]
    assert listener == ["start 0.0.0.0:9100", "stop"]


async def test_auth_events_reach_the_metrics(make_config, run_app, listener) -> None:
    http_app = build_http_app(make_config(server_extra={"metrics_port": 9100}))
    assert http_app.metrics is not None
    async with run_app(http_app) as driver:
        await driver.register()
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        await driver.submit_login(request_id, csrf, "kerem", "wrong-password")
    samples = http_app.metrics.metrics.registry
    assert samples.get_sample_value("ratatoskr_auth_events_total", {"event": "login_failed"}) == 1
    assert "kerem" not in http_app.metrics.metrics.render().decode("utf-8")
```

- [ ] **Step 2: Run it** — `.venv/Scripts/python -m pytest tests/unit/secure_http/e2e/test_http_metrics.py -q`;
  expected: 3 failed (`HttpApp` has no `metrics`).

- [ ] **Step 3: Implement**

```diff
diff --git a/src/ratatoskr/transport/app.py b/src/ratatoskr/transport/app.py
index bfed930..35fb3e4 100644
--- a/src/ratatoskr/transport/app.py
+++ b/src/ratatoskr/transport/app.py
@@ -8,6 +8,8 @@ Request path, outermost first: Host check (every route but ``/mcp`` and the heal
 OAuth and login endpoints, per-IP reservations on ``POST /register`` and ``/authorize``, the client compatibility
 rewrites of ``/revoke`` and ``/register`` bodies, the clean end of ``/mcp`` streams on shutdown, then the SDK's app
 (bearer authentication, OAuth handlers, ``/mcp`` with its DNS-rebinding check) and the custom routes.
+``/metrics`` is not one of them: with ``server.metrics_port`` set it is served by a separate listener
+(``observability.metrics_server``) that runs inside this app's lifespan.
 """
 
 from __future__ import annotations
@@ -33,8 +35,9 @@ from ratatoskr.auth.web import CALLBACK_PATH, LoginRoutes
 from ratatoskr.backends.registry import BackendRegistry
 from ratatoskr.config.loader import ConfigError
 from ratatoskr.config.models import OidcSettings, RatatoskrConfig
-from ratatoskr.observability.audit import CompositeAuditSink, LogAuditSink
+from ratatoskr.observability.audit import AuditSink, CompositeAuditSink, LogAuditSink
 from ratatoskr.observability.health import HealthRoutes
+from ratatoskr.observability.metrics_service import MetricsService, build_metrics
 from ratatoskr.state.audit import SqliteAuditSink
 from ratatoskr.state.maintenance import CleanupTask
 from ratatoskr.state.records import Clock
@@ -66,6 +69,7 @@ class HttpApp:
     store: SqliteStore
     provider: RatatoskrOAuthProvider
     registry: BackendRegistry
+    metrics: MetricsService | None = None
 
 
 class _RunningOidc:
@@ -159,7 +163,11 @@ def build_http_app(
     keyring = Keyring(settings.secret_key)
     store = SqliteStore(server.state_path)
     sqlite_sink = SqliteAuditSink(store)
-    audit = CompositeAuditSink([LogAuditSink(), sqlite_sink])
+    metrics = build_metrics(config, backends)
+    sinks: list[AuditSink] = [LogAuditSink(), sqlite_sink]
+    if metrics is not None:
+        sinks.append(metrics.sink)
+    audit = CompositeAuditSink(sinks)
 
     provider = RatatoskrOAuthProvider(
         config, store=store, keyring=keyring, audit=audit, clock=clock, local=local, oidc=oidc
@@ -234,8 +242,10 @@ def build_http_app(
             await store.open()
             sqlite_sink.start()
             cleanup.start()
+            if metrics is not None:  # stops before the registry closes, so no scrape finds it closing
+                await stack.enter_async_context(metrics.server.running())
             await stack.enter_async_context(session_manager_lifespan(starlette_app))
             yield
 
     app.router.lifespan_context = lifespan
-    return HttpApp(asgi=app, store=store, provider=provider, registry=backends)
+    return HttpApp(asgi=app, store=store, provider=provider, registry=backends, metrics=metrics)
```

- [ ] **Step 4: Run** — expected: 3 passed; then the whole `tests/unit/secure_http` directory passes.

- [ ] **Step 5: Commit** — `Run the metrics listener in the HTTP app lifespan`

### Task 10: stdio composition root with metrics

**Files:**
- Create: `src/ratatoskr/transport/stdio.py`
- Modify: `src/ratatoskr/cli.py`, `tests/unit/test_cli.py`
- Test: `tests/unit/test_stdio_serve.py`

- [ ] **Step 1: Write the failing test**

```python
"""serve_stdio: the stdio composition root (registry, audit sinks, optional metrics listener)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from mcp.server.fastmcp import FastMCP

from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.observability.metrics_server import MetricsServer
from ratatoskr.transport.stdio import serve_stdio
from tests.fakes import make_config


@pytest.fixture
def closed(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    calls: list[int] = []

    async def close_all(self: BackendRegistry) -> None:
        calls.append(1)

    monkeypatch.setattr(BackendRegistry, "close_all", close_all)
    return calls


async def test_runs_the_session_and_closes_the_registry(monkeypatch: pytest.MonkeyPatch, closed: list[int]) -> None:
    ran: list[str] = []

    async def run_stdio_async(self: FastMCP[Any]) -> None:
        ran.append("session")

    monkeypatch.setattr(FastMCP, "run_stdio_async", run_stdio_async)
    await serve_stdio(make_config(stdio_role="team", roles={"team": {"main": "read"}}))
    assert ran == ["session"] and closed == [1]


async def test_metrics_listener_wraps_the_session_and_counts_tool_calls(
    monkeypatch: pytest.MonkeyPatch, closed: list[int]
) -> None:
    events: list[str] = []
    servers: list[MetricsServer] = []

    @asynccontextmanager
    async def running(self: MetricsServer) -> AsyncIterator[None]:
        servers.append(self)
        events.append("listen")
        yield
        events.append("stop")

    async def run_stdio_async(self: FastMCP[Any]) -> None:
        events.append("session")
        await self.call_tool("list_connections", {})
        await self.call_tool("pg_query", {"connection": "ghost", "sql": "SELECT 1"})

    monkeypatch.setattr(MetricsServer, "running", running)
    monkeypatch.setattr(FastMCP, "run_stdio_async", run_stdio_async)
    config = make_config(stdio_role="team", roles={"team": {"main": "read"}}, metrics_port=9100)
    await serve_stdio(config)
    assert events == ["listen", "session", "stop"] and closed == [1]
    text = (await servers[0].render()).decode("utf-8")
    assert 'ratatoskr_tool_calls_total{connection="_all",result="ok",tool="list_connections"} 1.0' in text
    assert 'ratatoskr_tool_calls_total{connection="_unresolved",result="denied",tool="pg_query"} 1.0' in text
    assert "ghost" not in text
```

- [ ] **Step 2: Run it** — `.venv/Scripts/python -m pytest tests/unit/test_stdio_serve.py -q`; expected: collection
  error (`ratatoskr.transport.stdio` missing).

- [ ] **Step 3: Implement**

```python
"""Composition root for ``transport: stdio``: one process serves one MCP session over stdin/stdout.

This function owns the backend registry (it passes it to ``build_app`` and closes it after the session) and, with
``server.metrics_port`` set, runs the metrics listener for as long as the session lasts.
"""

from __future__ import annotations

from contextlib import AsyncExitStack

from ratatoskr.app import build_app
from ratatoskr.auth.resolver import StdioPrincipalResolver
from ratatoskr.backends.registry import BackendRegistry
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import AuditSink, CompositeAuditSink, LogAuditSink
from ratatoskr.observability.metrics_service import build_metrics


async def serve_stdio(config: RatatoskrConfig) -> None:
    """Serve until the client closes stdin. Raises ``MetricsStartupError`` when the metrics port cannot be bound."""
    registry = BackendRegistry(config)
    metrics = build_metrics(config, registry)
    sinks: list[AuditSink] = [LogAuditSink()]
    if metrics is not None:
        sinks.append(metrics.sink)
    app = build_app(
        config,
        resolver=StdioPrincipalResolver(config.server.stdio_role),
        audit=CompositeAuditSink(sinks),
        registry=registry,
    )
    async with AsyncExitStack() as stack:
        stack.push_async_callback(registry.close_all)
        if metrics is not None:
            await stack.enter_async_context(metrics.server.running())
        await app.run_stdio_async()
```

```diff
diff --git a/src/ratatoskr/cli.py b/src/ratatoskr/cli.py
index 52f2cab..4e3d2e3 100644
--- a/src/ratatoskr/cli.py
+++ b/src/ratatoskr/cli.py
@@ -3,6 +3,7 @@
 from __future__ import annotations
 
 import argparse
+import asyncio
 import logging
 import os
 import sys
@@ -10,19 +11,18 @@ from collections.abc import Mapping, Sequence
 from pathlib import Path
 
 from ratatoskr import __version__
-from ratatoskr.app import build_app
 from ratatoskr.auth.password_cli import DESCRIPTION as HASH_PASSWORD_DESCRIPTION
 from ratatoskr.auth.password_cli import run_hash_password
-from ratatoskr.auth.resolver import StdioPrincipalResolver
 from ratatoskr.config.http_models import HttpConnection
 from ratatoskr.config.loader import ConfigError, load_config
 from ratatoskr.config.loki_models import LokiConnection
 from ratatoskr.config.models import PostgresConnection, RatatoskrConfig
 from ratatoskr.config.notices import config_warnings
-from ratatoskr.observability.audit import LogAuditSink
 from ratatoskr.observability.logging import setup_logging
+from ratatoskr.observability.metrics_server import MetricsStartupError
 from ratatoskr.transport.preconditions import check_http_preconditions
 from ratatoskr.transport.serve import HttpServerStartupError, serve_http
+from ratatoskr.transport.stdio import serve_stdio
 
 DEFAULT_CONFIG_PATH = Path("/config/config.yaml")
 CONFIG_ENV_VAR = "RATATOSKR_CONFIG"
@@ -134,11 +134,13 @@ def _serve(args: argparse.Namespace) -> int:
     for warning in config_warnings(config):
         logger.warning(warning)
     try:
-        app = build_app(config, resolver=StdioPrincipalResolver(config.server.stdio_role), audit=LogAuditSink())
         logger.info("starting ratatoskr %s over stdio with %d connection(s)", __version__, len(config.connections))
-        app.run(transport="stdio")
+        asyncio.run(serve_stdio(config))
     except KeyboardInterrupt:
         return EXIT_INTERRUPTED
+    except MetricsStartupError as exc:
+        logger.error("%s", exc)
+        return EXIT_UNEXPECTED_ERROR
     except Exception:
         # Through the redacting JSON handler: a raw traceback on stderr could carry a DSN or password.
         logger.exception("fatal error")
```

- [ ] **Step 4: Adapt the cli tests** (they patched `FastMCP.run` and `cli.build_app`; add the busy-port case)

```diff
diff --git a/tests/unit/test_cli.py b/tests/unit/test_cli.py
index f48e24d..6c3420f 100644
--- a/tests/unit/test_cli.py
+++ b/tests/unit/test_cli.py
@@ -13,6 +13,7 @@ from mcp.server.fastmcp import FastMCP
 import ratatoskr
 from ratatoskr import cli
 from ratatoskr.cli import DEFAULT_CONFIG_PATH, main, resolve_config_path
+from ratatoskr.transport import stdio
 
 STDIO_CONFIG = """
 server:
@@ -145,10 +146,10 @@ def test_serve_runs_stdio(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> No
     monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
     calls: list[str] = []
 
-    def fake_run(self: FastMCP[Any], transport: str = "stdio", mount_path: str | None = None) -> None:
-        calls.append(transport)
+    async def fake_run(self: FastMCP[Any]) -> None:
+        calls.append("stdio")
 
-    monkeypatch.setattr(FastMCP, "run", fake_run)
+    monkeypatch.setattr(FastMCP, "run_stdio_async", fake_run)
     assert main(["serve", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 0
     assert calls == ["stdio"]
 
@@ -164,7 +165,7 @@ def test_serve_unexpected_error_is_logged_redacted(
     def failing_build_app(*args: Any, **kwargs: Any) -> FastMCP[Any]:
         raise RuntimeError(f"cannot start with {LEAKY_DSN}")
 
-    monkeypatch.setattr(cli, "build_app", failing_build_app)
+    monkeypatch.setattr(stdio, "build_app", failing_build_app)
     assert main(["serve", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 1
     captured = capsys.readouterr()
     assert "leak-pass-4417" not in captured.out + captured.err
@@ -174,13 +175,31 @@ def test_serve_unexpected_error_is_logged_redacted(
 def test_serve_keyboard_interrupt_exits_130(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
     monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
 
-    def interrupted_run(self: FastMCP[Any], transport: str = "stdio", mount_path: str | None = None) -> None:
+    async def interrupted_run(self: FastMCP[Any]) -> None:
         raise KeyboardInterrupt
 
-    monkeypatch.setattr(FastMCP, "run", interrupted_run)
+    monkeypatch.setattr(FastMCP, "run_stdio_async", interrupted_run)
     assert main(["serve", "--config", str(_write(tmp_path, STDIO_CONFIG))]) == 130
 
 
+def test_serve_stdio_metrics_port_in_use_exits_1(
+    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
+) -> None:
+    from ratatoskr.observability.metrics_server import MetricsServer, MetricsStartupError
+
+    monkeypatch.setenv("MAIN_DSN", "postgresql://db/app")
+
+    def busy(self: MetricsServer) -> Any:
+        raise MetricsStartupError("cannot listen for metrics on 127.0.0.1:9100 (Address already in use)")
+
+    monkeypatch.setattr(MetricsServer, "running", busy)
+    text = STDIO_CONFIG.replace("  stdio_role: admins", "  stdio_role: admins\n  metrics_port: 9100")
+    assert main(["serve", "--config", str(_write(tmp_path, text))]) == 1
+    err = capsys.readouterr().err
+    assert "cannot listen for metrics on 127.0.0.1:9100" in err
+    assert "fatal error" not in err
+
+
 def test_check_config_unexpected_error_prints_only_the_class(
     tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
 ) -> None:
```

- [ ] **Step 5: Run**

Run: `.venv/Scripts/python -m pytest tests/unit/test_cli.py tests/unit/test_stdio_serve.py -q` (16 passed, the real
stdio subprocess test included), then the full unit suite `.venv/Scripts/python -m pytest -q`, `ruff check`,
`ruff format --check`, `mypy src`.

- [ ] **Step 6: Commit** — `Serve stdio from its own composition root with the metrics listener`

### Task 11: Dockerfile: Dependabot-friendly base, Debian security fixes, labels

**Files:**
- Modify: `Dockerfile`
- Test: `tests/unit/test_dockerfile.py`

- [ ] **Step 1: Write the failing test**

```python
"""The Dockerfile: one digest-pinned base image for both stages, OCI labels, the uid and port compose relies on."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_both_stages_use_the_same_digest_pinned_base() -> None:
    bases = re.findall(r"^FROM (\S+)", DOCKERFILE, flags=re.MULTILINE)
    assert len(bases) == 2 and bases[0] == bases[1], "Dependabot updates each FROM line; keep them identical"
    assert re.fullmatch(r"python:3\.12-slim@sha256:[0-9a-f]{64}", bases[0])


def test_labels_and_runtime_contract() -> None:
    assert 'org.opencontainers.image.description="Secure multi-connection MCP server for PostgreSQL, Prometheus' in (
        DOCKERFILE
    )
    assert "USER 10001:10001" in DOCKERFILE
    assert "EXPOSE 8000" in DOCKERFILE
    assert 'ENTRYPOINT ["ratatoskr"]' in DOCKERFILE


def test_runtime_stage_takes_debian_security_fixes() -> None:
    runtime = DOCKERFILE.split("AS builder", 1)[1].split("\nFROM ", 1)[1]
    assert "apt-get upgrade -y" in runtime and "rm -rf /var/lib/apt/lists/*" in runtime
```

- [ ] **Step 2: Run it** — `.venv/Scripts/python -m pytest tests/unit/test_dockerfile.py -q`; expected: 3 failed.

- [ ] **Step 3: Implement**

```diff
diff --git a/Dockerfile b/Dockerfile
index 7c4fa65..ad39666 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,11 +1,11 @@
 # syntax=docker/dockerfile:1
 
-# Base image: python:3.12-slim, pinned by digest so that rebuilds start from the same layers. To move to a newer one:
+# Base image: python:3.12-slim, pinned by digest so that rebuilds start from the same layers. Both stages name the
+# same digest: Dependabot updates each FROM line, and tests/unit/test_dockerfile.py keeps them equal. By hand:
 #   docker pull python:3.12-slim && docker inspect --format '{{index .RepoDigests 0}}' python:3.12-slim
-ARG PYTHON_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
 
 # ── build: install the package into a self-contained virtualenv ─────────────
-FROM ${PYTHON_IMAGE} AS builder
+FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS builder
 
 ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
     PIP_NO_CACHE_DIR=1
@@ -21,11 +21,18 @@ RUN python -m pip --python /opt/ratatoskr/bin/python install -c constraints.txt
  && /opt/ratatoskr/bin/python -m compileall -q /opt/ratatoskr
 
 # ── runtime: non-root, read-only friendly; only /data is written ────────────
-FROM ${PYTHON_IMAGE}
+FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
+
+# Debian security fixes released after the base image was built: the digest pins the base layers, not their fixes,
+# and the image scan (Trivy in CI) fails on a fixed HIGH or CRITICAL vulnerability.
+RUN apt-get update \
+ && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \
+ && rm -rf /var/lib/apt/lists/*
 
 ARG VERSION=dev
+# CI (docker/metadata-action) sets source, version and revision from the repository and tag at build time.
 LABEL org.opencontainers.image.title="ratatoskr" \
-      org.opencontainers.image.description="Secure multi-connection MCP server for PostgreSQL" \
+      org.opencontainers.image.description="Secure multi-connection MCP server for PostgreSQL, Prometheus and Loki" \
       org.opencontainers.image.source="https://github.com/keremkocatus/claude-postgresql" \
       org.opencontainers.image.version="${VERSION}" \
       org.opencontainers.image.licenses="MIT"
@@ -50,6 +57,7 @@ USER 10001:10001
 WORKDIR /data
 VOLUME ["/data"]
 # Keep server.port at 8000 and server.host at 0.0.0.0 in containers; the health check below relies on it.
+# server.metrics_port is deliberately not exposed: it has no authentication; reach it only on an internal network.
 EXPOSE 8000
 
 # /healthz is exempt from the Host check, so the loopback address is fine.
```

- [ ] **Step 4: Run and build**

Run: the test (3 passed), then `docker build -t ratatoskr:dev .`,
`docker run --rm --read-only ratatoskr:dev --version` (`ratatoskr 1.0.0.dev0`),
`docker run --rm --entrypoint id ratatoskr:dev -u` (`10001`) and the scan:
`MSYS_NO_PATHCONV=1 docker run --rm -v //var/run/docker.sock:/var/run/docker.sock aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress ratatoskr:dev`
Expected: exit code 0 (without the `apt-get upgrade` line it reported `zlib1g CVE-2026-85091 HIGH fixed` on
2026-11-22).

- [ ] **Step 5: Commit** — `Pin the base image in both FROM lines and take Debian security fixes`

### Task 12: `compose.yml` with Caddy; delete the 0.1 compose file

**Files:**
- Create: `compose.yml`, `deploy/Caddyfile`, `deploy/config.example.yaml`, `.env.example`
- Modify: `.gitignore`
- Delete: `docker-compose.yml`
- Test: `tests/unit/test_deploy_files.py`

- [ ] **Step 1: Write the failing test**

```python
"""compose.yml, deploy/Caddyfile and deploy/config.example.yaml agree with each other and with the image."""

import ipaddress
import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from ratatoskr.config.loader import load_config

ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_RE = re.compile(r"\$\{(?P<name>[A-Z_]+):-(?P<default>[^}]+)\}")


def _compose() -> dict[str, Any]:
    data = yaml.safe_load((ROOT / "compose.yml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def _default(value: str) -> str:
    match = _DEFAULT_RE.fullmatch(value)
    assert match is not None, value
    return match.group("default")


def test_ratatoskr_service_is_locked_down() -> None:
    service = _compose()["services"]["ratatoskr"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert "ports" not in service, "only Caddy is published; 8000 and the metrics port stay on the compose network"
    assert "ratatoskr-data:/data" in service["volumes"]
    assert "./config.yaml:/config/config.yaml:ro" in service["volumes"]
    assert service["stop_grace_period"] in ("15s", "20s", "30s")  # the audit flush needs >= 10 s


def test_caddy_address_is_the_trusted_proxy() -> None:
    compose = _compose()
    caddy_ip = _default(compose["services"]["caddy"]["networks"]["edge"]["ipv4_address"])
    subnet = _default(compose["networks"]["edge"]["ipam"]["config"][0]["subnet"])
    assert ipaddress.ip_address(caddy_ip) in ipaddress.ip_network(subnet)
    assert _default(compose["services"]["ratatoskr"]["environment"]["RATATOSKR_PROXY_IP"]) == caddy_ip


def test_caddyfile_proxies_to_the_service_and_hides_internal_paths() -> None:
    caddyfile = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
    assert "{$RATATOSKR_DOMAIN}" in caddyfile
    assert "reverse_proxy ratatoskr:8000" in caddyfile
    assert re.search(r"path /healthz /readyz /metrics\b", caddyfile)
    assert "Strict-Transport-Security" in caddyfile


def test_compose_config_template_is_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    import ratatoskr.transport.preconditions as preconditions
    from ratatoskr.auth.identity.local import hash_password
    from ratatoskr.transport.preconditions import check_http_preconditions

    monkeypatch.setattr(preconditions, "_check_state_path", lambda path: None)  # /data is the container's
    env = {
        "RATATOSKR_DOMAIN": "mcp.example.com",
        "RATATOSKR_PROXY_IP": _default(_compose()["services"]["ratatoskr"]["environment"]["RATATOSKR_PROXY_IP"]),
        "SERVER_SECRET_KEY": "example-secret-key-0123456789-abcdefghijklmnop",
        "ALICE_PASSWORD_HASH": hash_password("example-password"),
        "APP_DB_DSN": "postgresql://ratatoskr_read:pw@db.internal:5432/app",
    }
    config = load_config(ROOT / "deploy" / "config.example.yaml", env=env)
    assert (config.server.host, config.server.port) == ("0.0.0.0", 8000)  # the image's health check
    assert config.server.trusted_proxies == [env["RATATOSKR_PROXY_IP"] + "/32"]
    assert check_http_preconditions(config, insecure_dev=False).public_url == "https://mcp.example.com"


def test_env_example_single_quotes_the_password_hash() -> None:
    lines = (ROOT / ".env.example").read_text(encoding="utf-8").splitlines()
    hashes = [line for line in lines if line.startswith("ALICE_PASSWORD_HASH=")]
    assert hashes and all(line.split("=", 1)[1].startswith("'") for line in hashes), (
        "argon2 hashes contain '$': unquoted, compose would try to interpolate them"
    )
```

- [ ] **Step 2: Run it** — expected: 5 failed (files missing).

- [ ] **Step 3: Create the files**

`compose.yml`:

```yaml
# Ratatoskr behind Caddy, which gets and renews the TLS certificate from Let's Encrypt.
#
# You provide, next to this file:
#   .env         RATATOSKR_DOMAIN (a DNS name that points at this host) and the secrets config.yaml refers to;
#                start from .env.example
#   config.yaml  start from deploy/config.example.yaml
# Ports 80 and 443 must be reachable from the internet for the certificate. Then:
#   docker compose build            # or set RATATOSKR_IMAGE to a released image and `docker compose pull`
#   docker compose run --rm ratatoskr check-config
#   docker compose up -d
# The MCP endpoint is https://<RATATOSKR_DOMAIN>/mcp. See README.md and docs/configuration.md.
name: ratatoskr

services:
  ratatoskr:
    image: ${RATATOSKR_IMAGE:-ratatoskr:local}
    build: .
    restart: unless-stopped
    env_file:
      - path: .env
        required: true
    environment:
      # Always set, so config.yaml can use them even when .env leaves them out.
      RATATOSKR_DOMAIN: ${RATATOSKR_DOMAIN:?set RATATOSKR_DOMAIN in .env}
      RATATOSKR_PROXY_IP: ${RATATOSKR_PROXY_IP:-10.203.53.10}
    volumes:
      - ./config.yaml:/config/config.yaml:ro
      # A new named volume starts as a copy of the image's /data, which is owned by uid 10001.
      - ratatoskr-data:/data
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    # SIGTERM lets in-flight requests finish and flushes queued audit events; keep this at 10 s or more.
    stop_grace_period: 15s
    networks:
      - edge
    # No ports: Caddy reaches 8000 on the compose network; a metrics port (server.metrics_port) stays internal too.

  caddy:
    image: caddy:2.11.9-alpine@sha256:003a97808e781aa9f7e75cc2f43d34d461099031faf5e20faefb9f61126836f0
    restart: unless-stopped
    environment:
      RATATOSKR_DOMAIN: ${RATATOSKR_DOMAIN:?set RATATOSKR_DOMAIN in .env}
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"
    volumes:
      - ./deploy/Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy-data:/data
      - caddy-config:/config
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    security_opt: ["no-new-privileges:true"]
    depends_on:
      ratatoskr:
        condition: service_healthy
    networks:
      edge:
        # Fixed, so that server.trusted_proxies can name it (deploy/config.example.yaml uses RATATOSKR_PROXY_IP).
        ipv4_address: ${RATATOSKR_PROXY_IP:-10.203.53.10}

networks:
  edge:
    ipam:
      config:
        # Outside Docker's default address pools; change RATATOSKR_SUBNET and RATATOSKR_PROXY_IP together if it
        # collides with a network this host routes to.
        - subnet: ${RATATOSKR_SUBNET:-10.203.53.0/24}

volumes:
  ratatoskr-data:
  caddy-data:
  caddy-config:
```

`deploy/Caddyfile`:

```caddyfile
# Caddy in front of Ratatoskr (compose.yml). RATATOSKR_DOMAIN comes from .env; Caddy obtains its certificate from
# Let's Encrypt on first start (ports 80 and 443 must be reachable) and keeps it in the caddy-data volume.
{$RATATOSKR_DOMAIN} {
	# HSTS is set here, at the TLS endpoint; Ratatoskr does not send it.
	header Strict-Transport-Security "max-age=31536000; includeSubDomains"

	# Probes and metrics are for the compose network only.
	@internal path /healthz /readyz /metrics
	respond @internal 404

	# Caddy replaces any X-Forwarded-For from the client with the client's address; Ratatoskr trusts it from
	# Caddy only (server.trusted_proxies). Event streams on /mcp are flushed as they arrive.
	reverse_proxy ratatoskr:8000
}
```

`deploy/config.example.yaml`:

```yaml
# Ratatoskr config for compose.yml (Ratatoskr behind Caddy). Copy it to ./config.yaml next to compose.yml and edit
# users, roles and connections. Every ${NAME} is read from the container environment: compose passes .env (see
# .env.example) plus RATATOSKR_DOMAIN and RATATOSKR_PROXY_IP. Full reference: docs/configuration.md.
server:
  transport: streamable-http
  public_url: https://${RATATOSKR_DOMAIN}
  host: 0.0.0.0                       # inside the container; nothing publishes this port
  port: 8000                          # the image's health check uses 8000
  state_path: /data/state.db          # the ratatoskr-data volume
  secret_key: ${SERVER_SECRET_KEY}
  trusted_proxies: ["${RATATOSKR_PROXY_IP}"]   # Caddy's fixed address on the compose network
  # metrics_host: 0.0.0.0             # metrics for a Prometheus on the compose network (not published, hidden by Caddy)
  # metrics_port: 9100

auth:
  mode: local                         # or oidc: see docs/authentik.md
  local:
    users:
      - username: alice
        password_hash: ${ALICE_PASSWORD_HASH}   # docker compose run --rm ratatoskr hash-password
        groups: [admins]

roles:
  admins: { "*": read }

connections:
  app-db:
    kind: postgres
    description: "Application database"
    dsn: ${APP_DB_DSN}                # a restricted role: docs/postgres-roles.md
```

`.env.example`:

```dotenv
# Copy to .env next to compose.yml and fill in. .env holds secrets: never commit it (it is in .gitignore).
# Values in single quotes are taken literally; use them for anything with a '$' (password hashes).

# DNS name of this host; Caddy gets its certificate for it. The MCP endpoint is https://<this>/mcp.
RATATOSKR_DOMAIN=mcp.example.com

# Secrets that config.yaml refers to as ${NAME}.
# python -c "import secrets; print(secrets.token_urlsafe(48))"
SERVER_SECRET_KEY=
# docker compose run --rm ratatoskr hash-password   (paste the whole $argon2id$... value inside the quotes)
ALICE_PASSWORD_HASH=''
APP_DB_DSN=postgresql://ratatoskr_read:change-me@db.internal:5432/app

# Optional.
# RATATOSKR_IMAGE=ghcr.io/keremkocatus/ratatoskr:1.0.0   # a released image instead of a local build
# RATATOSKR_SUBNET=10.203.53.0/24                         # change both if this collides with a routed network
# RATATOSKR_PROXY_IP=10.203.53.10
```

`.gitignore` (append):

```diff
diff --git a/.gitignore b/.gitignore
index a517183..bfde06f 100644
--- a/.gitignore
+++ b/.gitignore
@@ -181,4 +181,7 @@ cython_debug/
 #  exclude from AI features like autocomplete and code analysis. Recommended for sensitive data
 #  refer to https://docs.cursor.com/context/ignore-files
 .cursorignore
-.cursorindexingignore
\ No newline at end of file
+.cursorindexingignore
+# Local deployment files (compose.yml): your config and the dev stack state
+/config.yaml
+/.dev/
```

Then `git rm docker-compose.yml`.

- [ ] **Step 4: Run the test** — expected: 5 passed.

- [ ] **Step 5: Validate and try the stack locally** (no certificate is requested for `localhost`; Caddy uses its
  internal CA)

```bash
printf 'local-test-password\n' | .venv/Scripts/ratatoskr hash-password      # copy the hash
# .env: RATATOSKR_DOMAIN=localhost, SERVER_SECRET_KEY=<token_urlsafe(48)>, ALICE_PASSWORD_HASH='<hash>',
#       APP_DB_DSN=postgresql://ratatoskr_read:change-me@db.internal:5432/app
cp deploy/config.example.yaml config.yaml
docker compose -f compose.yml config --quiet
docker compose -f compose.yml build
docker compose -f compose.yml run --rm ratatoskr check-config     # "Config OK", "metrics: off"
docker compose -f compose.yml up -d
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost/healthz           # 404 (hidden by Caddy)
curl -sk -o /dev/null -w "%{http_code}\n" https://localhost/metrics           # 404
curl -skI https://localhost/.well-known/oauth-authorization-server | grep -i strict   # HSTS header
curl -sk -o /dev/null -w "%{http_code}\n" -X POST https://localhost/mcp       # 401
docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' ratatoskr-caddy-1   # 10.203.53.10
docker compose -f compose.yml exec ratatoskr sh -c 'id -u; touch /x; ls -ln /data'   # 10001, read-only, owned by 10001
docker compose -f compose.yml down -v
rm .env config.yaml
```

- [ ] **Step 6: Commit** — `Add compose.yml with Caddy and a config template; remove the 0.1 docker-compose.yml`

### Task 13: Dev stack (`compose.dev.yml`)

**Files:**
- Create: `compose.dev.yml`, `dev/postgres/initdb/01-shop.sql`, `dev/postgres/initdb/02-ratatoskr-roles.sql`,
  `dev/prometheus/prometheus.yml`, `dev/prometheus/rules.yml`, `dev/loki/loki.yaml`, `dev/loggen/loggen.sh`,
  `dev/ratatoskr/stdio.yaml`, `dev/ratatoskr/local-http.yaml`
- Modify: `.gitattributes`
- Test: `tests/unit/test_dev_stack_files.py`, `tests/integration/test_dev_seed.py`

- [ ] **Step 1: Write the failing tests**

```python
"""compose.dev.yml and the dev configs under dev/ agree: loopback-only ports, matching hosts and ports."""

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest
import yaml

from ratatoskr.config.loader import load_config
from ratatoskr.config.models import PostgresConnection

ROOT = Path(__file__).resolve().parents[2]


def _compose() -> dict[str, Any]:
    data = yaml.safe_load((ROOT / "compose.dev.yml").read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_published_ports_bind_loopback_only() -> None:
    for name, service in _compose()["services"].items():
        for port in service.get("ports", []):
            assert str(port).startswith("127.0.0.1:"), f"{name} publishes {port} beyond this machine"


def _hosts(path: Path) -> set[str]:
    config = load_config(path, insecure_dev=True)
    hosts: set[str] = set()
    for connection in config.connections.values():
        if isinstance(connection, PostgresConnection):
            hosts.add(urlsplit(connection.dsn.get_secret_value()).netloc.rsplit("@", 1)[1])
            assert connection.write_dsn is not None
        else:
            hosts.add(f"{connection.url.host}:{connection.url.port}")
    return hosts


def test_container_config_uses_service_names() -> None:
    services = _compose()["services"]
    hosts = _hosts(ROOT / "dev" / "ratatoskr" / "stdio.yaml")
    assert {host.split(":")[0] for host in hosts} <= set(services)


def test_host_config_uses_the_published_ports() -> None:
    published = {
        "127.0.0.1:" + str(port).split(":")[1]
        for service in _compose()["services"].values()
        for port in service.get("ports", [])
    }
    assert _hosts(ROOT / "dev" / "ratatoskr" / "local-http.yaml") == published


def test_host_config_passes_the_insecure_dev_preconditions(monkeypatch: pytest.MonkeyPatch) -> None:
    import ratatoskr.transport.preconditions as preconditions

    monkeypatch.setattr(preconditions, "_check_state_path", lambda path: None)
    config = load_config(ROOT / "dev" / "ratatoskr" / "local-http.yaml", insecure_dev=True)
    settings = preconditions.check_http_preconditions(config, insecure_dev=True)
    assert settings.public_url == "http://127.0.0.1:8000"


def test_prometheus_scrapes_the_dev_metrics_port() -> None:
    config = load_config(ROOT / "dev" / "ratatoskr" / "stdio.yaml")
    prometheus = yaml.safe_load((ROOT / "dev" / "prometheus" / "prometheus.yml").read_text(encoding="utf-8"))
    targets = {t for job in prometheus["scrape_configs"] for group in job["static_configs"] for t in group["targets"]}
    assert f"ratatoskr:{config.server.metrics_port}" in targets
    assert config.server.metrics_host == "0.0.0.0"


def test_log_generator_has_unix_line_endings() -> None:
    assert b"\r\n" not in (ROOT / "dev" / "loggen" / "loggen.sh").read_bytes()
```

```python
"""dev/postgres/initdb (the dev stack's sample database) loads on a fresh PostgreSQL and its roles behave."""

import asyncio
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from testcontainers.community.postgres import PostgresContainer

pytestmark = pytest.mark.integration

INITDB = Path(__file__).resolve().parents[2] / "dev" / "postgres" / "initdb"


def _dsn(base: str, *, user: str | None = None, password: str | None = None) -> str:
    parts = urlsplit(base)
    netloc = parts.netloc if user is None else f"{user}:{password}@{parts.netloc.rsplit('@', 1)[1]}"
    return urlunsplit(parts._replace(netloc=netloc))


async def _load(dsn: str) -> None:
    connection = await asyncpg.connect(dsn)
    try:
        for script in sorted(INITDB.glob("*.sql")):  # the order the postgres image runs them in
            await connection.execute(script.read_text(encoding="utf-8"))  # trusted fixture SQL, not user input
    finally:
        await connection.close()


@pytest.fixture(scope="module")
def shop() -> Iterator[str]:
    """Like compose.dev.yml: database "shop", the init scripts run as the superuser."""
    container = PostgresContainer("postgres:17-alpine", dbname="shop", driver=None)
    container.ports["5432"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        port = container.get_exposed_port(5432)
        dsn = f"postgresql://{container.username}:{container.password}@127.0.0.1:{port}/shop"
        asyncio.run(_load(dsn))
        yield dsn


async def test_sample_data_is_there(shop: str) -> None:
    connection = await asyncpg.connect(_dsn(shop, user="ratatoskr_read", password="dev-read"))
    try:
        counts = await connection.fetchrow(
            "SELECT (SELECT count(*) FROM customers), (SELECT count(*) FROM products), (SELECT count(*) FROM orders),"
            " (SELECT count(*) > 0 FROM order_items)"
        )
        assert tuple(counts) == (200, 30, 1000, True)
        with pytest.raises(asyncpg.PostgresError):
            await connection.execute("DELETE FROM orders")
    finally:
        await connection.close()


async def test_write_role_can_change_rows_only(shop: str) -> None:
    connection = await asyncpg.connect(_dsn(shop, user="ratatoskr_write", password="dev-write"))
    try:
        await connection.execute("INSERT INTO customers (name, email, country) VALUES ('Dev', 'dev@example.com', 'DE')")
        with pytest.raises(asyncpg.PostgresError) as info:
            await connection.execute("DROP TABLE order_items")
        assert info.value.sqlstate == "42501"
    finally:
        await connection.close()
```

- [ ] **Step 2: Run them** — `.venv/Scripts/python -m pytest tests/unit/test_dev_stack_files.py -q`; expected: failures
  (files missing).

- [ ] **Step 3: Create the files**

`compose.dev.yml`:

```yaml
# Local playground: PostgreSQL with a sample shop database, Prometheus, Loki with generated logs, and Ratatoskr over
# stdio. Everything runs on this machine; published ports bind to 127.0.0.1 only. Passwords here are dev-only.
#
#   docker compose -f compose.dev.yml up -d                     # postgres, prometheus, loki, loggen
#   docker compose -f compose.dev.yml run --rm -T --use-aliases ratatoskr   # an MCP server on stdin/stdout
#   docker compose -f compose.dev.yml down -v                   # stop and delete the data
#
# Host ports: PostgreSQL 55432, Prometheus 59090, Loki 53100 (dev/ratatoskr/local-http.yaml uses them).
name: ratatoskr-dev

services:
  postgres:
    image: postgres:17-alpine@sha256:526f86d93c6ea08fd3f1fe5605650cacc781b2c6013169a0ad8f42c7d3d84f32
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: dev-postgres
      POSTGRES_DB: shop
    volumes:
      - ./dev/postgres/initdb:/docker-entrypoint-initdb.d:ro
    ports:
      - "127.0.0.1:55432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d shop"]
      interval: 2s
      timeout: 5s
      retries: 30

  prometheus:
    image: prom/prometheus:v3.16.0@sha256:e04987641b57704f408e31f6373ba4138ecf27cb4a165d24aabb6c38fddd0f06
    volumes:
      - ./dev/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./dev/prometheus/rules.yml:/etc/prometheus/rules.yml:ro
    ports:
      - "127.0.0.1:59090:9090"

  loki:
    image: grafana/loki:3.7.9@sha256:0db216b630ae1f348a1584c67f3cead8b4c1fc839169a39501db664744158e28
    command: ["-config.file=/etc/loki/dev.yaml"]
    volumes:
      - ./dev/loki/loki.yaml:/etc/loki/dev.yaml:ro
    ports:
      - "127.0.0.1:53100:3100"

  loggen:
    image: alpine:3.22@sha256:d406446bc05b82480756ce8f1287964d28768c23955fa9480d2a74a2eae7a654
    command: ["/bin/sh", "/loggen.sh"]
    volumes:
      - ./dev/loggen/loggen.sh:/loggen.sh:ro
    depends_on: [loki]

  ratatoskr:
    # Not started by `up` (profile): run it on demand; it serves MCP over stdin/stdout until stdin closes.
    profiles: [stdio]
    image: ratatoskr:dev
    build: .
    command: ["serve", "--config", "/config/dev.yaml"]
    stdin_open: true
    volumes:
      - ./dev/ratatoskr/stdio.yaml:/config/dev.yaml:ro
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    depends_on:
      postgres:
        condition: service_healthy
```

`dev/postgres/initdb/01-shop.sql`:

```sql
-- Sample data for the dev stack (compose.dev.yml). The postgres image runs this once, as the superuser, in the
-- database "shop" when its volume is empty. The tables belong to shop_owner, as an application's tables would.
CREATE ROLE shop_owner NOLOGIN;
GRANT CREATE ON SCHEMA public TO shop_owner;
SET ROLE shop_owner;

CREATE TABLE customers (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  name text NOT NULL,
  email text NOT NULL UNIQUE,
  country text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE products (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  sku text NOT NULL UNIQUE,
  name text NOT NULL,
  price numeric(10, 2) NOT NULL CHECK (price >= 0),
  stock int NOT NULL DEFAULT 0
);
CREATE TABLE orders (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  customer_id bigint NOT NULL REFERENCES customers (id),
  status text NOT NULL CHECK (status IN ('new', 'paid', 'shipped', 'cancelled')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE order_items (
  order_id bigint NOT NULL REFERENCES orders (id) ON DELETE CASCADE,
  product_id bigint NOT NULL REFERENCES products (id),
  quantity int NOT NULL CHECK (quantity > 0),
  unit_price numeric(10, 2) NOT NULL,
  PRIMARY KEY (order_id, product_id)
);
CREATE INDEX orders_customer_idx ON orders (customer_id);
CREATE INDEX orders_created_idx ON orders (created_at);
COMMENT ON TABLE orders IS 'Customer orders; status goes new -> paid -> shipped (or cancelled)';

INSERT INTO customers (name, email, country, created_at)
SELECT 'Customer ' || n, 'customer' || n || '@example.com', (ARRAY['DE', 'TR', 'NL', 'US', 'FR'])[1 + n % 5],
       now() - (n % 365) * interval '1 day'
FROM generate_series(1, 200) AS n;

INSERT INTO products (sku, name, price, stock)
SELECT 'SKU-' || lpad(n::text, 4, '0'), 'Product ' || n, (5 + (n * 37) % 200) + 0.99, (n * 13) % 100
FROM generate_series(1, 30) AS n;

INSERT INTO orders (customer_id, status, created_at)
SELECT 1 + (n * 7919) % 200, (ARRAY['new', 'paid', 'shipped', 'cancelled'])[1 + n % 4],
       now() - (n % 720) * interval '1 hour'
FROM generate_series(1, 1000) AS n;

INSERT INTO order_items (order_id, product_id, quantity, unit_price)
SELECT o.id, p.id, 1 + (o.id + k) % 5, p.price
FROM orders AS o
CROSS JOIN generate_series(1, 1 + (o.id % 3)::int) AS k
JOIN products AS p ON p.id = 1 + (o.id * k * 31) % 30
ON CONFLICT DO NOTHING;

RESET ROLE;
ANALYZE;
```

`dev/postgres/initdb/02-ratatoskr-roles.sql`:

```sql
-- The read and write roles of docs/postgres-roles.md, for the dev connection "shop" (dsn and write_dsn).
-- Dev-only passwords: compose.dev.yml publishes this database on 127.0.0.1 only.
CREATE ROLE ratatoskr_read LOGIN PASSWORD 'dev-read'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE shop TO ratatoskr_read;
GRANT USAGE ON SCHEMA public TO ratatoskr_read;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ratatoskr_read;
ALTER DEFAULT PRIVILEGES FOR ROLE shop_owner IN SCHEMA public GRANT SELECT ON TABLES TO ratatoskr_read;
GRANT pg_read_all_stats TO ratatoskr_read;

CREATE ROLE ratatoskr_write LOGIN PASSWORD 'dev-write'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE shop TO ratatoskr_write;
GRANT USAGE ON SCHEMA public TO ratatoskr_write;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ratatoskr_write;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ratatoskr_write;
ALTER DEFAULT PRIVILEGES FOR ROLE shop_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ratatoskr_write;
ALTER DEFAULT PRIVILEGES FOR ROLE shop_owner IN SCHEMA public GRANT USAGE ON SEQUENCES TO ratatoskr_write;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

`dev/prometheus/prometheus.yml`:

```yaml
# Dev Prometheus (compose.dev.yml): scrapes itself, Loki and, while a dev Ratatoskr runs, its /metrics.
global:
  scrape_interval: 15s
  evaluation_interval: 15s
rule_files: [/etc/prometheus/rules.yml]
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ["localhost:9090"]
  - job_name: loki
    static_configs:
      - targets: ["loki:3100"]
  - job_name: ratatoskr
    # Up only while `docker compose -f compose.dev.yml run --rm -T --use-aliases ratatoskr` is running.
    static_configs:
      - targets: ["ratatoskr:9100"]
```

`dev/prometheus/rules.yml`:

```yaml
groups:
  - name: ratatoskr-dev
    rules:
      - alert: DevSampleAlert
        expr: vector(1)
        labels: { severity: info }
        annotations: { summary: "Always firing, so prom_alerts has something to show" }
      - alert: TargetDown
        expr: up == 0
        for: 1m
        labels: { severity: warning }
        annotations: { summary: "{{ $labels.job }} is down" }
      - record: job:up:sum
        expr: sum by (job) (up)
```

`dev/loki/loki.yaml`:

```yaml
# Dev Loki (compose.dev.yml): single binary, single tenant (no X-Scope-OrgID needed), no usage reports.
auth_enabled: false
server:
  http_listen_port: 3100
  log_level: warn
common:
  instance_addr: 127.0.0.1
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2020-10-24
      store: tsdb
      object_store: filesystem
      schema: v13
      index:
        prefix: index_
        period: 24h
analytics:
  reporting_enabled: false
```

`dev/loggen/loggen.sh` (LF line endings):

```sh
#!/bin/sh
# Pushes made-up log lines of two apps to the dev Loki every 2 seconds (compose.dev.yml). busybox sh and wget only.
set -u
url="${LOKI_URL:-http://loki:3100}/loki/api/v1/push"
i=0
while true; do
  i=$((i + 1))
  now="$(date +%s)000000000"
  case $((i % 10)) in
    0) app=shop-api level=error line="GET /orders/$i 500 upstream timeout after 3000ms" ;;
    3 | 7) app=shop-api level=warn line="slow query on orders took $((i % 900 + 100))ms" ;;
    5) app=worker level=info line="sent invoice for order $i" ;;
    *) app=shop-api level=info line="GET /orders/$i 200 $((i % 40 + 5))ms" ;;
  esac
  body=$(printf '{"streams":[{"stream":{"app":"%s","env":"dev","level":"%s"},"values":[["%s","%s"]]}]}' \
    "$app" "$level" "$now" "$line")
  wget -q -O /dev/null --header 'Content-Type: application/json' --post-data "$body" "$url" \
    || echo "loggen: push to $url failed" >&2
  sleep 2
done
```

`dev/ratatoskr/stdio.yaml`:

```yaml
# Ratatoskr over stdio inside the dev stack (compose.dev.yml, service "ratatoskr"). Dev-only credentials.
server:
  transport: stdio
  stdio_role: dev
  metrics_host: 0.0.0.0     # scraped by the dev Prometheus as ratatoskr:9100 (run with --use-aliases)
  metrics_port: 9100
roles:
  dev: { "*": write }
connections:
  shop:
    kind: postgres
    description: "Dev shop database: customers, products, orders, order_items"
    mode: write
    dsn: postgresql://ratatoskr_read:dev-read@postgres:5432/shop?sslmode=disable
    write_dsn: postgresql://ratatoskr_write:dev-write@postgres:5432/shop?sslmode=disable
  metrics:
    kind: prometheus
    description: "Dev Prometheus: scrapes itself, Loki and Ratatoskr"
    url: http://prometheus:9090
  logs:
    kind: loki
    description: "Dev Loki: logs of the made-up shop-api and worker apps (labels app, env, level)"
    url: http://loki:3100
```

`dev/ratatoskr/local-http.yaml` (the hash is of `ratatoskr-dev`; regenerate with `ratatoskr hash-password` if you
like, the test does not depend on it):

```yaml
# Ratatoskr on this machine over HTTP against the dev stack's published ports (compose.dev.yml):
#   ratatoskr serve --insecure-dev --config dev/ratatoskr/local-http.yaml
# Then connect a client to http://127.0.0.1:8000/mcp and sign in as dev / ratatoskr-dev.
# Dev-only secrets: the http public_url makes `serve` refuse this file without --insecure-dev, which only binds
# loopback.
server:
  transport: streamable-http
  public_url: http://127.0.0.1:8000
  host: 127.0.0.1
  port: 8000
  state_path: .dev/state.db
  secret_key: dev-only-secret-key-not-for-production-0123456789
  metrics_port: 9100        # http://127.0.0.1:9100/metrics
auth:
  mode: local
  local:
    users:
      - username: dev
        password_hash: $argon2id$v=19$m=65536,t=3,p=4$dQpcHe6FIAuptxYNWJOqgQ$GQEyOX43SFvuU6DUM0QRoSzDk1vzMoDhLOx53zEICeY
        groups: [dev]
roles:
  dev: { "*": write }
connections:
  shop:
    kind: postgres
    description: "Dev shop database: customers, products, orders, order_items"
    mode: write
    dsn: postgresql://ratatoskr_read:dev-read@127.0.0.1:55432/shop?sslmode=disable
    write_dsn: postgresql://ratatoskr_write:dev-write@127.0.0.1:55432/shop?sslmode=disable
  metrics:
    kind: prometheus
    description: "Dev Prometheus"
    url: http://127.0.0.1:59090
  logs:
    kind: loki
    description: "Dev Loki: logs of the made-up shop-api and worker apps (labels app, env, level)"
    url: http://127.0.0.1:53100
```

`.gitattributes`:

```diff
diff --git a/.gitattributes b/.gitattributes
index dfe0770..23d1249 100644
--- a/.gitattributes
+++ b/.gitattributes
@@ -1,2 +1,4 @@
 # Auto detect text files and perform LF normalization
 * text=auto
+# Shell scripts run in Linux containers: keep LF line endings on every checkout.
+*.sh text eol=lf
```

- [ ] **Step 4: Run the tests**

Run: `.venv/Scripts/python -m pytest tests/unit/test_dev_stack_files.py -q` (6 passed) and
`.venv/Scripts/python -m pytest -m integration tests/integration/test_dev_seed.py -q` (2 passed).

- [ ] **Step 5: Try the stack**

```bash
docker compose -f compose.dev.yml config --quiet
docker compose -f compose.dev.yml up -d
docker compose -f compose.dev.yml build ratatoskr
.venv/Scripts/ratatoskr check-config --config dev/ratatoskr/stdio.yaml
.venv/Scripts/ratatoskr check-config --insecure-dev --config dev/ratatoskr/local-http.yaml
```

Then drive one stdio session (the script below is a throwaway helper; keep it outside the repo):

```python
"""python drive_stdio.py <repo>: an MCP session through `docker compose run`, then check the dev Prometheus."""
import json, subprocess, sys, time, urllib.parse, urllib.request

proc = subprocess.Popen(
    ["docker", "compose", "-f", "compose.dev.yml", "run", "--rm", "-T", "--use-aliases", "ratatoskr"],
    cwd=sys.argv[1], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
)
ident = 0

def send(method, params=None, notify=False):
    global ident
    message = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if not notify:
        ident += 1
        message["id"] = ident
    proc.stdin.write(json.dumps(message) + "\n"); proc.stdin.flush()
    while not notify:
        reply = json.loads(proc.stdout.readline())
        if reply.get("id") == ident:
            return reply

def call(name, **arguments):
    result = send("tools/call", {"name": name, "arguments": arguments})["result"]
    print(f"--- {name} isError={result.get('isError')}\n{result['content'][0]['text'][:400]}\n")

send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "drive", "version": "0"}})
send("notifications/initialized", notify=True)
call("connection_health")
call("pg_query", connection="shop", sql="SELECT status, count(*) FROM orders GROUP BY status ORDER BY status")
call("pg_query", connection="shop", sql="SELECT current_user")                       # ratatoskr_read
call("pg_execute", connection="shop", statements=[{"sql": "UPDATE products SET stock = stock + 1 WHERE id = 1"}])
call("pg_execute", connection="shop", statements=[{"sql": "CREATE TABLE x (id int)"}])  # 42501, by the GRANTs
call("prom_alerts", connection="metrics")
call("loki_query", connection="logs", logql='{env="dev", level="error"}', start="now-10m")
for _ in range(20):                                                                   # one scrape: 15 s
    query = urllib.parse.urlencode({"query": "ratatoskr_tool_calls_total"})
    rows = json.load(urllib.request.urlopen(f"http://127.0.0.1:59090/api/v1/query?{query}"))["data"]["result"]
    if rows:
        print("scraped", len(rows), "series"); break
    time.sleep(3)
proc.stdin.close(); print("exit", proc.wait(timeout=30))
```

Expected (2026-11-22): health ok for `logs`, `metrics`, `shop`; 250 orders per status; `current_user` is
`ratatoskr_read`; the `UPDATE` commits; `CREATE TABLE` fails with `PostgreSQL error 42501: permission denied for
schema public`; `DevSampleAlert` firing; Loki lines from `shop-api`; the dev Prometheus has the
`ratatoskr_tool_calls_total` series; exit 0. Finally `docker compose -f compose.dev.yml down -v`.

- [ ] **Step 6: Commit** — `Add the dev stack: sample PostgreSQL, Prometheus, Loki and a stdio Ratatoskr`

### Task 14: `docs/postgres-roles.md`, executed by a test

**Files:**
- Create: `docs/postgres-roles.md`
- Test: `tests/integration/test_postgres_roles_doc.py`

- [ ] **Step 1: Write the failing test** (it reads the SQL blocks out of the page)

````python
"""The SQL recipes of docs/postgres-roles.md, run verbatim against a fresh PostgreSQL: what each role can do."""

import asyncio
import re
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from testcontainers.community.postgres import PostgresContainer

pytestmark = pytest.mark.integration

DOC = Path(__file__).resolve().parents[2] / "docs" / "postgres-roles.md"
SQL_BLOCK_RE = re.compile(r"```sql\n(.*?)```", re.DOTALL)
READ_ONLY_REFUSALS = ("42501", "25006")  # insufficient privilege, read-only transaction


def _recipe(role: str) -> str:
    blocks = SQL_BLOCK_RE.findall(DOC.read_text(encoding="utf-8"))
    [block] = [block for block in blocks if f"CREATE ROLE {role} " in block]
    return block


def _dsn(base: str, *, database: str, user: str | None = None, password: str | None = None) -> str:
    parts = urlsplit(base)
    netloc = parts.netloc if user is None else f"{user}:{password}@{parts.netloc.rsplit('@', 1)[1]}"
    return urlunsplit(parts._replace(netloc=netloc, path=f"/{database}"))


@pytest.fixture(scope="module")
def server() -> Iterator[str]:
    """A PostgreSQL of its own: the recipes create cluster-wide roles that other integration tests create too."""
    container = PostgresContainer("postgres:17-alpine", driver=None)
    container.ports["5432"] = ("127.0.0.1", None)  # random host port, loopback only
    with container:
        port = container.get_exposed_port(5432)
        yield f"postgresql://{container.username}:{container.password}@127.0.0.1:{port}/{container.dbname}"


async def _run(dsn: str, sql: str) -> None:
    connection = await asyncpg.connect(dsn)
    try:
        await connection.execute(sql)  # trusted fixture SQL (several statements), never user input
    finally:
        await connection.close()


@pytest.fixture(scope="module")
def app_db(server: str) -> str:
    """Database app owned by app_owner (identity and serial tables), both recipes, then one more table."""
    asyncio.run(_prepare(server))
    return server


async def _prepare(server: str) -> None:
    await _run(server, "CREATE ROLE app_owner LOGIN PASSWORD 'owner-pass'")
    await _run(server, "CREATE DATABASE app OWNER app_owner")
    owner = _dsn(server, database="app", user="app_owner", password="owner-pass")
    await _run(
        owner,
        "CREATE TABLE items (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name text);"
        "CREATE TABLE legacy (id serial PRIMARY KEY, note text);"
        "INSERT INTO items (name) VALUES ('apple');",
    )
    await _run(_dsn(server, database="app"), _recipe("ratatoskr_read") + _recipe("ratatoskr_write"))
    await _run(owner, "CREATE TABLE later (id serial PRIMARY KEY, note text)")  # covered by the default privileges


async def _connect(server: str, user: str, password: str) -> asyncpg.Connection:
    return await asyncpg.connect(_dsn(server, database="app", user=user, password=password))


async def test_read_role_reads_every_table_and_changes_nothing(app_db: str) -> None:
    connection = await _connect(app_db, "ratatoskr_read", "change-me")
    try:
        assert await connection.fetchval("SELECT count(*) FROM items") == 1
        assert await connection.fetchval("SELECT count(*) FROM later") == 0
        assert await connection.fetchval("SHOW default_transaction_read_only") == "on"
        for sql in ("INSERT INTO items (name) VALUES ('x')", "CREATE TABLE x (id int)", "TRUNCATE items"):
            with pytest.raises(asyncpg.PostgresError) as info:
                await connection.execute(sql)
            assert info.value.sqlstate in READ_ONLY_REFUSALS, sql
        await connection.execute("SET default_transaction_read_only = off")  # the GRANTs still refuse
        with pytest.raises(asyncpg.PostgresError) as info:
            await connection.execute("INSERT INTO items (name) VALUES ('x')")
        assert info.value.sqlstate == "42501"
    finally:
        await connection.close()


async def test_write_role_changes_rows_but_not_the_schema(app_db: str) -> None:
    connection = await _connect(app_db, "ratatoskr_write", "change-me-too")
    try:
        await connection.execute("INSERT INTO items (name) VALUES ('pear')")
        await connection.execute("INSERT INTO legacy (note) VALUES ('needs USAGE on the sequence')")
        await connection.execute("INSERT INTO later (note) VALUES ('default privileges')")
        await connection.execute("UPDATE items SET name = 'plum' WHERE name = 'pear'")
        await connection.execute("DELETE FROM items WHERE name = 'plum'")
        for sql in ("CREATE TABLE x (id int)", "TRUNCATE items", "DROP TABLE items", "ALTER TABLE items ADD c int"):
            with pytest.raises(asyncpg.PostgresError) as info:
                await connection.execute(sql)
            assert info.value.sqlstate == "42501", sql
    finally:
        await connection.close()
````

- [ ] **Step 2: Run it** — `.venv/Scripts/python -m pytest -m integration tests/integration/test_postgres_roles_doc.py -q`;
  expected: errors, the page does not exist.

- [ ] **Step 3: Write the page**

````markdown
# PostgreSQL roles for Ratatoskr

Ratatoskr keeps reads read-only in several layers (read-only sessions and transactions that are always rolled back,
the extended protocol, a session reset; see [the security model](security-model.md)), but **the database role in each
DSN is the real boundary**. Those layers cannot take away a privilege the role has, and they do not stop extensions
that open their own connections (`dblink`, `postgres_fdw`). Give every connection a dedicated role with only the
grants it needs; never a superuser or the owner of the tables.

The recipes below assume a database `app` whose tables belong to `app_owner` and live in schema `public`. Replace
the three names and the passwords. They work on PostgreSQL 12 and newer; run them as a superuser or as a role that
may create roles and grant on those objects. `tests/integration/test_postgres_roles_doc.py` runs the two SQL blocks
of this page against a real PostgreSQL and checks what each role can and cannot do; the dev stack
(`dev/postgres/initdb/02-ratatoskr-roles.sql`) uses the same grants.

## 1. Read role (`dsn`)

Every read logs in with `dsn`: `pg_query`, the discovery tools, `pg_explain`, `pg_activity`, `pg_table_stats`,
`pg_server_info` and `connection_health`.

```sql
CREATE ROLE ratatoskr_read LOGIN PASSWORD 'change-me'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- Another layer for anything else that logs in with this role; Ratatoskr's read sessions are read-only anyway.
ALTER ROLE ratatoskr_read SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE app TO ratatoskr_read;
GRANT USAGE ON SCHEMA public TO ratatoskr_read;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ratatoskr_read;
-- Tables app_owner creates later:
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT SELECT ON TABLES TO ratatoskr_read;
-- PostgreSQL 14 and older let every role create objects in public; 15 and newer do not.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

Repeat the `USAGE`, `SELECT` and `ALTER DEFAULT PRIVILEGES` lines for every other schema the connection should
see, and leave out tables it should not read: `allowed_schemas` in the config only filters the discovery tools, it
does not restrict SQL.

Optional: `GRANT pg_read_all_stats TO ratatoskr_read;` lets `pg_activity` show the queries of other users'
sessions. Those query texts can contain values your users may not otherwise see (literals, sometimes secrets), so
grant it only where that is acceptable. Without it `pg_activity` lists other users' sessions without their query
text.

## 2. Write role (`write_dsn`)

For a connection with `mode: write`, give the write pool its own login with `write_dsn`. Only `pg_execute` and
write-level `pg_explain(analyze=true)` use it; reads keep using `dsn`. Grant only what `pg_execute` should change.

```sql
CREATE ROLE ratatoskr_write LOGIN PASSWORD 'change-me-too'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE app TO ratatoskr_write;
GRANT USAGE ON SCHEMA public TO ratatoskr_write;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ratatoskr_write;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ratatoskr_write;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ratatoskr_write;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT USAGE ON SEQUENCES TO ratatoskr_write;
```

This role cannot create, alter, drop or truncate tables. Grant `TRUNCATE` or DDL rights only if `pg_execute` is
meant to do that.

Why a separate role: without `write_dsn` both pools log in as the same user, and PostgreSQL lets a session cancel
or end any other session of its own user, so a caller with read access could end in-flight writes with
`pg_terminate_backend`. The same holds for two Ratatoskr connections that point at one server with one user.

## 3. Configuration

```yaml
connections:
  app-db:
    kind: postgres
    mode: write                     # leave out (read) for a read-only connection, and then omit write_dsn
    dsn: ${APP_DB_READ_DSN}         # postgresql://ratatoskr_read:...@db.internal:5432/app
    write_dsn: ${APP_DB_WRITE_DSN}  # postgresql://ratatoskr_write:...@db.internal:5432/app
```

`check-config` shows `separate write role: yes` for a write connection with `write_dsn`.

## 4. Do not grant

- Superuser, `CREATEROLE`, `BYPASSRLS`, or membership in the table owner's role.
- `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program` (server files and programs).
- `EXECUTE` on `dblink*` functions or `USAGE` on a `postgres_fdw` server: they open connections Ratatoskr does not
  control.
- `pg_signal_backend` (cancel or end other users' sessions).

## 5. Check it

Connect as each role (`psql "postgresql://ratatoskr_read:...@db.internal/app"`) and expect:

| Statement | `ratatoskr_read` | `ratatoskr_write` |
|---|---|---|
| `SELECT ... FROM <table>` | works | works |
| `INSERT` / `UPDATE` / `DELETE` | `permission denied` or `cannot execute ... in a read-only transaction` | works |
| `CREATE TABLE x (id int)` | refused | `permission denied for schema public` |
| `TRUNCATE <table>` | refused | `permission denied` |
````

- [ ] **Step 4: Run** — expected: 2 passed (its own `postgres:17-alpine` container).

- [ ] **Step 5: Commit** — `Document the restricted PostgreSQL roles and test the recipe`

### Task 15: CI, release and Dependabot

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `.github/dependabot.yml`,
  `constraints-dev.txt`
- Test: `tests/unit/test_workflows.py`

- [ ] **Step 1: Write the failing test**

```python
"""GitHub Actions hygiene: actions pinned by commit SHA with a version comment, least privilege, no extra secrets.

The workflows cannot run locally; `actionlint` (see CONTRIBUTING.md) checks their syntax, this test their policy.
"""

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(?P<ref>\S+)(?P<comment>.*)$", re.MULTILINE)
PINNED_RE = re.compile(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}")
VERSION_COMMENT_RE = re.compile(r"\s+# v\d+\.\d+\.\d+")
WRITE_SCOPES = {"release.yml": {"image": {"packages"}}}


def _load(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def test_there_are_workflows() -> None:
    assert [path.name for path in WORKFLOWS] == ["ci.yml", "release.yml"]


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_is_pinned_by_sha_with_a_version_comment(path: Path) -> None:
    for match in USES_RE.finditer(path.read_text(encoding="utf-8")):
        ref = match.group("ref")
        if ref.startswith("./"):
            continue
        assert PINNED_RE.fullmatch(ref), f"{path.name}: {ref} is not pinned to a commit SHA"
        assert VERSION_COMMENT_RE.fullmatch(match.group("comment")), f"{path.name}: {ref} lacks a '# vX.Y.Z' comment"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_permissions_are_read_only_except_where_listed(path: Path) -> None:
    workflow = _load(path)
    assert workflow["permissions"] == {"contents": "read"}
    allowed = WRITE_SCOPES.get(path.name, {})
    for name, job in workflow["jobs"].items():
        granted = {scope for scope, level in job.get("permissions", {}).items() if level == "write"}
        assert granted <= allowed.get(name, set()), f"{path.name}: job {name} asks for {granted}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_only_github_token_and_no_privileged_triggers(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert set(re.findall(r"secrets\.(\w+)", text)) <= {"GITHUB_TOKEN"}
    assert "pull_request_target" not in text
    assert "workflow_run" not in text


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_checkout_does_not_keep_credentials(path: Path) -> None:
    for job in _load(path)["jobs"].values():
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_docker_images_run_by_workflows_are_digest_pinned() -> None:
    for path in WORKFLOWS:
        for image in re.findall(r"TRIVY_IMAGE:\s*(\S+)", path.read_text(encoding="utf-8")):
            assert re.fullmatch(r"aquasec/trivy@sha256:[0-9a-f]{64}", image), image


def test_ci_runs_every_check_the_conventions_name() -> None:
    text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for command in (
        "python -m ruff check src tests",
        "python -m ruff format --check src tests",
        "python -m mypy src",
        "python -m pytest -q",
        "python -m pytest -m integration -q",
        "docker compose -f compose.yml config --quiet",
        "docker compose -f compose.dev.yml config --quiet",
    ):
        assert command in text, command


def test_release_publishes_multi_arch_with_sbom_and_provenance() -> None:
    release = _load(ROOT / ".github" / "workflows" / "release.yml")
    assert release["jobs"]["image"]["needs"] == "ci"
    [push] = [step for step in release["jobs"]["image"]["steps"] if step.get("with", {}).get("push") is True]
    assert push["with"]["platforms"] == "linux/amd64,linux/arm64"
    assert push["with"]["sbom"] is True
    assert push["with"]["provenance"] == "mode=max"
```

- [ ] **Step 2: Run it** — expected: failures (`.github/workflows` empty).

- [ ] **Step 3: Create the files.** Before writing them, re-resolve the action SHAs (they must be commits, not tag
  objects):

```bash
for rv in actions/checkout@v7.0.1 actions/setup-python@v7.1.0 docker/setup-qemu-action@v4.4.0 \
          docker/setup-buildx-action@v4.4.1 docker/login-action@v4.8.0 docker/metadata-action@v6.2.0 \
          docker/build-push-action@v7.4.0; do
  r=${rv%@*}; v=${rv#*@}
  out=$(git ls-remote "https://github.com/$r.git" "refs/tags/$v" "refs/tags/$v^{}")
  sha=$(echo "$out" | grep '\^{}' | awk '{print $1}'); [ -z "$sha" ] && sha=$(echo "$out" | awk '{print $1}')
  echo "$r $v $sha"
done
docker buildx imagetools inspect aquasec/trivy:0.76.2 | grep -m1 Digest
```

On 2026-11-22 they gave the SHAs used below and `sha256:8f6bb947...8fb` for Trivy.

`constraints-dev.txt`:

```text
# Exact versions of the dev tools (the `dev` extra) that CI installs next to constraints.txt, so that a new ruff or
# mypy release cannot change lint, format or type results without a commit. Their own dependencies are not pinned.
# Refresh: upgrade in .venv, run the full checks, then copy the versions from `pip freeze`.
mypy==2.4.1
pytest==9.2.0
pytest-asyncio==1.5.0
respx==0.23.1
ruff==0.17.6
testcontainers==4.15.0
```

`.github/workflows/ci.yml`:

```yaml
# Lint, types, unit and integration tests, compose file checks, image build and vulnerability scan.
# Runs on pull requests, on pushes to main and from release.yml (workflow_call) before an image is published.
name: CI

on:
  pull_request:
  push:
    branches: [main]
  workflow_call:
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

env:
  PIP_DISABLE_PIP_VERSION_CHECK: "1"
  # Trivy 0.76.2, pinned by digest (multi-arch index).
  TRIVY_IMAGE: aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb

jobs:
  lint:
    name: ruff, format, mypy
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.12"
      - name: Install
        run: python -m pip install -c constraints.txt -c constraints-dev.txt -e ".[dev]"
      - name: ruff check
        run: python -m ruff check src tests
      - name: ruff format --check
        run: python -m ruff format --check src tests
      - name: mypy --strict
        run: python -m mypy src

  unit:
    name: unit tests (Python ${{ matrix.python }})
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    strategy:
      fail-fast: false
      matrix:
        python: ["3.12", "3.13"]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: ${{ matrix.python }}
      - name: Install
        run: python -m pip install -c constraints.txt -c constraints-dev.txt -e ".[dev]"
      - name: pytest (no network, no Docker)
        run: python -m pytest -q

  integration:
    name: integration tests (Docker)
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@6d4fd22b20465ccc0f7354476588e8df7c9ca0e0 # v7.1.0
        with:
          python-version: "3.12"
      - name: Install
        run: python -m pip install -c constraints.txt -c constraints-dev.txt -e ".[dev]"
      - name: pytest -m integration (testcontainers starts PostgreSQL, Prometheus and Loki)
        run: python -m pytest -m integration -q

  compose:
    name: compose files
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: docker compose config
        run: |
          cp .env.example .env
          cp deploy/config.example.yaml config.yaml
          docker compose -f compose.yml config --quiet
          docker compose -f compose.dev.yml config --quiet

  image:
    name: image build and Trivy scan
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1
      - name: Build (linux/amd64, loaded into the local daemon)
        uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          context: .
          load: true
          push: false
          tags: ratatoskr:ci
      - name: Smoke test (read-only root, non-root user)
        run: |
          docker run --rm --read-only ratatoskr:ci --version
          test "$(docker run --rm --entrypoint id ratatoskr:ci -u)" = "10001"
      - name: Trivy (fails on fixed HIGH or CRITICAL vulnerabilities)
        run: |
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" image \
            --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress ratatoskr:ci
```

`.github/workflows/release.yml`:

```yaml
# On a version tag (v1.0.0): run CI, check the tag against the package version, scan the image, then push it to
# GHCR for linux/amd64 and linux/arm64 with an SBOM and provenance attestation. Only GITHUB_TOKEN is used.
name: Release

on:
  push:
    tags: ["v[0-9]+.[0-9]+.[0-9]+"]

permissions:
  contents: read

jobs:
  ci:
    uses: ./.github/workflows/ci.yml

  image:
    name: publish image
    needs: ci
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    permissions:
      contents: read
      packages: write
    env:
      IMAGE: ghcr.io/${{ github.repository_owner }}/ratatoskr
      TRIVY_IMAGE: aquasec/trivy@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Tag matches src/ratatoskr/__init__.py
        run: |
          version="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' src/ratatoskr/__init__.py)"
          if [ "v${version}" != "${GITHUB_REF_NAME}" ]; then
            echo "::error::tag ${GITHUB_REF_NAME} does not match __version__ ${version}"
            exit 1
          fi
      - uses: docker/setup-qemu-action@99012661954931238ded8c8b007157a8430204e1 # v4.4.0
      - uses: docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069 # v4.4.1
      - id: meta
        uses: docker/metadata-action@dc802804100637a589fabce1cb79ff13a1411302 # v6.2.0
        with:
          images: ${{ env.IMAGE }}
          tags: |
            type=semver,pattern={{version}}
            type=semver,pattern={{major}}.{{minor}}
            type=semver,pattern={{major}}
          labels: |
            org.opencontainers.image.title=ratatoskr
            org.opencontainers.image.description=Secure multi-connection MCP server for PostgreSQL, Prometheus and Loki
      - name: Build linux/amd64 for the scan
        uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          context: .
          load: true
          push: false
          tags: ratatoskr:scan
          build-args: VERSION=${{ steps.meta.outputs.version }}
      - name: Trivy (fails on fixed HIGH or CRITICAL vulnerabilities)
        run: |
          docker run --rm -v /var/run/docker.sock:/var/run/docker.sock "$TRIVY_IMAGE" image \
            --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 --no-progress ratatoskr:scan
      - uses: docker/login-action@8aa5831fb8d48d8f76594c7ddde61ae58019f550 # v4.8.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - name: Build and push linux/amd64 + linux/arm64 with SBOM and provenance
        uses: docker/build-push-action@c3c9e263c25d99ce0380d002d59b67737d91b0dc # v7.4.0
        with:
          context: .
          platforms: linux/amd64,linux/arm64
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          annotations: ${{ steps.meta.outputs.annotations }}
          build-args: VERSION=${{ steps.meta.outputs.version }}
          sbom: true
          provenance: mode=max
```

`.github/dependabot.yml`:

```yaml
# Weekly update pull requests. CI must pass on each; for Python packages also refresh constraints.txt as CLAUDE.md
# ("Runtime constraints") describes, since Dependabot only edits the files it understands.
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    groups:
      actions:
        patterns: ["*"]

  - package-ecosystem: pip
    directory: /
    schedule:
      interval: weekly
    groups:
      python:
        patterns: ["*"]
    ignore:
      # The SDK cap is deliberate (pyproject.toml): raising it needs the re-verification described in CLAUDE.md.
      - dependency-name: mcp
        update-types: ["version-update:semver-minor", "version-update:semver-major"]

  - package-ecosystem: docker
    directory: /
    schedule:
      interval: weekly

  - package-ecosystem: docker-compose
    directory: /
    schedule:
      interval: weekly
```

- [ ] **Step 4: Run and lint**

Run: `.venv/Scripts/python -m pytest tests/unit/test_workflows.py -q` (12 passed) and
`MSYS_NO_PATHCONV=1 docker run --rm -v "$(cygpath -w "$PWD"):/repo" -w /repo rhysd/actionlint:1.7.12 -color=false`
(no output, exit 0). Optional, as CI's Linux jobs do: run the lint and unit commands in `python:3.12-slim`
on a `git archive` export (`pip install -c constraints.txt -c constraints-dev.txt -e ".[dev]"`, then ruff, mypy,
pytest).

- [ ] **Step 5: Commit** — `Add CI, the GHCR release workflow and Dependabot`

### Task 16: Move the reference out of the README; rewrite the README

**Files:**
- Create: `docs/configuration.md`, `docs/security-model.md`
- Modify: `README.md` (rewritten)

The settings tables (README `## Configuration` up to `## Tools`) move to `docs/configuration.md` under
`## Settings`, their `###` subsections become `##`, the `config.example.yaml` link gets `../`, the `metrics_port` row
is replaced by `metrics_port` + `metrics_host` rows, and `## Metrics`, `## Running in a container` and
`## Environment variables` are added. The security section (`## Security model` up to `### Database roles`) moves
to `docs/security-model.md` the same way; the `### Database roles` and `## Development` content is replaced by
`docs/postgres-roles.md` (Task 14) and `CONTRIBUTING.md` (Task 17). The README keeps features, three quick starts and
the `## Tools` section unchanged. The resulting files:

- [ ] **Step 1: Write `docs/configuration.md`**

````markdown
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
| `server.metrics_host` | `127.0.0.1` | Address of the metrics listener. It has no authentication: keep it on loopback, or use `0.0.0.0` in a container whose metrics port is reachable only on an internal network. |
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
  calls) and asked for its health with a 5 s limit. So with metrics on, every connection is opened within one scrape
  of the start, even if no tool used it yet. These checks are not tool calls: they are not audited.
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
  `deploy/config.example.yaml` trusts exactly that address. With your own proxy on the Docker host and a published
  port, it is the bridge gateway, not `127.0.0.1`:
  `docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}'` (usually `172.17.0.1`). With a wrong
  value every client shares the proxy's rate-limit bucket.

## Environment variables

| Variable | Meaning |
|---|---|
| `RATATOSKR_CONFIG` | Config file path when `--config` is not given. |
| `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` | Outgoing HTTP (OIDC issuer, Prometheus, Loki) goes through the proxy; list in-cluster hosts in `NO_PROXY`. PostgreSQL connections do not use them. |
| anything referenced as `${NAME}` | Values for the config file. |
````

- [ ] **Step 2: Write `docs/security-model.md`**

```markdown
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
```

- [ ] **Step 3: Replace `README.md`**

````markdown
# Ratatoskr

[![CI](https://github.com/keremkocatus/claude-postgresql/actions/workflows/ci.yml/badge.svg)](https://github.com/keremkocatus/claude-postgresql/actions/workflows/ci.yml)

Ratatoskr is an MCP server that gives Claude (claude.ai, Claude Desktop, Claude Code) controlled access to
**several PostgreSQL databases, Prometheus servers and Loki log stores at once**, with per-group access levels and
an audit trail. MIT licensed.

> **Status: 1.0.0, not released yet** (the package says `1.0.0.dev0`). Runs locally over **stdio**, or as a team
> server over **streamable HTTP** behind a TLS proxy, as a claude.ai custom connector: Ratatoskr is its own OAuth 2.1
> authorization server, and people sign in with local users or through an OIDC provider such as Authentik.
> Coming from `claude-postgresql` 0.1? See [`MIGRATION.md`](MIGRATION.md): there is no backward compatibility.

## Features

- Any number of named PostgreSQL (12 or newer), Prometheus and Loki connections in one server; the tool set stays
  the same (19 tools). Prometheus connections also work with Mimir, Thanos Query and VictoriaMetrics.
- Access per group: `read` or `write`, capped by each connection's `mode`. Unknown and forbidden connections look
  identical ("Connection 'x' not found.").
- Read-only enforcement by PostgreSQL itself rather than by SQL pattern matching (see the
  [security model](docs/security-model.md) and the [role recipe](docs/postgres-roles.md)).
- Every tool call is audited: one JSON log line with `event: audit` (the SQL, PromQL or LogQL with secrets masked
  and truncated to 4096 characters, plus the SHA-256 of the full text) and a `result` of `ok`, `denied`, `error` or
  `timeout`; over HTTP also in SQLite (`/data/state.db`, kept 90 days by default).
- Failed calls return an `Error: ...` text with MCP `isError: true`, so the host sees them as failures.
- Responses are clamped (rows and bytes) with an explicit note on how to narrow the request.
- Remote use over streamable HTTP with OAuth 2.1 (dynamic client registration, PKCE, rotating refresh tokens with
  reuse detection, revocation), local argon2id users or OIDC (Authentik) and rate-limited sign-in.
- Prometheus metrics on a separate port: tool calls, latency, backend reachability, auth events.
- Query results and log lines are returned exactly as stored (long log lines are cut, and marked). Masking of DSNs,
  passwords and tokens applies to error messages, logs and the audited query text, never to your data.

## Quick start: team server (Docker Compose + Caddy)

[`compose.yml`](compose.yml) runs Ratatoskr behind Caddy, which gets a Let's Encrypt certificate for your domain.
You need a host with Docker, a DNS name pointing at it and ports 80 and 443 open.

```bash
git clone https://github.com/keremkocatus/claude-postgresql.git ratatoskr && cd ratatoskr
cp .env.example .env                          # set RATATOSKR_DOMAIN and the secrets
cp deploy/config.example.yaml config.yaml     # users, roles, connections
docker compose build
docker compose run --rm ratatoskr hash-password   # paste the hash into .env, inside single quotes
docker compose run --rm ratatoskr check-config
docker compose up -d
```

Then add `https://<RATATOSKR_DOMAIN>/mcp` as a custom connector in claude.ai, or in Claude Code with
`claude mcp add --transport http ratatoskr https://<RATATOSKR_DOMAIN>/mcp`; see [connectors](docs/connectors.md).
Give each connection a restricted database role ([PostgreSQL roles](docs/postgres-roles.md)); for single sign-on
follow [Authentik](docs/authentik.md).

The container runs as uid 10001 with a read-only root file system, keeps its state in the `ratatoskr-data` volume
and is reachable only through Caddy, which also hides `/healthz`, `/readyz` and `/metrics`. Configuration changes
need `docker compose restart ratatoskr`.

## Quick start: on your machine (stdio)

Requires Python 3.12+.

```bash
pip install -e .                      # from a checkout; or: uv pip install -e .
cp config.example.yaml config.yaml    # edit connections and roles
export APP_DB_DSN='postgresql://ratatoskr_read:password@localhost:5432/app'
ratatoskr check-config --config config.yaml
claude mcp add ratatoskr -e APP_DB_DSN="$APP_DB_DSN" -- ratatoskr serve --config "$PWD/config.yaml"
```

Claude Desktop takes the same command in `claude_desktop_config.json`; see [connectors](docs/connectors.md). Logs
go to **stderr** as JSON with secrets masked; stdout is the MCP channel.

## Try it with sample data

[`compose.dev.yml`](compose.dev.yml) starts PostgreSQL with a small shop database (and the restricted roles of the
role recipe), Prometheus, Loki with a log generator, all on this machine:

```bash
docker compose -f compose.dev.yml up -d
claude mcp add ratatoskr-dev -- docker compose -f "$PWD/compose.dev.yml" run --rm -T --use-aliases ratatoskr
```

Or run Ratatoskr from your checkout over HTTP against the same stack
(`ratatoskr serve --insecure-dev --config dev/ratatoskr/local-http.yaml`, then connect a client to
`http://127.0.0.1:8000/mcp` and sign in as `dev` / `ratatoskr-dev`). `docker compose -f compose.dev.yml down -v`
removes it all.

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

## Documentation

| Page | What it covers |
|---|---|
| [Configuration reference](docs/configuration.md) | Every setting, connection kind, metrics, containers, environment variables. |
| [Connectors](docs/connectors.md) | claude.ai custom connector, Claude Desktop, Claude Code. |
| [PostgreSQL roles](docs/postgres-roles.md) | Restricted read role and separate write role, tested SQL. |
| [Authentik](docs/authentik.md) | Single sign-on with OIDC, Caddy example, verification checklist. |
| [Security model](docs/security-model.md) | What Ratatoskr enforces and what it leaves to roles and proxies. |
| [Migration from 0.1](MIGRATION.md) | `claude-postgresql` 0.1 to Ratatoskr 1.0. |
| [Changelog](CHANGELOG.md), [Contributing](CONTRIBUTING.md), [Security policy](SECURITY.md) | |

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the setup, the checks CI runs and the conventions
([`CLAUDE.md`](CLAUDE.md)).

## License

MIT, see [`LICENSE`](LICENSE).
````

- [ ] **Step 4: Check** — `git diff --stat README.md docs/` and read the three pages once; the link and coverage
  tests come in Task 18 (they also need the pages of Task 17).

- [ ] **Step 5: Commit** — `Move the configuration and security reference out of the README`

### Task 17: Connectors, security policy, contributing, changelog, migration

**Files:**
- Create: `docs/connectors.md`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `MIGRATION.md`

Every claim in `docs/connectors.md` is either backed by a named test or listed under "Check by hand".

- [ ] **Step 1: `docs/connectors.md`**

````markdown
# Connecting Claude

Ratatoskr speaks MCP in two ways: **streamable HTTP** at `<public_url>/mcp` with OAuth (a team server, for example
[`compose.yml`](../compose.yml)), and **stdio** (a local process the client starts). Every client sees the same 19
tools; what a person can use depends on their groups (`roles:` in the config).

Each section says what the test suite checks against Ratatoskr itself and what you have to check by hand: the
client applications are not part of the tests, and their menus change.

## claude.ai (custom connector)

Needs a team server with an https `public_url` that claude.ai can reach from the internet.

1. In claude.ai open the connector settings and add a custom connector with the URL `https://<your domain>/mcp`.
   Leave the OAuth client ID and secret empty: claude.ai registers itself.
2. claude.ai opens Ratatoskr's sign-in page (local users) or sends you to your identity provider (OIDC); afterwards
   the connector shows as connected.
3. Ask Claude to run `list_connections`: it lists exactly the connections your groups grant.

What Ratatoskr does here, covered by tests (`tests/unit/secure_http/e2e/`): dynamic client registration for
redirect URIs on `server.allowed_redirect_hosts` (default `claude.ai`, `claude.com`, `localhost`, `127.0.0.1`),
authorization code with PKCE S256, rotating refresh tokens, revocation; scopes a client asks for (claude.ai sends
`claudeai`) are replaced by Ratatoskr's only scope, `mcp`.

Check by hand:

- [ ] Where the custom connector setting is in your plan (on Team and Enterprise plans an owner may have to add the
      connector for the organization first) and that the flow above completes.
- [ ] Your proxy lets claude.ai's servers reach `/mcp`, `/register`, `/authorize`, `/token` and
      `/.well-known/oauth-authorization-server` (and nothing blocks `/login` or `/oauth/callback` for browsers).
- [ ] A tool call shows up in the audit trail with your user as `subject`.

## Claude Desktop

**Remote (team server):** Claude Desktop uses the connectors of your claude.ai account; add the server as above.

**Local (stdio):** add Ratatoskr to `claude_desktop_config.json` (*Settings → Developer → Edit Config* in recent
versions); Claude Desktop starts the process and talks to it over stdin/stdout:

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
`.venv/bin/ratatoskr`, on Windows `.venv\Scripts\ratatoskr.exe`). Over stdio there is no sign-in: you act as a
member of `server.stdio_role`.

Covered by tests: `tests/unit/test_cli.py` starts `ratatoskr serve` as a real process and speaks JSON-RPC over stdio
with it (initialize, tool list, a tool call) without anything but protocol messages on stdout.

Check by hand:

- [ ] A connector added in claude.ai shows up in Claude Desktop signed in with the same account.
- [ ] After a restart of Claude Desktop the local server shows as running and `list_connections` answers.
- [ ] Its log (stderr) is in Claude Desktop's MCP log files, as JSON lines with secrets masked.

## Claude Code

**Remote (team server):**

```bash
claude mcp add --transport http ratatoskr https://<your domain>/mcp
```

Then run `/mcp` in Claude Code and choose the server to sign in in the browser. Claude Code registers as a public
client (no client secret, PKCE only); sign-in, refresh and `/revoke` for public clients are covered by
`tests/unit/secure_http/e2e/test_http_client_compat.py`. For a server on this machine started with
`serve --insecure-dev`, use `http://127.0.0.1:8000/mcp`.

**Local (stdio):**

```bash
claude mcp add ratatoskr -e APP_DB_DSN='postgresql://ratatoskr_read:password@localhost:5432/app' \
  -- ratatoskr serve --config /absolute/path/to/config.yaml
```

**Dev stack:** with `docker compose -f compose.dev.yml up -d` running, Claude Code can start Ratatoskr inside the
stack, with the sample connections `shop`, `metrics` and `logs`:

```bash
claude mcp add ratatoskr-dev -- docker compose -f /absolute/path/to/compose.dev.yml run --rm -T --use-aliases ratatoskr
```

`-T` keeps a terminal out of the MCP channel; `--use-aliases` lets the dev Prometheus scrape this run's metrics as
`ratatoskr:9100`.

Check by hand:

- [ ] `claude mcp list` shows the server as connected, and `/mcp` shows its tools.
- [ ] For the remote server: sign-in in the browser returns to Claude Code, and the session survives an access token
      lifetime (`auth.access_token_ttl`, default 1 hour) through a refresh.

## Several stdio clients

Each stdio client starts its own process. They share nothing but the config file; with `server.metrics_port` set
only the first can listen on that port, so leave metrics off in configs used by several clients (see
[Metrics](configuration.md#metrics)).
````

- [ ] **Step 2: `SECURITY.md`** (GitHub private vulnerability reporting; no e-mail address)

```markdown
# Security policy

Ratatoskr sits between Claude and your databases, metrics and logs, so security reports are welcome and taken
seriously.

## Reporting a vulnerability

Report it privately through GitHub: open
[a new security advisory](https://github.com/keremkocatus/claude-postgresql/security/advisories/new) (the
repository's *Security* tab → *Report a vulnerability*). Please do not open a public issue, pull request or
discussion for a vulnerability.

Include what you can of:

- the version (`ratatoskr --version`, image tag or commit) and the transport (stdio or streamable HTTP);
- the affected part (OAuth/sign-in, policy, PostgreSQL read path, Prometheus or Loki backends, metrics, image);
- steps to reproduce, or a proof of concept, and the impact you see;
- the relevant config with every secret removed.

The maintainer replies in the advisory, keeps you informed while a fix is prepared and credits you in the advisory
and the changelog unless you prefer otherwise. This is a volunteer project: there is no bug bounty and no fixed
response time.

## Supported versions

Fixes go into the latest release only (the newest `1.x`). `claude-postgresql` 0.1 is no longer maintained.

## Scope

In scope: anything that lets a caller do more than their groups allow, read data of a connection they cannot see,
bypass read-only enforcement on a `mode: read` connection, obtain or replay tokens, sign in without valid
credentials, or makes Ratatoskr leak secrets (DSNs, passwords, tokens, tenants) into tool output, error texts or
logs.

Out of scope: what a database role, Prometheus or Loki credential is itself allowed to do (see
[PostgreSQL roles](docs/postgres-roles.md)), expensive but permitted queries, a reachable metrics port you chose to
expose, and deployments that ignore [the security model](docs/security-model.md) (for example no TLS proxy, or
`--insecure-dev` beyond loopback).
```

- [ ] **Step 3: `CONTRIBUTING.md`**

````markdown
# Contributing

Thanks for helping. Bugs and ideas go into [issues](https://github.com/keremkocatus/claude-postgresql/issues);
security problems go through [`SECURITY.md`](SECURITY.md), never into a public issue.

## Setup

Python 3.12 or 3.13, and Docker for the integration tests and the image.

```bash
python -m venv .venv
. .venv/bin/activate                     # Windows: .venv\Scripts\activate
python -m pip install -c constraints.txt -c constraints-dev.txt -e ".[dev]"
```

`constraints.txt` pins the runtime dependencies the image ships, `constraints-dev.txt` the dev tools CI uses, so your
results match CI.

## Checks (all run in CI)

```bash
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy src                       # strict
python -m pytest -q                      # unit tests: no network, no Docker
python -m pytest -m integration -q       # Docker: testcontainers starts PostgreSQL, Prometheus and Loki
docker build -t ratatoskr:dev .
docker compose -f compose.yml config --quiet       # needs a .env and config.yaml (copy the examples)
docker compose -f compose.dev.yml config --quiet
```

The workflows cannot run locally; lint them with actionlint (their policy, such as SHA-pinned actions and minimal
permissions, is checked by `tests/unit/test_workflows.py`):

```bash
docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.12
```

The image scan CI runs:

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.76.2 image \
  --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed ratatoskr:dev
```

To try changes by hand, use the dev stack in [`compose.dev.yml`](compose.dev.yml) (see the README).

## Rules

The conventions are in [`CLAUDE.md`](CLAUDE.md); read it before changing code. In short:

- Tests first: a failing test, then the code. Unit tests never touch the network or Docker (`tests/fakes.py`);
  anything that needs a real PostgreSQL, Prometheus or Loki goes in `tests/integration/` with
  `pytestmark = pytest.mark.integration`, and only ever uses local containers.
- Every tool call goes through `ToolRuntime`; no secrets in errors, logs or metrics labels; logs go to stderr.
- Docs describe what the code does now. A change of behaviour updates the docs and `CHANGELOG.md` in the same pull
  request.
- Dependencies: a new or upgraded runtime dependency also updates `constraints.txt` (how: `CLAUDE.md`, "Runtime
  constraints"); the image build and the full test suite must pass with it.

## Pull requests

- One topic per pull request, with a description of what changes and why.
- Commit subjects in the imperative ("Add ...", "Fix ..."), and CI green.
- New behaviour comes with tests; a bug fix with a test that failed before it.
````

- [ ] **Step 4: `CHANGELOG.md`**

```markdown
# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 1.0.0 (to be released)

Ratatoskr 1.0.0 replaces `claude-postgresql` 0.1. It is not backward compatible: see [`MIGRATION.md`](MIGRATION.md).

#### Added

- Any number of named PostgreSQL, Prometheus and Loki connections in one server, with one tool set of 19 tools
  (`list_connections`, `connection_health`, nine `pg_*`, five `prom_*`, three `loki_*`).
- One YAML config file with `${ENV}` and `${file:...}` secret references and `ratatoskr check-config`.
- Groups and roles: effective access per connection is the highest grant of your groups, capped by the connection's
  `mode`; unknown and forbidden connections look the same.
- Streamable HTTP transport with Ratatoskr as OAuth 2.1 authorization server (dynamic client registration, PKCE,
  rotating refresh tokens with reuse detection, revocation), local argon2id users (`ratatoskr hash-password`) or
  OIDC sign-in (Authentik guide), rate-limited sign-in, and SQLite state in `/data`.
- Audit trail of every tool call and authentication event, in the JSON log and (over HTTP) in SQLite.
- Separate write role per PostgreSQL connection (`write_dsn`).
- Prometheus metrics on a separate listener (`server.metrics_port`): tool calls, latency, backend reachability,
  authentication events.
- `compose.yml` with Caddy (Let's Encrypt), `compose.dev.yml` with sample PostgreSQL, Prometheus and Loki data.
- Container image: non-root (uid 10001), read-only root file system, health check. The release workflow publishes
  it on version tags to `ghcr.io/keremkocatus/ratatoskr` for linux/amd64 and linux/arm64 with SBOM and provenance.
- CI: lint, types, unit and integration tests, image build and Trivy scan; Dependabot.
- Documentation: configuration reference, connectors, PostgreSQL roles, security model, security policy.

#### Changed

- Name: package `ratatoskr-mcp`, command `ratatoskr`, module `ratatoskr` (was `claude-postgresql`).
- PostgreSQL tools renamed and merged (`execute_select` is now `pg_query`, and so on; see `MIGRATION.md`).
- Read-only enforcement by PostgreSQL (read-only sessions and transactions that are always rolled back, extended
  protocol) instead of SQL pattern matching.

#### Removed

- `PG_MCP_*` environment variables and `.env` loading.
- The `sse` transport, the shared admin password and in-memory tokens.
- `allowed_tables`, the query history table, Railway support (`railway.json`) and the old `docker-compose.yml`.
```

- [ ] **Step 5: `MIGRATION.md`** (mapping checked against `git show e7aa8e3:src/claude_postgresql/config.py` and
  `server.py`, the last 0.1 commit)

````markdown
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
````

- [ ] **Step 6: Commit** — `Add connectors, security policy, contributing guide, changelog and migration guide`

### Task 18: Point the remaining docs at the new pages; test the docs set

**Files:**
- Modify: `docs/authentik.md`, `config.example.yaml`, `tests/unit/test_example_config.py`
- Test: `tests/unit/test_docs.py`

- [ ] **Step 1: Write the failing tests**

````python
"""The documentation set stays consistent with the code: links resolve, every setting and metric is documented once."""

import re
from pathlib import Path
from typing import get_args

import pytest
from pydantic import BaseModel

from ratatoskr.auth.events import AuthEventName
from ratatoskr.config.loki_models import LokiConnection
from ratatoskr.config.models import AuthSettings, PostgresConnection, ServerSettings
from ratatoskr.config.prometheus_models import PrometheusConnection

ROOT = Path(__file__).resolve().parents[2]
PAGES = sorted(
    [*(ROOT / name for name in ("README.md", "CHANGELOG.md", "CONTRIBUTING.md", "MIGRATION.md", "SECURITY.md"))]
    + list((ROOT / "docs").glob("*.md"))
)
CONFIGURATION = (ROOT / "docs" / "configuration.md").read_text(encoding="utf-8")
LINK_RE = re.compile(r"\[[^\]]*\]\((?!https?://|mailto:)([^)\s]+)\)")
CODE_BLOCK_RE = re.compile(r"```.*?```", re.DOTALL)


def _anchor(heading: str) -> str:
    """GitHub's heading anchor: lower case, punctuation dropped, spaces to hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")


def _anchors(page: Path) -> set[str]:
    text = CODE_BLOCK_RE.sub("", page.read_text(encoding="utf-8"))
    return {_anchor(line.lstrip("#")) for line in text.splitlines() if line.startswith("#")}


def test_the_documentation_set_is_complete() -> None:
    names = {page.relative_to(ROOT).as_posix() for page in PAGES}
    expected = {
        "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "MIGRATION.md", "SECURITY.md", "docs/authentik.md",
        "docs/configuration.md", "docs/connectors.md", "docs/postgres-roles.md", "docs/security-model.md",
    }  # fmt: skip
    assert expected <= names


@pytest.mark.parametrize("page", PAGES, ids=lambda page: page.relative_to(ROOT).as_posix())
def test_relative_links_resolve(page: Path) -> None:
    text = CODE_BLOCK_RE.sub("", page.read_text(encoding="utf-8"))
    for target in LINK_RE.findall(text):
        path, _, fragment = target.partition("#")
        resolved = (page.parent / path).resolve() if path else page
        assert resolved.exists(), f"{page.name}: {target} does not exist"
        if fragment and resolved.suffix == ".md":
            assert fragment in _anchors(resolved), f"{page.name}: {target} has no such heading"


def _fields(model: type[BaseModel]) -> list[str]:
    return list(model.model_fields)


@pytest.mark.parametrize(
    ("model", "prefix"),
    [(ServerSettings, "server."), (AuthSettings, "auth."), (PostgresConnection, "connections.<name>.")],
    ids=["server", "auth", "postgres"],
)
def test_every_setting_is_in_the_reference(model: type[BaseModel], prefix: str) -> None:
    missing = [field for field in _fields(model) if f"`{prefix}{field}" not in CONFIGURATION]
    assert missing == []


def _section(heading: str) -> str:
    start = CONFIGURATION.index(f"## {heading}\n")
    end = CONFIGURATION.find("\n## ", start + 1)
    return CONFIGURATION[start:end]


@pytest.mark.parametrize(
    ("model", "heading"),
    [(PrometheusConnection, "Prometheus connections"), (LokiConnection, "Loki connections")],
    ids=["prometheus", "loki"],
)
def test_every_connection_setting_is_in_its_section(model: type[BaseModel], heading: str) -> None:
    section = _section(heading)
    keys = [field for field in _fields(model) if field not in ("kind", "description", "limits")]
    limits = model.model_fields["limits"].annotation
    assert isinstance(limits, type) and issubclass(limits, BaseModel)
    keys += [f"limits.{field}" for field in _fields(limits)]
    assert [key for key in keys if f"`{key}`" not in section] == []


def test_metrics_section_names_every_series_and_auth_event() -> None:
    section = _section("Metrics")
    for series in ("ratatoskr_tool_calls_total", "ratatoskr_tool_duration_seconds", "ratatoskr_backend_up"):
        assert f"`{series}`" in section
    assert "`ratatoskr_auth_events_total`" in section
    assert [event for event in get_args(AuthEventName) if f"`{event}`" not in section] == []


def test_settings_live_only_in_the_reference() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "| `server." not in readme, "the settings tables belong in docs/configuration.md"
    for page in PAGES:
        assert "not implemented" not in page.read_text(encoding="utf-8"), page.name
````

```diff
diff --git a/tests/unit/test_example_config.py b/tests/unit/test_example_config.py
index ab85434..0ac27dd 100644
--- a/tests/unit/test_example_config.py
+++ b/tests/unit/test_example_config.py
@@ -126,3 +126,14 @@ def test_commented_http_example_is_valid(tmp_path: Path, monkeypatch: pytest.Mon
     assert (config.auth.oidc is not None) is oidc
     settings = check_http_preconditions(config, insecure_dev=False)
     assert settings.public_url == "https://mcp.example.com"
+
+
+def test_commented_metrics_example_is_valid(tmp_path: Path) -> None:
+    text = EXAMPLE.read_text(encoding="utf-8")
+    text = text.replace("  # metrics_port: 9100 ", "  metrics_port: 9100 ").replace(
+        "  # metrics_host: 127.0.0.1 ", "  metrics_host: 127.0.0.1 "
+    )
+    path = tmp_path / "config.yaml"
+    path.write_text(text, encoding="utf-8")
+    server = load_config(path, env={"APP_DB_DSN": "postgresql://reader:pw@localhost/app"}).server
+    assert (server.metrics_host, server.metrics_port) == ("127.0.0.1", 9100)
```

- [ ] **Step 2: Run** — `.venv/Scripts/python -m pytest tests/unit/test_docs.py tests/unit/test_example_config.py -q`;
  expected: the metrics example test fails (no commented metrics lines yet); fix any link the docs test reports.

- [ ] **Step 3: Edit the two files**

```diff
diff --git a/config.example.yaml b/config.example.yaml
index c1ee5c9..7bd80b1 100644
--- a/config.example.yaml
+++ b/config.example.yaml
@@ -8,6 +8,8 @@ server:
   transport: stdio            # stdio (local, Claude Desktop / Code) | streamable-http (remote, OAuth; see below)
   stdio_role: admins          # over stdio you act as a member of this group (see roles); unset = no access
   log_level: INFO             # DEBUG | INFO | WARNING | ERROR | CRITICAL; logs go to stderr as redacted JSON
+  # metrics_port: 9100        # Prometheus /metrics on a separate listener without auth (docs/configuration.md)
+  # metrics_host: 127.0.0.1   # keep loopback; 0.0.0.0 only in a container whose port stays internal
   # ── streamable-http only (set transport: streamable-http and uncomment the auth section below) ──
   # public_url: https://mcp.example.com   # origin only, https; the MCP endpoint is <public_url>/mcp
   # host: 0.0.0.0                         # 127.0.0.1 by default; 0.0.0.0 in a container
@@ -49,7 +51,7 @@ connections:
     kind: postgres            # PostgreSQL 12 or newer
     description: "Application database"
     mode: read                # read (default) | write; only write connections accept pg_execute
-    dsn: ${APP_DB_DSN}        # postgresql://user:password@host:5432/dbname -- use a restricted role (see README)
+    dsn: ${APP_DB_DSN}        # postgresql://user:password@host:5432/dbname -- a restricted role: docs/postgres-roles.md
     statement_timeout: 30s
     pool: { min_size: 1, max_size: 5 }   # write_max_size: 2 (lazy write pool, mode: write only)
     # allowed_schemas: [public]   # filters discovery tools only; NOT a security boundary (pg_query is not limited)
@@ -60,7 +62,7 @@ connections:
     #   cert_file: /config/certs/client.pem    # client certificate; set together with key_file
     #   key_file: /config/certs/client.key
 
-  # metrics:                    # Prometheus HTTP API: Prometheus, Mimir, Thanos Query, VictoriaMetrics (see README)
+  # metrics:                    # Prometheus HTTP API: Prometheus, Mimir, Thanos Query, VictoriaMetrics (docs/configuration.md)
   #   kind: prometheus          # always read-only (leave mode out); PromQL itself is not restricted
   #   description: "Production metrics"
   #   url: http://prometheus:9090   # API root (<url>/api/v1/...); for Mimir include its prefix: https://mimir/prometheus
@@ -74,7 +76,7 @@ connections:
   #   limits: { max_series: 100, max_values: 500, max_points: 1000, max_range: 31d, max_response_bytes: 65536 }
   #   # limits.max_body_bytes: 8388608 (8 MiB read per request; a call holds about 10x this while decoding)
 
-  # logs:                       # Loki HTTP API (see README; tested with Loki 3.7)
+  # logs:                       # Loki HTTP API (docs/configuration.md; tested with Loki 3.7)
   #   kind: loki                # always read-only (leave mode out); LogQL itself is not restricted
   #   description: "Production logs"
   #   url: http://loki:3100     # Loki root (<url>/loki/api/v1/...), or the URL of its gateway
@@ -96,4 +98,4 @@ connections:
   #   mode: write
   #   dsn: ${STAGING_DB_DSN}              # read pool login (a read-only role)
   #   write_dsn: ${STAGING_DB_WRITE_DSN}  # optional, mode: write only: write pool login (pg_execute and
-  #                                       # write-level EXPLAIN ANALYZE); recommended, see README "Security model"
+  #                                       # write-level EXPLAIN ANALYZE); recommended, see docs/postgres-roles.md
```

````diff
diff --git a/docs/authentik.md b/docs/authentik.md
index 4f19481..21aec1a 100644
--- a/docs/authentik.md
+++ b/docs/authentik.md
@@ -100,7 +100,10 @@ connections:
     dsn: ${PROD_PG_DSN}
 ```
 
-Run it with the image (state lives in `/data`, the config is read from `/config/config.yaml`):
+With [`compose.yml`](../compose.yml), put this `auth` section into `config.yaml` (keep the `server` section of
+[`deploy/config.example.yaml`](../deploy/config.example.yaml), whose `trusted_proxies` already names Caddy), add
+`OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` to `.env` and run `docker compose up -d`. Without compose, run the image
+(state lives in `/data`, the config is read from `/config/config.yaml`):
 
 ```bash
 docker run -d --name ratatoskr --read-only --restart unless-stopped \
@@ -118,11 +121,13 @@ unreadable, every session ends and all users must reconnect.
 
 ## 5. Reverse proxy (Caddy)
 
+[`deploy/Caddyfile`](../deploy/Caddyfile), used by `compose.yml`, does this already. For a Caddy of your own:
+
 ```caddyfile
 mcp.example.com {
     header Strict-Transport-Security "max-age=31536000; includeSubDomains"
-    @probes path /healthz /readyz
-    respond @probes 404
+    @internal path /healthz /readyz /metrics
+    respond @internal 404
     reverse_proxy ratatoskr:8000
 }
 ```
````

- [ ] **Step 4: Run** — expected: 25 passed.

- [ ] **Step 5: Commit** — `Link the docs set together and test it against the code`

### Task 19: Prepare the repository rename (one slug, nothing renamed)

**Files:**
- Modify: `pyproject.toml` (`[project.urls]`)
- Test: `tests/unit/test_repo_links.py`

Every place that names the GitHub repository after this task (`git grep -n "github.com/keremkocatus"` outside
`docs/superpowers/`): `pyproject.toml` (5 URLs), `Dockerfile` (`org.opencontainers.image.source`), `README.md`
(CI badge and `git clone`), `SECURITY.md` (advisory link), `CONTRIBUTING.md` (issues link). The image name
`ghcr.io/keremkocatus/ratatoskr` (CHANGELOG, `.env.example`) and the workflows (`${{ github.repository }}`,
`${{ github.repository_owner }}`) do not depend on the repository name. The historical plans and the spec under
`docs/superpowers/` keep their wording.

- [ ] **Step 1: Write the test**

```python
"""Every link to the GitHub repository uses one slug, so renaming the repository is one search-and-replace.

After the owner renames the repository on GitHub, replace REPO_SLUG's value everywhere (this file included):
    git grep -l "keremkocatus/claude-postgresql" -- ":!docs/superpowers" \
      | xargs sed -i "s#keremkocatus/claude-postgresql#keremkocatus/ratatoskr#g"
The image name does not depend on the repository name: it is always ghcr.io/<owner>/ratatoskr.
"""

import os
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPO_SLUG = "keremkocatus/claude-postgresql"
IMAGE = "ghcr.io/keremkocatus/ratatoskr"
SKIP_DIRS = {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", "__pycache__", "superpowers"}
SUFFIXES = {".md", ".toml", ".yml", ".yaml", ".py", ".txt", ".example", ""}
GITHUB_RE = re.compile(r"github\.com/keremkocatus/([A-Za-z0-9_.-]+)")
GHCR_RE = re.compile(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+")


def _files() -> list[Path]:
    found: list[Path] = []
    for directory, subdirectories, names in os.walk(ROOT):
        subdirectories[:] = [name for name in subdirectories if name not in SKIP_DIRS]
        found += [Path(directory) / name for name in names if Path(name).suffix in SUFFIXES]
    return found


def test_every_repository_link_uses_the_one_slug() -> None:
    repo = REPO_SLUG.split("/", 1)[1]
    seen = 0
    for path in _files():
        for name in GITHUB_RE.findall(path.read_text(encoding="utf-8", errors="replace")):
            seen += 1
            assert name.removesuffix(".git") == repo, f"{path.relative_to(ROOT)} links to keremkocatus/{name}"
    assert seen >= 5


def test_every_image_reference_uses_the_published_name() -> None:
    for path in _files():
        for image in GHCR_RE.findall(path.read_text(encoding="utf-8", errors="replace")):
            assert image == IMAGE, f"{path.relative_to(ROOT)} names {image}"


def test_project_urls_point_at_the_repository() -> None:
    urls = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["urls"]
    base = f"https://github.com/{REPO_SLUG}"
    assert urls["Repository"] == base
    assert all(url.startswith(base) for url in urls.values())
    assert f'org.opencontainers.image.source="{base}"' in (ROOT / "Dockerfile").read_text(encoding="utf-8")
```

- [ ] **Step 2: Run it** — expected: `test_project_urls_point_at_the_repository` fails until the URLs below exist
  (`Documentation`, `Issues`, `Changelog` keys are new); the other two pass.

- [ ] **Step 3: Implement**

```diff
diff --git a/pyproject.toml b/pyproject.toml
index f67479f..c3c68d7 100644
--- a/pyproject.toml
+++ b/pyproject.toml
@@ -42,8 +42,12 @@ dependencies = [
 ]
 
 [project.urls]
+# One slug everywhere (tests/unit/test_repo_links.py): renaming the repository is a single search-and-replace.
 Homepage = "https://github.com/keremkocatus/claude-postgresql"
 Repository = "https://github.com/keremkocatus/claude-postgresql"
+Documentation = "https://github.com/keremkocatus/claude-postgresql/blob/main/docs/configuration.md"
+Issues = "https://github.com/keremkocatus/claude-postgresql/issues"
+Changelog = "https://github.com/keremkocatus/claude-postgresql/blob/main/CHANGELOG.md"
 
 [project.scripts]
 ratatoskr = "ratatoskr.cli:main"
```

- [ ] **Step 4: Run** — expected: 3 passed.

- [ ] **Step 5: Commit** — `Keep every repository link on one slug for the coming rename`

### Task 20: CLAUDE.md

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Apply**

```diff
diff --git a/CLAUDE.md b/CLAUDE.md
index 036debb..a5528b9 100644
--- a/CLAUDE.md
+++ b/CLAUDE.md
@@ -6,7 +6,8 @@ Multi-connection MCP server (`src/ratatoskr`, PyPI `ratatoskr-mcp`, CLI `ratatos
 Current state: stdio (Plan 1a) and secure streamable-HTTP (Plan 1b: OAuth AS, local + OIDC identity, SQLite state,
 `Dockerfile`). Stage 2 adds Prometheus connections (`docs/superpowers/plans/2026-11-22-phase2-prometheus.md`),
 stage 3 Loki connections (`docs/superpowers/plans/2026-11-22-phase3-loki.md`).
-`docker-compose.yml` is still the old 0.1 one (compose, Caddy and CI are stage 4).
+Stage 4 (`docs/superpowers/plans/2026-11-22-phase4-packaging.md`) adds `/metrics` on a separate listener,
+`compose.yml` (Ratatoskr + Caddy), `compose.dev.yml` (sample PostgreSQL, Prometheus, Loki), CI and the docs set.
 
 ## Commands (Windows, repo root)
 
@@ -20,6 +21,12 @@ stage 3 Loki connections (`docs/superpowers/plans/2026-11-22-phase3-loki.md`).
 - Validate a config: `.venv/Scripts/ratatoskr check-config --config config.yaml` (`--insecure-dev` validates what
   `serve --insecure-dev` accepts)
 - Image: `docker build -t ratatoskr:dev .` (uid 10001, read-only root, writes only `/data`; local builds only)
+- Dev tools at CI's versions: `.venv/Scripts/python -m pip install -c constraints.txt -c constraints-dev.txt -e ".[dev]"`
+- Compose files: `docker compose -f compose.yml config --quiet` (needs `.env` and `config.yaml`; copy the
+  examples) and `docker compose -f compose.dev.yml config --quiet`; dev stack: `docker compose -f compose.dev.yml up -d`
+  (ports on 127.0.0.1 only), `... down -v` to remove it.
+- Workflows (cannot run locally): `docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:1.7.12`; image scan:
+  see `CONTRIBUTING.md` (Trivy).
 - Installing packages: pip's extra index on this machine is broken and slow; always pass
   `--index-url https://pypi.org/simple`.
 
@@ -51,7 +58,7 @@ remote or production database, Prometheus or Loki.
   routes (`web.py`), `identity/` (local argon2id, OIDC RP), `password_cli.py` (`hash-password`).
 - `state/` SQLite state store (`sqlite.py`, WAL, one connection + lock, `migrations.py`), audit sink, hourly
   cleanup. All OAuth/session state goes through the `Store` protocol; it stores hashes and sealed blobs only.
-- `transport/` HTTP composition root (`app.py`), preconditions (same checks for `serve` and `check-config`), client
+- `transport/` stdio composition root (`stdio.py`), HTTP composition root (`app.py`), preconditions (same checks for `serve` and `check-config`), client
   IP / trusted proxies, Host check, body and endpoint limits, client compatibility rewrites for `/revoke` and
   `/register` (`oauth_compat.py`), clean end of `/mcp` streams on shutdown (`stream_end.py`), uvicorn (`serve.py`).
 - `backends/` `Backend` protocol, `BackendRegistry` (lazy open, 10 s retry), user-safe errors, `clamp_text`,
@@ -73,7 +80,9 @@ remote or production database, Prometheus or Loki.
   (`streams.py`, `formatting.py`), tool logic (`querying.py`, `discovery.py`), registration (`tools.py`) and tool
   texts (`descriptions.py`).
 - `tools/runtime.py` the one wrapper every tool goes through; `tools/common.py` backend-independent tools.
-- `observability/` audit events and sinks, JSON logging, secret redaction.
+- `observability/` audit events and sinks, JSON logging, secret redaction; metrics: `metrics.py` (series and
+  bounded labels), `metrics_sink.py` (audit events -> metrics), `backend_probe.py` (`backend_up`, cached),
+  `metrics_http.py` + `metrics_server.py` (the separate listener), `metrics_service.py` (composition).
 - `app.py` builds the FastMCP app; `cli.py` is the entry point.
 - Tests: `tests/fakes.py` (fake config, backends, clock, audit sink), `tests/unit/`, `tests/integration/`;
   `tests/unit/prom_helpers.py` / `tests/unit/loki_helpers.py` with the `prom_api` / `loki_api` (respx) and
@@ -82,6 +91,10 @@ remote or production database, Prometheus or Loki.
   against the real Starlette app via `httpx.ASGITransport` in `tests/unit/secure_http/e2e/` (fake OIDC issuer via
   respx): they are unit tests, no network, no Docker.
 - `config.example.yaml` is the annotated config reference; `tests/unit/test_example_config.py` keeps it valid.
+- Packaging: `compose.yml`, `deploy/` (Caddyfile, compose config template), `compose.dev.yml`, `dev/` (seed SQL,
+  Prometheus, Loki, log generator, dev configs), `.github/` (CI, release, Dependabot); static checks in
+  `tests/unit/test_deploy_files.py`, `test_dev_stack_files.py`, `test_dockerfile.py`, `test_workflows.py`,
+  `test_docs.py`, `test_repo_links.py`.
 
 ## Rules
 
@@ -147,5 +160,12 @@ remote or production database, Prometheus or Loki.
   back, when to use the tool, the limits, and that `connection` comes from `list_connections`.
 - Tests: unit tests must not touch the network or Docker (use `tests/fakes.py`). Anything that needs a real
   PostgreSQL goes in `tests/integration/` with `pytestmark = pytest.mark.integration`.
-- Docs must describe what the code does now; do not document unimplemented config as working.
+- Docs must describe what the code does now; do not document unimplemented config as working. Settings are
+  documented once, in `docs/configuration.md` (`tests/unit/test_docs.py` checks every model field is there and
+  that links resolve); the README links to it.
+- Metrics: every count comes from the audit event (`MetricsAuditSink`); never call `Metrics` from tools. Labels
+  are bounded: `connection` only through `Metrics.connection_label` (configured names, `_all`, `_unresolved`),
+  never a subject, query, secret or a name a caller typed. `/metrics` never goes on the MCP port.
+- GitHub: actions pinned by commit SHA with a `# vX.Y.Z` comment, `permissions: contents: read` at the top, only
+  `GITHUB_TOKEN`. Repository links use the one slug in `tests/unit/test_repo_links.py`.
 - Commits: imperative subject line; end the message with the agreed `Co-Authored-By` trailer.
```

- [ ] **Step 2: Commit** — `Describe stage 4 in the conventions`

### Task 21: Final verification

- [ ] `.venv/Scripts/python -m pytest -q` — expect 1874 passed, 4 skipped (Windows).
- [ ] `.venv/Scripts/python -m pytest -m integration -q` — expect 174 passed (Docker Desktop running).
- [ ] `.venv/Scripts/python -m ruff check src tests`, `ruff format --check src tests`, `mypy src` — clean.
- [ ] `docker build -t ratatoskr:dev .`, the smoke commands and the Trivy scan of Task 11 — exit 0.
- [ ] actionlint (Task 15) — exit 0.
- [ ] `docker compose -f compose.yml config --quiet` (with example `.env`/`config.yaml` copied, then removed) and
      `docker compose -f compose.dev.yml config --quiet`.
- [ ] Optional: the dev stack session of Task 13 and the local `compose.yml` run of Task 12.
- [ ] Clean up: `docker compose -f compose.dev.yml down -v`, `docker compose -f compose.yml down -v`,
      `docker image rm ratatoskr:dev ratatoskr:local` (keep the build cache); no `.env`, `config.yaml` or `.dev/`
      left in the tree (`git status` clean).
- [ ] Ask for the branch review (`superpowers:requesting-code-review`), then the owner actions below.

## Risks

- **First CI run is the real test of the workflows.** actionlint, the policy test and a Linux run of the lint and
  unit commands passed, but GitHub runners were never used: expect to fix small things (runner image, Docker
  permissions for Trivy's socket mount, testcontainers on Ubuntu) in the first PR.
- **Trivy needs its vulnerability DB** from `ghcr.io/aquasecurity/trivy-db` at every run; rate limits have broken
  such jobs before. Mitigation if it happens: add `--db-repository public.ecr.aws/aquasecurity/trivy-db` (or cache
  the DB). A new fixed HIGH/CRITICAL in the base image fails CI until the image is rebuilt (by design).
- **`apt-get upgrade`** makes image builds depend on the build date; a broken Debian update would break the build.
- **`backend_up` opens every connection** once metrics are on (failed opens are logged as warnings by the registry
  every 10 s while scrapes continue). Documented; an operator who does not want that leaves metrics off.
- **`disable_created_metrics()`** is process-wide (fine for this server; a test environment importing another
  prometheus-client user would see no `_created` series either).
- **stdio metrics port clashes** when several stdio clients share a config (documented: the second process exits).
- **Compose requirements:** `env_file` with `required:` needs Compose 2.24+; `docker compose run --use-aliases`
  is needed for the dev Prometheus to see a stdio run.
- **Subnet collisions:** `10.203.53.0/24` may collide with a routed corporate network; `RATATOSKR_SUBNET` and
  `RATATOSKR_PROXY_IP` override it (both together).
- **Dependabot coverage is partly unverified:** whether it updates `constraints.txt` / `constraints-dev.txt`
  (pip) and `compose*.yml` image digests (docker-compose ecosystem) shows only after the first weekly run; the
  manual refresh in `CLAUDE.md` stays the fallback.
- **Client UIs** (claude.ai connector settings, Claude Desktop menus) are not under test; `docs/connectors.md`
  marks them as manual checks.
- **Action SHAs** were resolved on 2026-11-22; re-resolve if the plan is executed much later (Task 15 Step 3).

## Owner actions (not part of the implementation; need the repository owner)

- [ ] Review and merge `feature/packaging`.
- [ ] **Rename the repository** on GitHub to `ratatoskr` (*Settings → General → Repository name*). Then, in a
      checkout: `git remote set-url origin https://github.com/keremkocatus/ratatoskr.git`, run the one-liner from the
      docstring of `tests/unit/test_repo_links.py`
      (`git grep -l "keremkocatus/claude-postgresql" -- ":!docs/superpowers" | xargs sed -i "s#keremkocatus/claude-postgresql#keremkocatus/ratatoskr#g"`),
      run `pytest tests/unit/test_repo_links.py tests/unit/test_docs.py -q`, commit
      `Point links at the renamed repository` and open a PR. GitHub redirects the old URLs meanwhile.
- [ ] **Enable private vulnerability reporting** (*Settings → Code security → Private vulnerability reporting →
      Enable*); `SECURITY.md` links to it. Optionally enable Dependabot alerts and security updates there too.
- [ ] **Actions settings** (*Settings → Actions → General*): workflow permissions "Read repository contents and
      packages permissions" (the workflows request `packages: write` themselves); require approval for workflows
      from first-time contributors; optionally allow only actions pinned by SHA.
- [ ] **Branch protection** for `main`: require the CI jobs (ruff/format/mypy, unit 3.12 and 3.13, integration,
      compose files, image build and Trivy scan).
- [ ] **First release:** set `__version__ = "1.0.0"` in `src/ratatoskr/__init__.py`, move the `CHANGELOG.md` notes to
      `## [1.0.0] - <date>`, update the README status line and (optionally) the `Development Status` classifier,
      merge, then `git tag v1.0.0 && git push origin v1.0.0`. The release workflow runs CI, checks the tag, scans and
      pushes `ghcr.io/keremkocatus/ratatoskr:1.0.0`, `:1.0` and `:1`.
- [ ] **GHCR package visibility:** the first push creates a private package. In *Packages → ratatoskr → Package
      settings*: change visibility to **Public**, and connect it to the repository if it is not linked already. Check
      anonymously: `docker logout ghcr.io; docker pull ghcr.io/keremkocatus/ratatoskr:1.0.0` and
      `docker buildx imagetools inspect ghcr.io/keremkocatus/ratatoskr:1.0.0` (two platforms, attestation manifests).
- [ ] After the release, set `RATATOSKR_IMAGE=ghcr.io/keremkocatus/ratatoskr:1.0.0` in your own `.env` and do the
      manual connector checks in `docs/connectors.md` and the Authentik checklist in `docs/authentik.md`.
