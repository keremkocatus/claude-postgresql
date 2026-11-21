"""DCR → authorize → login → code → token → MCP tool call → refresh → revoke, against the real app."""

from __future__ import annotations

import asyncio
import logging
import sqlite3

import pytest

from ratatoskr.observability.health import READY_CACHE_SECONDS, HealthRoutes
from ratatoskr.transport.app import build_http_app
from tests.unit.secure_http.conftest import SECRET_KEY

PUBLIC_URL = "https://mcp.example.com"
CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PASSWORD = "correct horse battery staple"


@pytest.fixture
def http_app(make_config):
    return build_http_app(make_config())


def audit_rows(tmp_path) -> list[tuple[str, str, str]]:
    with sqlite3.connect(tmp_path / "state.db") as raw:
        return [tuple(row) for row in raw.execute("SELECT tool, subject, result FROM audit_events ORDER BY id")]


async def test_metadata_is_published(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        server = (await driver.http.get("/.well-known/oauth-authorization-server")).json()
        resource = (await driver.http.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert server["issuer"] == PUBLIC_URL + "/"
    assert server["registration_endpoint"] == PUBLIC_URL + "/register"
    assert server["revocation_endpoint"] == PUBLIC_URL + "/revoke"
    assert server["code_challenge_methods_supported"] == ["S256"]
    assert resource["resource"] == PUBLIC_URL + "/mcp"


async def test_full_local_flow(http_app, run_app, tmp_path) -> None:
    async with run_app(http_app) as driver:
        assert (await driver.register()).status_code == 201

        login_url = await driver.authorize()
        assert login_url.startswith(PUBLIC_URL + "/login?request=")
        page, request_id, csrf = await driver.open_login(login_url)
        assert "Claude" in page.text and "claude.ai" in page.text
        csp = page.headers["content-security-policy"]
        assert "frame-ancestors 'none'" in csp and "form-action 'self' https://claude.ai" in csp
        assert page.headers["x-content-type-options"] == "nosniff"
        assert page.headers["referrer-policy"] == "no-referrer"
        assert "samesite=strict" in page.headers["set-cookie"].lower()

        redirect = await driver.submit_login(request_id, csrf, "kerem", PASSWORD)
        assert redirect.status_code == 302
        assert redirect.headers["location"].startswith(CLIENT_REDIRECT + "?")
        tokens = await driver.exchange(driver.code_from(redirect.headers["location"]))
        assert tokens["token_type"] == "Bearer" and tokens["expires_in"] == 3600

        session = await driver.open_session(tokens["access_token"])
        listing = await driver.tool_text(tokens["access_token"], session, "list_connections")
        assert "prod-pg" in listing and "staging-pg" in listing

        refreshed = await driver.refresh(tokens["refresh_token"])
        assert refreshed.status_code == 200, refreshed.text
        new = refreshed.json()
        assert new["refresh_token"] != tokens["refresh_token"]
        old_call = await driver.call_tool(tokens["access_token"], session, "list_connections")
        assert old_call.status_code == 401
        assert "prod-pg" in await driver.tool_text(new["access_token"], session, "list_connections")

        assert (await driver.revoke(new["refresh_token"])).status_code == 200
        assert (await driver.call_tool(new["access_token"], session, "list_connections")).status_code == 401
        assert (await driver.refresh(new["refresh_token"])).status_code == 400

    rows = audit_rows(tmp_path)
    assert ("login_succeeded", "kerem", "ok") in rows
    assert rows.count(("list_connections", "kerem", "ok")) == 2
    assert ("token_revoked", "kerem", "ok") in rows
    names = [tool for tool, _, _ in rows]
    assert names.index("login_succeeded") < names.index("list_connections") < names.index("token_revoked")


async def test_policy_filters_connections_per_user(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        tokens = await driver.exchange(await driver.login_for_code("ayse"))
        session = await driver.open_session(tokens["access_token"])
        listing = await driver.tool_text(tokens["access_token"], session, "list_connections")
    assert "prod-pg" in listing and "staging-pg" not in listing


async def test_authorization_code_is_single_use(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        code = await driver.login_for_code()
        await driver.exchange(code)
        again = await driver.token(
            grant_type="authorization_code", code=code, redirect_uri=CLIENT_REDIRECT, code_verifier=driver.verifier
        )
    assert again.status_code == 400 and again.json()["error"] == "invalid_grant"


async def test_wrong_pkce_verifier_is_rejected(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        code = await driver.login_for_code()
        response = await driver.token(
            grant_type="authorization_code", code=code, redirect_uri=CLIENT_REDIRECT, code_verifier="w" * 64
        )
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"


async def test_refresh_token_reuse_revokes_the_session(make_config, run_app, clock) -> None:
    # A replay inside the 5 s retry grace is refused without revoking (provider tests cover it); the fake clock
    # moves past the grace window so the replay counts as reuse.
    async with run_app(build_http_app(make_config(), clock=clock)) as driver:
        await driver.register()
        tokens = await driver.exchange(await driver.login_for_code())
        new = (await driver.refresh(tokens["refresh_token"])).json()
        clock.advance(30)
        replay = await driver.refresh(tokens["refresh_token"])
        assert replay.status_code == 400 and replay.json()["error"] == "invalid_grant"
        response = await driver.mcp_post(new["access_token"], driver.rpc("tools/list"))
    assert response.status_code == 401


async def test_health_endpoints(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        health = await driver.http.get("/healthz")
        ready = await driver.http.get("/readyz")
    assert health.status_code == 200 and health.json() == {"status": "ok"}
    assert ready.status_code == 200 and ready.json() == {"status": "ready"}
    assert health.headers["cache-control"] == "no-store"


async def test_readyz_reports_an_unwritable_store(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await http_app.store.close()
        ready = await driver.http.get("/readyz")
        health = await driver.http.get("/healthz")
    assert ready.status_code == 503 and ready.json() == {"status": "unavailable"}
    assert health.status_code == 200


async def test_audit_events_are_persisted(make_config, run_app, tmp_path) -> None:
    async with run_app(build_http_app(make_config())) as driver:
        await driver.register()
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        await driver.submit_login(request_id, csrf, "kerem", "wrong-password")
    assert ("login_failed", "kerem", "denied") in audit_rows(tmp_path)


async def test_no_secrets_reach_the_logs(http_app, run_app, caplog, password_hash) -> None:
    caplog.set_level(logging.DEBUG)
    async with run_app(http_app) as driver:
        await driver.register()
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        failed = await driver.submit_login(request_id, csrf, "kerem", "wrong-" + PASSWORD)
        assert failed.status_code == 401
        code = await driver.login_for_code()
        tokens = await driver.exchange(code)
        session = await driver.open_session(tokens["access_token"])
        await driver.tool_text(tokens["access_token"], session, "list_connections")
        refreshed = (await driver.refresh(tokens["refresh_token"])).json()
        await driver.revoke(refreshed["access_token"])
        secrets = [
            PASSWORD,
            "wrong-" + PASSWORD,
            password_hash,
            SECRET_KEY,
            csrf,
            code,
            tokens["access_token"],
            tokens["refresh_token"],
            refreshed["access_token"],
            refreshed["refresh_token"],
            driver.client_secret,
        ]
    assert caplog.records, "the flow is expected to log something"
    leaked = [s for s in secrets if s in caplog.text]
    assert leaked == []


class CountingStore:
    def __init__(self) -> None:
        self.checks = 0
        self.fail = False

    async def check_writable(self) -> None:
        self.checks += 1
        await asyncio.sleep(0.01)
        if self.fail:
            raise RuntimeError("disk full")


async def test_readiness_is_checked_at_most_once_per_cache_period(clock) -> None:
    store = CountingStore()
    health = HealthRoutes(store, clock=clock)  # type: ignore[arg-type]
    answers = await asyncio.gather(*(health.readyz(None) for _ in range(50)))  # type: ignore[arg-type]
    assert {a.status_code for a in answers} == {200}
    assert store.checks == 1, "a flood of probes must not queue up on the store writer"

    store.fail = True
    clock.advance(READY_CACHE_SECONDS - 0.5)
    assert (await health.readyz(None)).status_code == 200  # type: ignore[arg-type]
    clock.advance(1.0)
    assert (await health.readyz(None)).status_code == 503  # type: ignore[arg-type]
    assert (await health.readyz(None)).status_code == 503  # type: ignore[arg-type]
    assert store.checks == 2
