"""OIDC mode end to end: our /login redirects to the fake issuer, /oauth/callback finishes, refresh re-validates.

Callback attacks that Task 13 already pins are not repeated here (see ``test_http_guards.py``,
``test_oidc_flow_cookie_is_lax_bound_to_the_request_and_single_use``): the Lax flow cookie and its flags, a callback
without the flow cookie (another browser) or with a forged one, a state that does not match the cookie (never reaching
the issuer), and single use of the pending request.
"""

from __future__ import annotations

import sqlite3
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from ratatoskr.transport.app import build_http_app

CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def http_app(make_config, fake_issuer, clock):
    return build_http_app(make_config(mode="oidc"), clock=clock)


async def start_oidc_login(driver, fake_issuer) -> tuple[str, str]:
    """Returns (state, nonce) that our server sent to the issuer."""
    login = await driver.http.get(await driver.authorize())
    assert login.status_code == 302
    location = login.headers["location"]
    assert location.startswith(fake_issuer.authorization_endpoint + "?")
    query = {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}
    assert query["redirect_uri"] == "https://mcp.example.com/oauth/callback"
    assert query["code_challenge_method"] == "S256"
    assert "samesite=lax" in login.headers["set-cookie"].lower()
    return query["state"], query["nonce"]


async def sign_in(driver, fake_issuer, groups: list[str]) -> dict[str, Any]:
    await driver.register()
    state, nonce = await start_oidc_login(driver, fake_issuer)
    fake_issuer.queue_token_response(
        id_token=fake_issuer.id_token(nonce=nonce, groups=groups),
        access_token="up-a",
        refresh_token="up-r1",
        token_type="Bearer",
    )
    callback = await driver.http.get("/oauth/callback", params={"code": "upstream-code", "state": state})
    assert callback.status_code == 302, callback.text
    assert fake_issuer.form()["code_verifier"]
    return await driver.exchange(driver.code_from(callback.headers["location"]))


async def test_oidc_login_refresh_and_offboarding(http_app, run_app, fake_issuer) -> None:
    async with run_app(http_app) as driver:
        tokens = await sign_in(driver, fake_issuer, ["admins"])
        session = await driver.open_session(tokens["access_token"])
        assert "staging-pg" in await driver.tool_text(tokens["access_token"], session, "list_connections")

        # Our refresh re-validates upstream: the issuer now reports other groups, so the policy narrows.
        fake_issuer.queue_token_response(
            id_token=fake_issuer.id_token(groups=["analyst"]), refresh_token="up-r2", token_type="Bearer"
        )
        refreshed = await driver.refresh(tokens["refresh_token"])
        assert refreshed.status_code == 200, refreshed.text
        upstream = fake_issuer.form()
        assert upstream["grant_type"] == "refresh_token" and upstream["refresh_token"] == "up-r1"
        new = refreshed.json()
        listing = await driver.tool_text(new["access_token"], session, "list_connections")
        assert "prod-pg" in listing and "staging-pg" not in listing

        # Offboarded upstream: the next refresh fails and the session's access token stops working.
        fake_issuer.queue_token_response(400, error="invalid_grant")
        rejected = await driver.refresh(new["refresh_token"])
        assert fake_issuer.form()["refresh_token"] == "up-r2"
        assert rejected.status_code == 400 and rejected.json()["error"] == "invalid_grant"
        assert (await driver.call_tool(new["access_token"], session, "list_connections")).status_code == 401

        # The session is gone for good: trying the same refresh token again fails without asking the issuer.
        upstream_calls = len(fake_issuer.token_requests)
        again = await driver.refresh(new["refresh_token"])
        assert again.status_code == 400 and again.json()["error"] == "invalid_grant"
        assert len(fake_issuer.token_requests) == upstream_calls


async def test_forged_state_is_rejected_without_reaching_the_issuer(http_app, run_app, fake_issuer) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        await start_oidc_login(driver, fake_issuer)
        response = await driver.http.get("/oauth/callback", params={"code": "c", "state": "attacker-state"})
    assert response.status_code == 400
    assert fake_issuer.token_requests == []


async def test_issuer_error_is_relayed_as_access_denied(http_app, run_app, fake_issuer) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        state, _ = await start_oidc_login(driver, fake_issuer)
        response = await driver.http.get("/oauth/callback", params={"error": "access_denied", "state": state})
        # The pending request is consumed: the same callback cannot be replayed with a code.
        replay = await driver.http.get("/oauth/callback", params={"code": "c", "state": state})
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(CLIENT_REDIRECT + "?")
    query = parse_qs(urlsplit(location).query)
    assert query["error"] == ["access_denied"] and query["state"] == ["claude-state"]
    assert "code" not in query
    assert replay.status_code == 400
    assert fake_issuer.token_requests == []


def login_failures(tmp_path) -> list[tuple[str, str, str]]:
    with sqlite3.connect(tmp_path / "state.db") as raw:
        rows = raw.execute(
            "SELECT tool, result, error_class FROM audit_events WHERE tool = 'login_failed' ORDER BY id"
        ).fetchall()
    return [tuple(row) for row in rows]


async def test_bad_id_token_fails_the_sign_in(http_app, run_app, fake_issuer, tmp_path) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        state, _ = await start_oidc_login(driver, fake_issuer)
        fake_issuer.queue_token_response(
            id_token=fake_issuer.id_token(nonce="replayed-nonce"), access_token="up-a", token_type="Bearer"
        )
        response = await driver.http.get("/oauth/callback", params={"code": "c", "state": state})
    assert response.status_code == 400
    assert "location" not in response.headers
    assert len(fake_issuer.token_requests) == 1
    assert login_failures(tmp_path) == [("login_failed", "denied", "identity_invalid")]


async def test_issuer_refusing_the_code_is_a_denied_sign_in(http_app, run_app, fake_issuer, tmp_path) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        state, _ = await start_oidc_login(driver, fake_issuer)
        fake_issuer.queue_token_response(400, error="invalid_grant")
        response = await driver.http.get("/oauth/callback", params={"code": "c", "state": state})
    assert response.status_code == 400
    assert login_failures(tmp_path) == [("login_failed", "denied", "upstream_rejected")]


async def test_unreachable_issuer_at_the_callback_is_an_error_not_a_denial(
    http_app, run_app, fake_issuer, tmp_path
) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        state, _ = await start_oidc_login(driver, fake_issuer)
        fake_issuer.queue_token_response(503)
        response = await driver.http.get("/oauth/callback", params={"code": "c", "state": state})
    assert response.status_code == 502
    assert "could not be reached" in response.text
    assert login_failures(tmp_path) == [("login_failed", "error", "upstream_unavailable")]


async def test_password_form_is_disabled_in_oidc_mode(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        response = await driver.http.post("/login", data={"request": "x", "username": "a", "password": "b"})
    assert response.status_code == 404
