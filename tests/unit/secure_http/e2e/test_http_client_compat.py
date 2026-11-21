"""What real MCP clients send: public clients (Claude Code), revocation without a secret, scopes we do not know."""

from __future__ import annotations

import sqlite3
from urllib.parse import parse_qs, urlsplit

import pytest

from ratatoskr.transport.app import build_http_app
from ratatoskr.transport.body_limit import MAX_AUTH_BODY_BYTES

PUBLIC_URL = "https://mcp.example.com"


@pytest.fixture
def http_app(make_config):
    return build_http_app(make_config())


def audit_tools(tmp_path) -> list[str]:
    with sqlite3.connect(tmp_path / "state.db") as raw:
        return [row[0] for row in raw.execute("SELECT tool FROM audit_events ORDER BY id")]


# ── public clients and /revoke ──────────────────────────────────────────────


@pytest.mark.parametrize("revoked", ["refresh_token", "access_token"])
async def test_public_client_full_flow_and_revoke_ends_the_family(http_app, run_app, tmp_path, revoked) -> None:
    async with run_app(http_app) as driver:
        registered = await driver.register(auth_method="none")
        assert registered.status_code == 201, registered.text
        assert "client_secret" not in registered.json()
        assert driver.client_secret == ""

        tokens = await driver.exchange(await driver.login_for_code())
        session = await driver.open_session(tokens["access_token"])
        assert "prod-pg" in await driver.tool_text(tokens["access_token"], session, "list_connections")
        refreshed = await driver.refresh(tokens["refresh_token"])
        assert refreshed.status_code == 200, refreshed.text
        current = refreshed.json()

        response = await driver.revoke(current[revoked])
        assert response.status_code == 200, response.text
        assert (await driver.call_tool(current["access_token"], session, "list_connections")).status_code == 401
        assert (await driver.refresh(current["refresh_token"])).status_code == 400
    assert "token_revoked" in audit_tools(tmp_path)


@pytest.mark.parametrize("auth_method", ["client_secret_post", "client_secret_basic"])
async def test_confidential_clients_revoke_with_their_secret(http_app, run_app, auth_method) -> None:
    async with run_app(http_app) as driver:
        assert (await driver.register(auth_method=auth_method)).status_code == 201
        assert driver.client_secret
        tokens = await driver.exchange(await driver.login_for_code())
        assert (await driver.revoke(tokens["refresh_token"])).status_code == 200
        assert (await driver.refresh(tokens["refresh_token"])).status_code in (400, 401)
        assert (await driver.mcp_post(tokens["access_token"], driver.rpc("tools/list"))).status_code == 401


async def test_confidential_client_cannot_revoke_without_its_secret(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        tokens = await driver.exchange(await driver.login_for_code())
        response = await driver.http.post(
            "/revoke", data={"token": tokens["refresh_token"], "client_id": driver.client_id}
        )
        assert response.status_code == 401
        wrong = await driver.http.post(
            "/revoke",
            data={"token": tokens["refresh_token"], "client_id": driver.client_id, "client_secret": "wrong"},
        )
        assert wrong.status_code == 401
        # The family survives both attempts.
        assert (await driver.refresh(tokens["refresh_token"])).status_code == 200


async def test_public_client_cannot_revoke_another_clients_tokens(http_app, run_app) -> None:
    async with run_app(http_app) as victim:
        await victim.register()
        tokens = await victim.exchange(await victim.login_for_code())
        async with victim.spawn("198.51.100.20") as attacker:
            await attacker.register(auth_method="none")
            assert (await attacker.revoke(tokens["refresh_token"])).status_code == 200  # RFC 7009: no oracle
        assert (await victim.refresh(tokens["refresh_token"])).status_code == 200


async def test_revoke_body_limit_still_applies(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register(auth_method="none")
        response = await driver.http.post(
            "/revoke",
            content=b"token=" + b"a" * MAX_AUTH_BODY_BYTES + b"&client_id=" + driver.client_id.encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert response.status_code == 413


# ── scopes ──────────────────────────────────────────────────────────────────


async def test_metadata_advertises_the_mcp_scope(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        server = (await driver.http.get("/.well-known/oauth-authorization-server")).json()
        resource = (await driver.http.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert server["scopes_supported"] == ["mcp"]
    assert resource["scopes_supported"] == ["mcp"]


@pytest.mark.parametrize("requested", ["claudeai", "openid profile offline_access", "mcp admin"])
async def test_registration_replaces_requested_scopes_with_mcp(http_app, run_app, requested) -> None:
    async with run_app(http_app) as driver:
        response = await driver.register(auth_method="none", scope=requested)
        assert response.status_code == 201, response.text
        assert response.json()["scope"] == "mcp"
        stored = await http_app.provider.get_client(driver.client_id)
    assert stored is not None and stored.scope == "mcp"


async def test_registration_without_scope_gets_mcp(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        response = await driver.register()
    assert response.status_code == 201 and response.json()["scope"] == "mcp"


@pytest.mark.parametrize("requested", ["claudeai", "openid profile offline_access", "mcp"])
async def test_authorize_with_unknown_scopes_grants_mcp(http_app, run_app, requested) -> None:
    async with run_app(http_app) as driver:
        await driver.register(auth_method="none", scope="claudeai")
        _, request_id, csrf = await driver.open_login(await driver.authorize(scope=requested))
        redirect = await driver.submit_login(request_id, csrf, "kerem", driver.PASSWORD)
        assert redirect.status_code == 302, redirect.text
        tokens = await driver.exchange(driver.code_from(redirect.headers["location"]))
        assert tokens["scope"] == "mcp"
        session = await driver.open_session(tokens["access_token"])
        assert "prod-pg" in await driver.tool_text(tokens["access_token"], session, "list_connections")
        refreshed = await driver.refresh(tokens["refresh_token"])
    assert refreshed.status_code == 200 and refreshed.json()["scope"] == "mcp"


async def test_authorize_still_caps_the_number_of_scopes(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        response = await driver.http.get("/authorize", params=driver.authorize_params(scope="a b c d e"))
    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["location"]).query)
    assert query["error"] == ["invalid_request"] and query["state"] == ["claude-state"]
