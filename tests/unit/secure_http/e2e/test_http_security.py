"""Security properties of the HTTP surface (spec §10 "Güvenlik").

Cases that Task 13's e2e tests already pin are not repeated here (see ``test_http_guards.py``):

- wrong Host with a token on ``/mcp`` → 421: ``test_mcp_keeps_the_sdk_dns_rebinding_check``
- wrong password lockout → 429 + ``Retry-After``: ``test_login_lockout_returns_429_with_retry_after_and_audits``
- lockout per IP and per username: ``test_user_lockout_covers_every_spelling_of_the_name_from_any_ip`` (user key,
  any IP; other users unaffected) and ``test_ip_lockout_groups_ipv6_clients_by_their_64_network`` (IP key, any user;
  other networks unaffected)
- DCR rate limit: ``test_parallel_registration_burst_from_one_ip_is_capped``
- forged CSRF token, CSRF checked first: ``test_csrf_is_checked_before_the_pending_request_and_the_rate_limit``
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from ratatoskr.transport.app import build_http_app

CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PASSWORD = "correct horse battery staple"


@pytest.fixture
def http_app(make_config):
    return build_http_app(make_config())


async def test_disallowed_redirect_uri_is_rejected_at_registration(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        foreign = await driver.register("https://evil.example/callback")
        insecure = await driver.register("http://claude.ai/api/mcp/auth_callback")
    assert foreign.status_code == 400 and foreign.json()["error"] == "invalid_redirect_uri"
    assert insecure.status_code == 400 and insecure.json()["error"] == "invalid_redirect_uri"


@pytest.mark.parametrize("overrides", [{"code_challenge": None}, {"code_challenge_method": "plain"}])
async def test_authorize_without_s256_pkce_is_rejected(http_app, run_app, overrides) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        response = await driver.http.get("/authorize", params=driver.authorize_params(**overrides))
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(CLIENT_REDIRECT)
    query = parse_qs(urlsplit(location).query)
    assert query["error"] == ["invalid_request"]
    assert "code" not in query


async def test_authorize_for_another_resource_is_rejected(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        params = driver.authorize_params(resource="https://other.example.com/mcp")
        response = await driver.http.get("/authorize", params=params)
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith(CLIENT_REDIRECT)
    query = parse_qs(urlsplit(location).query)
    assert query["error"] == ["invalid_request"]
    assert "code" not in query


async def test_login_post_without_csrf_token_or_cookie_is_rejected(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        no_token = await driver.submit_login(request_id, "", "kerem", PASSWORD)
        cookies = dict(driver.http.cookies.items())
        driver.http.cookies.clear()
        no_cookie = await driver.submit_login(request_id, csrf, "kerem", PASSWORD)
        for name, value in cookies.items():
            driver.http.cookies.set(name, value, domain="mcp.example.com")
        # Neither refused post consumed the pending request: the intact form still signs in.
        ok = await driver.submit_login(request_id, csrf, "kerem", PASSWORD)
    assert no_token.status_code == 403
    assert no_cookie.status_code == 403
    assert "location" not in no_token.headers and "location" not in no_cookie.headers
    assert ok.status_code == 302


async def test_csrf_token_is_bound_to_its_request(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        _, first_request, first_csrf = await driver.open_login(await driver.authorize())
        _, second_request, _ = await driver.open_login(await driver.authorize())
        response = await driver.submit_login(second_request, first_csrf, "kerem", PASSWORD)
    assert first_request != second_request
    assert response.status_code == 403
    assert "location" not in response.headers


async def test_request_without_a_valid_token_gets_401(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        missing = await driver.mcp_post(None, driver.rpc("tools/list"))
        bogus = await driver.mcp_post("not-a-real-token", driver.rpc("tools/list"))
    assert missing.status_code == 401
    assert (
        'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
        in missing.headers["www-authenticate"]
    )
    assert bogus.status_code == 401


async def test_foreign_origin_is_rejected_by_dns_rebinding_protection(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        tokens = await driver.exchange(await driver.login_for_code())
        bad_origin = await driver.mcp_post(
            tokens["access_token"], driver.rpc("tools/list"), headers={"Origin": "https://attacker.example"}
        )
    assert bad_origin.status_code == 403


async def test_invalid_login_link_shows_a_framing_protected_error_page(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        response = await driver.http.get("/login?request=does-not-exist")
    assert response.status_code == 400
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert response.headers["x-content-type-options"] == "nosniff"
