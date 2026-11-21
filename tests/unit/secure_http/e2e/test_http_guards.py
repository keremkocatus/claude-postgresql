"""Task 13 guards on the composed app: Host check, body limits, DCR / authorize / login rate limits, CSRF order,
cookie flags and the OIDC flow cookie."""

from __future__ import annotations

import asyncio
import re
import sqlite3
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from pydantic import AnyHttpUrl

from ratatoskr.auth.ratelimit import LOGIN_RULE, REGISTER_RULE
from ratatoskr.transport.app import build_http_app
from ratatoskr.transport.body_limit import MAX_AUTH_BODY_BYTES
from ratatoskr.transport.endpoint_limit import AUTHORIZE_RULE
from tests.unit.secure_http.e2e.conftest import OAuthDriver

PASSWORD = "correct horse battery staple"
CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def http_app(make_config, clock):
    return build_http_app(make_config(), clock=clock)


def audit_rows(tmp_path) -> list[tuple[str, str, str, str]]:
    with sqlite3.connect(tmp_path / "state.db") as raw:
        rows = raw.execute("SELECT tool, subject, auth_source, result FROM audit_events ORDER BY id").fetchall()
    return [tuple(row) for row in rows]


# ── Host check ──────────────────────────────────────────────────────────────


async def test_login_post_with_a_foreign_host_is_refused(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        response = await driver.http.post(
            "/login",
            data={"request": request_id, "csrf_token": csrf, "username": "kerem", "password": PASSWORD},
            headers={"Host": "evil.example"},
        )
        assert response.status_code == 421
        # The refused request consumed nothing: the same form still signs in from the right host.
        ok = await driver.submit_login(request_id, csrf, "kerem", PASSWORD)
    assert ok.status_code == 302


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/login?request=x"),
        ("GET", "/authorize"),
        ("POST", "/register"),
        ("POST", "/token"),
        ("POST", "/revoke"),
        ("GET", "/.well-known/oauth-authorization-server"),
        ("GET", "/.well-known/oauth-protected-resource/mcp"),
        ("GET", "/no-such-page"),
    ],
)
async def test_every_non_mcp_route_checks_the_host(http_app, run_app, method, path) -> None:
    async with run_app(http_app) as driver:
        response = await driver.http.request(method, path, headers={"Host": "mcp.example.com.evil.example"})
    assert response.status_code == 421


@pytest.mark.parametrize("host", ["mcp.example.com", "MCP.Example.COM", "mcp.example.com:443", "mcp.example.com:8443"])
async def test_the_public_host_is_accepted_with_or_without_a_port(http_app, run_app, host) -> None:
    async with run_app(http_app) as driver:
        response = await driver.http.get("/.well-known/oauth-authorization-server", headers={"Host": host})
    assert response.status_code == 200


async def test_health_endpoints_do_not_check_the_host(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        health = await driver.http.get("/healthz", headers={"Host": "10.0.0.7:8000"})
        ready = await driver.http.get("/readyz", headers={"Host": "10.0.0.7:8000"})
    assert health.status_code == 200 and ready.status_code == 200


async def test_mcp_keeps_the_sdk_dns_rebinding_check(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        access = (await driver.exchange(await driver.login_for_code()))["access_token"]
        init = driver.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {}})
        no_token = await driver.mcp_post(None, init, headers={"Host": "evil.example"})
        with_token = await driver.mcp_post(access, init, headers={"Host": "evil.example"})
    assert no_token.status_code == 401
    assert with_token.status_code == 421


# ── body limit ──────────────────────────────────────────────────────────────

LIMITED = ["/register", "/token", "/revoke", "/authorize", "/login", "/oauth/callback"]


@pytest.mark.parametrize("path", LIMITED)
async def test_oversized_declared_body_is_refused(http_app, run_app, path) -> None:
    async with run_app(http_app) as driver:
        response = await driver.http.post(
            path,
            content=b"a=" + b"x" * MAX_AUTH_BODY_BYTES,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert response.status_code == 413


@pytest.mark.parametrize("path", LIMITED)
async def test_oversized_chunked_body_is_refused_before_it_is_read_completely(http_app, run_app, path) -> None:
    sent = 0
    chunks = 1000

    async def body() -> AsyncIterator[bytes]:
        nonlocal sent
        for _ in range(chunks):
            sent += 1
            yield b"x" * 1024

    async with run_app(http_app) as driver:
        response = await driver.http.post(
            path, content=body(), headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
    assert response.status_code == 413
    assert sent <= MAX_AUTH_BODY_BYTES // 1024 + 2 < chunks


async def test_body_just_under_the_limit_is_processed(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        response = await driver.http.post(
            "/login",
            content=b"pad=" + b"x" * (MAX_AUTH_BODY_BYTES - 100),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert response.status_code == 403  # reached the route: the CSRF check refused it


# ── DCR and /authorize rate limits (atomic reservations) ────────────────────


async def test_parallel_registration_burst_from_one_ip_is_capped(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        responses = await asyncio.gather(*(driver.register() for _ in range(60)))
        statuses = [r.status_code for r in responses]
        assert statuses.count(201) == REGISTER_RULE.limit
        assert statuses.count(429) == 60 - REGISTER_RULE.limit
        blocked = next(r for r in responses if r.status_code == 429)
        assert int(blocked.headers["retry-after"]) == int(REGISTER_RULE.base_lockout) + 1
        assert blocked.json()["error"] == "too_many_requests"
        async with driver.spawn("198.51.100.20") as other:
            assert (await other.register()).status_code == 201


async def test_parallel_authorize_burst_from_one_ip_is_capped(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        burst = AUTHORIZE_RULE.limit + 25
        responses = await asyncio.gather(
            *(driver.http.get("/authorize", params=driver.authorize_params()) for _ in range(burst))
        )
        statuses = [r.status_code for r in responses]
        assert statuses.count(302) == AUTHORIZE_RULE.limit
        assert statuses.count(429) == burst - AUTHORIZE_RULE.limit
        blocked = next(r for r in responses if r.status_code == 429)
        assert int(blocked.headers["retry-after"]) == int(AUTHORIZE_RULE.base_lockout) + 1
        async with driver.spawn("198.51.100.21") as other:
            other.client_id = driver.client_id
            assert (await other.http.get("/authorize", params=other.authorize_params())).status_code == 302


# ── login rate limit ────────────────────────────────────────────────────────

_CSRF_FIELD = re.compile(r'name="csrf_token" value="([^"]+)"')


class LoginForm:
    """The sign-in form as a browser keeps it: every re-rendered form carries a new CSRF token and cookie."""

    def __init__(self, driver: OAuthDriver, request_id: str, csrf: str) -> None:
        self.driver, self.request_id, self.csrf = driver, request_id, csrf

    @classmethod
    async def open(cls, driver: OAuthDriver) -> LoginForm:
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        return cls(driver, request_id, csrf)

    async def submit(self, username: str, password: str) -> httpx.Response:
        response = await self.driver.submit_login(self.request_id, self.csrf, username, password)
        match = _CSRF_FIELD.search(response.text)
        if match is not None:
            self.csrf = match.group(1)
        return response


async def test_login_lockout_returns_429_with_retry_after_and_audits(http_app, run_app, tmp_path) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        form = await LoginForm.open(driver)
        for _ in range(LOGIN_RULE.limit):
            failed = await form.submit("kerem", "wrong")
            assert failed.status_code == 401
            assert "Invalid username or password." in failed.text
        blocked = await form.submit("kerem", PASSWORD)
        assert blocked.status_code == 429
        assert blocked.headers["retry-after"] == str(int(LOGIN_RULE.base_lockout) + 1)
        assert f"Try again in {int(LOGIN_RULE.base_lockout) + 1} seconds" in blocked.text
    rows = audit_rows(tmp_path)
    assert rows.count(("login_failed", "kerem", "local", "denied")) == LOGIN_RULE.limit
    assert ("login_rate_limited", "kerem", "local", "denied") in rows
    assert not any(row[0] == "login_succeeded" for row in rows)


async def test_parallel_wrong_passwords_cannot_exceed_the_limit(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        # Every post carries the cookie of the one form, as parallel tabs or a script would.
        cookie = "; ".join(f"{name}={value}" for name, value in driver.http.cookies.items())
        responses = await asyncio.gather(
            *(
                driver.http.post(
                    "/login",
                    data={"request": request_id, "csrf_token": csrf, "username": "kerem", "password": f"guess-{i}"},
                    headers={"Cookie": cookie},
                )
                for i in range(12)
            )
        )
    statuses = [r.status_code for r in responses]
    assert statuses.count(401) == LOGIN_RULE.limit
    assert statuses.count(429) == 12 - LOGIN_RULE.limit


async def test_a_successful_login_is_refunded(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        form = await LoginForm.open(driver)
        for _ in range(LOGIN_RULE.limit - 1):
            assert (await form.submit("kerem", "wrong")).status_code == 401
        assert (await form.submit("kerem", PASSWORD)).status_code == 302
        # Without the refund the good login would have been the limit-th attempt and started a lockout.
        form = await LoginForm.open(driver)
        assert (await form.submit("kerem", "wrong")).status_code == 401
        assert (await form.submit("kerem", PASSWORD)).status_code == 429


async def test_user_lockout_covers_every_spelling_of_the_name_from_any_ip(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        form = await LoginForm.open(driver)
        for _ in range(LOGIN_RULE.limit):
            assert (await form.submit("kerem", "wrong")).status_code == 401
        async with driver.spawn("198.51.100.30") as other:
            other.client_id = driver.client_id
            other_form = await LoginForm.open(other)
            assert (await other_form.submit("  KEREM ", PASSWORD)).status_code == 429
            assert (await other_form.submit("ＫEREM", PASSWORD)).status_code == 429  # fullwidth K, NFKC
            # Another user from that IP is not affected.
            assert (await other_form.submit("ayse", PASSWORD)).status_code == 302


async def test_ip_lockout_groups_ipv6_clients_by_their_64_network(http_app, run_app) -> None:
    async with run_app(http_app, peer="2001:db8:1:2::1") as driver:
        await driver.register()
        form = await LoginForm.open(driver)
        for i in range(LOGIN_RULE.limit):
            assert (await form.submit(f"nobody-{i}", "wrong")).status_code == 401
        async with driver.spawn("2001:db8:1:2:ffff::9") as neighbour:
            neighbour.client_id = driver.client_id
            assert (await (await LoginForm.open(neighbour)).submit("ayse", PASSWORD)).status_code == 429
        async with driver.spawn("2001:db8:1:3::1") as elsewhere:
            elsewhere.client_id = driver.client_id
            assert (await (await LoginForm.open(elsewhere)).submit("ayse", PASSWORD)).status_code == 302


async def test_csrf_is_checked_before_the_pending_request_and_the_rate_limit(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        unknown = await driver.http.post(
            "/login", data={"request": "no-such-request", "csrf_token": "1.x", "username": "kerem", "password": "x"}
        )
        assert unknown.status_code == 403
        _, request_id, csrf = await driver.open_login(await driver.authorize())
        for _ in range(LOGIN_RULE.limit * 2):
            forged = await driver.submit_login(request_id, csrf + "x", "kerem", "wrong")
            assert forged.status_code == 403
        # None of the forged posts counted against the IP or the user.
        assert (await driver.submit_login(request_id, csrf, "kerem", PASSWORD)).status_code == 302


# ── cookies ─────────────────────────────────────────────────────────────────


async def test_https_public_url_uses_secure_host_prefixed_cookies(http_app, run_app) -> None:
    async with run_app(http_app) as driver:
        await driver.register()
        page, _, _ = await driver.open_login(await driver.authorize())
    cookie = page.headers["set-cookie"]
    assert cookie.startswith("__Host-ratatoskr-csrf=")
    assert "secure" in cookie.lower() and "httponly" in cookie.lower() and "samesite=strict" in cookie.lower()


async def test_insecure_dev_uses_plain_cookies(make_config) -> None:
    config = make_config(host="127.0.0.1")
    # make_config validates without --insecure-dev, so the http public_url is set afterwards.
    server = config.server.model_copy(update={"public_url": AnyHttpUrl("http://127.0.0.1:8000")})
    config = config.model_copy(update={"server": server})
    http_app = build_http_app(config, insecure_dev=True)
    app = http_app.asgi
    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 50000))
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client,
    ):
        driver = OAuthDriver(client, app)
        await driver.register()
        authorized = await client.get(
            "/authorize", params=driver.authorize_params(resource="http://127.0.0.1:8000/mcp")
        )
        assert authorized.headers["location"].startswith("http://127.0.0.1:8000/login?")
        page, request_id, csrf = await driver.open_login(authorized.headers["location"])
        cookie = page.headers["set-cookie"]
        assert cookie.startswith("ratatoskr-csrf=") and "secure" not in cookie.lower()
        assert (await driver.submit_login(request_id, csrf, "kerem", PASSWORD)).status_code == 302


# ── OIDC flow cookie ────────────────────────────────────────────────────────


async def test_oidc_flow_cookie_is_lax_bound_to_the_request_and_single_use(
    make_config, run_app, clock, fake_issuer, tmp_path
) -> None:
    http_app = build_http_app(make_config(mode="oidc"), clock=clock)
    async with run_app(http_app) as driver:
        await driver.register()
        login_url = await driver.authorize()
        start = await driver.http.get(login_url)
        assert start.status_code == 302
        upstream = urlsplit(start.headers["location"])
        assert start.headers["location"].startswith(fake_issuer.authorization_endpoint)
        query = {k: v[0] for k, v in parse_qs(upstream.query).items()}
        assert query["redirect_uri"] == "https://mcp.example.com/oauth/callback"
        cookie = start.headers["set-cookie"].lower()
        assert cookie.startswith("__host-ratatoskr-oidc=")
        assert "samesite=lax" in cookie and "secure" in cookie and "httponly" in cookie
        callback = {"state": query["state"], "code": "upstream-code"}

        # Another browser (no flow cookie) cannot complete this sign-in, nor can a tampered cookie.
        async with driver.spawn("198.51.100.40") as other:
            assert (await other.http.get("/oauth/callback", params=callback)).status_code == 400
            other.http.cookies.set("__Host-ratatoskr-oidc", "forged", domain="mcp.example.com")
            assert (await other.http.get("/oauth/callback", params=callback)).status_code == 400
        # A cookie for another pending request does not fit this one.
        second_login = await driver.authorize()
        second = await driver.http.get(second_login)
        second_state = parse_qs(urlsplit(second.headers["location"]).query)["state"][0]
        assert second_state != query["state"]
        mismatched = await driver.http.get("/oauth/callback", params={"state": query["state"], "code": "c"})
        assert mismatched.status_code == 400

        # Back to the first flow: its cookie is restored, the issuer answers, the client gets a code.
        assert (await driver.http.get(login_url)).status_code == 302
        flow_cookie = driver.http.cookies.get("__Host-ratatoskr-oidc")
        assert flow_cookie
        fake_issuer.queue_token_response(
            id_token=fake_issuer.id_token(nonce=query["nonce"]),
            access_token="upstream-access",
            refresh_token="upstream-refresh",
            token_type="Bearer",
        )
        done = await driver.http.get("/oauth/callback", params=callback)
        assert done.status_code == 302, done.text
        assert done.headers["location"].startswith(CLIENT_REDIRECT + "?")
        assert driver.http.cookies.get("__Host-ratatoskr-oidc") is None, "the flow cookie is cleared"
        tokens = await driver.exchange(driver.code_from(done.headers["location"]))
        assert tokens["token_type"] == "Bearer"

        # Single use: the same callback with the same cookie finds no pending request any more.
        driver.http.cookies.set("__Host-ratatoskr-oidc", flow_cookie, domain="mcp.example.com")
        fake_issuer.queue_token_response(
            id_token=fake_issuer.id_token(nonce=query["nonce"]), access_token="a", token_type="Bearer"
        )
        replay = await driver.http.get("/oauth/callback", params=callback)
        assert replay.status_code == 400
        assert len(fake_issuer.token_requests) == 1, "the replay never reached the issuer"
    assert ("login_succeeded", "alice@example.com", "oidc", "ok") in audit_rows(tmp_path)
