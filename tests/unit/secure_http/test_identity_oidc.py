from __future__ import annotations

import asyncio
import base64
import json
import ssl
import time
from collections.abc import AsyncIterator
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from joserfc import jwt
from joserfc.jwk import KeySet, OctKey

from ratatoskr.auth.crypto import pkce_challenge
from ratatoskr.auth.identity.base import IdentityError, UpstreamRejectedError, UpstreamUnavailableError
from ratatoskr.auth.identity.oidc import (
    JWKS_MAX_AGE_SECONDS,
    JWKS_REFRESH_COOLDOWN_SECONDS,
    MAX_RESPONSE_BYTES,
    OidcIdentityProvider,
)
from ratatoskr.config.models import OidcSettings

REDIRECT = "https://mcp.example.com/oauth/callback"
VERIFIER = "v" * 64


@pytest.fixture
async def http(tls_context: ssl.SSLContext) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(verify=tls_context) as client:
        yield client


def settings(**overrides: object) -> OidcSettings:
    values: dict[str, object] = {
        "issuer": "https://idp.example.com/application/o/mcp/",
        "client_id": "ratatoskr",
        "client_secret": "upstream-secret",
        **overrides,
    }
    return OidcSettings.model_validate(values)


@pytest.fixture
def oidc(http: httpx.AsyncClient, clock) -> OidcIdentityProvider:
    return OidcIdentityProvider(settings(), REDIRECT, http, clock)


async def test_authorization_url_carries_pkce_state_and_nonce(oidc, fake_issuer) -> None:
    url = await oidc.authorization_url(state="st", nonce="nn", code_verifier=VERIFIER)
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == fake_issuer.authorization_endpoint
    query = {k: v[0] for k, v in parse_qs(parts.query).items()}
    assert query == {
        "response_type": "code",
        "client_id": "ratatoskr",
        "redirect_uri": REDIRECT,
        "scope": "openid email profile groups offline_access",
        "state": "st",
        "nonce": "nn",
        "code_challenge": pkce_challenge(VERIFIER),
        "code_challenge_method": "S256",
    }


async def test_discovery_issuer_mismatch_is_rejected(oidc, fake_issuer) -> None:
    fake_issuer.discovery["issuer"] = "https://attacker.example.com/"
    with pytest.raises(IdentityError, match="does not match"):
        await oidc.metadata()


async def test_complete_returns_principal_and_upstream_refresh(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(
        id_token=fake_issuer.id_token(nonce="nn", groups=["devops", "analyst"]),
        access_token="up-access",
        refresh_token="up-refresh",
        token_type="Bearer",
    )
    login = await oidc.complete("the-code", VERIFIER, "nn")
    assert login.principal.subject == "alice@example.com"
    assert login.principal.display_name == "Alice Example"
    assert login.principal.groups == frozenset({"devops", "analyst"})
    assert login.principal.auth_source == "oidc"
    assert login.refresh_token == "up-refresh"
    form = fake_issuer.form()
    assert form == {
        "grant_type": "authorization_code",
        "code": "the-code",
        "redirect_uri": REDIRECT,
        "code_verifier": VERIFIER,
    }
    basic = base64.b64encode(b"ratatoskr:upstream-secret").decode()
    assert fake_issuer.token_requests[-1].headers["authorization"] == f"Basic {basic}"


async def test_subject_and_groups_claims_are_configurable(http, clock, fake_issuer) -> None:
    provider = OidcIdentityProvider(settings(subject_claim="sub", groups_claim="roles"), REDIRECT, http, clock)
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn", roles=["dba"]))
    login = await provider.complete("c", VERIFIER, "nn")
    assert login.principal.subject == "a1b2c3"
    assert login.principal.groups == frozenset({"dba"})
    assert login.refresh_token is None


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"nonce": "other"}, "claims rejected"),
        ({"nonce": None}, "claims rejected"),
        ({"aud": "someone-else"}, "claims rejected"),
        ({"iss": "https://attacker.example.com/"}, "claims rejected"),
        ({"email": None}, "missing"),
    ],
)
async def test_invalid_id_token_claims_are_rejected(oidc, fake_issuer, overrides, message) -> None:
    claims = {"nonce": "nn", **overrides}
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(**claims))
    with pytest.raises(IdentityError, match=message):
        await oidc.complete("c", VERIFIER, "nn")


async def test_expired_id_token_is_rejected(oidc, fake_issuer, clock) -> None:
    token = fake_issuer.id_token(nonce="nn")
    clock.advance(300 + 61)
    fake_issuer.queue_token_response(id_token=token)
    with pytest.raises(IdentityError, match="claims rejected"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_several_audiences_require_azp(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn", aud=["ratatoskr", "other"]))
    with pytest.raises(IdentityError, match="azp"):
        await oidc.complete("c", VERIFIER, "nn")
    fake_issuer.queue_token_response(
        id_token=fake_issuer.id_token(nonce="nn", aud=["ratatoskr", "other"], azp="ratatoskr")
    )
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.subject == "alice@example.com"


async def test_signature_from_unknown_key_is_rejected(oidc, fake_issuer, other_rsa_key) -> None:
    forged = fake_issuer.id_token(key=other_rsa_key, header={"alg": "RS256", "kid": "key-1"}, nonce="nn")
    fake_issuer.queue_token_response(id_token=forged)
    with pytest.raises(IdentityError, match="signature"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_hmac_signed_token_is_rejected(oidc, fake_issuer) -> None:
    secret = OctKey.import_key("upstream-secret-upstream-secret-32")
    token = jwt.encode(
        {"alg": "HS256"},
        {"iss": fake_issuer.issuer, "aud": "ratatoskr", "email": "alice@example.com", "nonce": "nn"},
        secret,
    )
    fake_issuer.queue_token_response(id_token=token)
    with pytest.raises(IdentityError):
        await oidc.complete("c", VERIFIER, "nn")


async def test_key_rotation_refetches_jwks(oidc, fake_issuer, other_rsa_key) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    await oidc.complete("c", VERIFIER, "nn")
    assert fake_issuer.jwks_fetches == 1
    fake_issuer.jwks = dict(KeySet([other_rsa_key]).as_dict(private=False))
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(key=other_rsa_key, nonce="nn"))
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.subject == "alice@example.com"
    assert fake_issuer.jwks_fetches == 2


async def test_missing_id_token_is_rejected(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(access_token="only-access")
    with pytest.raises(IdentityError, match="id_token"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_refresh_rereads_groups_from_new_id_token(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(groups=["analyst"]), refresh_token="up-2")
    login = await oidc.refresh("up-1")
    assert login.principal.groups == frozenset({"analyst"})
    assert login.refresh_token == "up-2"
    assert fake_issuer.form() == {"grant_type": "refresh_token", "refresh_token": "up-1"}


async def test_refresh_without_id_token_uses_userinfo(oidc, fake_issuer) -> None:
    fake_issuer.userinfo = {"sub": "a1b2c3", "email": "alice@example.com", "groups": ["ops"]}
    fake_issuer.queue_token_response(access_token="up-access")
    login = await oidc.refresh("up-1")
    assert login.principal.groups == frozenset({"ops"})
    assert login.refresh_token == "up-1"


async def test_refresh_rejected_by_issuer(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(400, error="invalid_grant")
    with pytest.raises(UpstreamRejectedError, match="invalid_grant"):
        await oidc.refresh("up-1")


async def test_issuer_outage_is_reported_as_unavailable(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(503, error="unavailable")
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")


async def test_network_error_is_reported_as_unavailable(oidc, fake_issuer) -> None:
    fake_issuer.discovery["token_endpoint"] = "https://idp-down.example.com/token/"
    fake_issuer.router.post("https://idp-down.example.com/token/").mock(side_effect=httpx.ConnectError("down"))
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")


# ── hardening beyond the plan's tests ──


def _unsigned(claims: dict[str, object], header: dict[str, object]) -> str:
    def b64(data: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

    return f"{b64(header)}.{b64(claims)}."


def test_plain_http_issuer_is_refused_unless_explicitly_allowed(http, clock) -> None:
    with pytest.raises(ValueError, match="https"):
        OidcIdentityProvider(settings(issuer="http://idp.example.com/o/"), REDIRECT, http, clock)
    OidcIdentityProvider(settings(issuer="http://127.0.0.1:9000/o/"), REDIRECT, http, clock, allow_insecure_http=True)


@pytest.mark.parametrize("endpoint", ["authorization_endpoint", "token_endpoint", "jwks_uri", "userinfo_endpoint"])
async def test_discovery_endpoints_must_be_https(oidc, fake_issuer, endpoint) -> None:
    fake_issuer.discovery[endpoint] = "http://idp.example.com/plain/"
    with pytest.raises(IdentityError, match="https"):
        await oidc.metadata()


async def test_discovery_issuer_must_match_exactly(oidc, fake_issuer) -> None:
    fake_issuer.discovery["issuer"] = fake_issuer.issuer.rstrip("/")
    with pytest.raises(IdentityError, match="does not match"):
        await oidc.metadata()


async def test_discovery_redirect_is_not_followed(oidc, fake_issuer) -> None:
    fake_issuer.router.get(fake_issuer.issuer + ".well-known/openid-configuration").mock(
        return_value=httpx.Response(302, headers={"Location": "https://attacker.example.com/"})
    )
    with pytest.raises(IdentityError):
        await oidc.metadata()


async def test_upstream_requests_carry_a_timeout(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    await oidc.complete("c", VERIFIER, "nn")
    for call in fake_issuer.router.calls:
        timeout = call.request.extensions["timeout"]
        assert all(value is not None for value in timeout.values())


async def test_oversized_upstream_response_is_rejected(oidc, fake_issuer) -> None:
    fake_issuer.discovery["padding"] = "x" * (MAX_RESPONSE_BYTES + 1)
    with pytest.raises(IdentityError, match="too large"):
        await oidc.metadata()


async def test_oversized_response_without_content_length_is_cut_off(oidc, fake_issuer) -> None:
    async def endless() -> AsyncIterator[bytes]:
        while True:
            yield b"x" * 65536

    fake_issuer.router.get(fake_issuer.issuer + ".well-known/openid-configuration").mock(
        side_effect=lambda request: httpx.Response(200, content=endless())
    )
    with pytest.raises(IdentityError, match="too large"):
        await oidc.metadata()


async def test_oversized_token_response_is_rejected(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token="x" * (MAX_RESPONSE_BYTES + 1))
    with pytest.raises(IdentityError, match="too large"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_unsigned_token_is_rejected_even_if_advertised(oidc, fake_issuer) -> None:
    fake_issuer.discovery["id_token_signing_alg_values_supported"] = ["none", "HS256", "RS256"]
    now = int(fake_issuer.clock())
    claims = {"iss": fake_issuer.issuer, "aud": "ratatoskr", "email": "a@x", "nonce": "nn", "iat": now, "exp": now + 60}
    fake_issuer.queue_token_response(id_token=_unsigned(claims, {"alg": "none"}))
    with pytest.raises(IdentityError, match="signature"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_hmac_token_with_published_oct_key_is_rejected(oidc, fake_issuer) -> None:
    """Algorithm confusion: even an advertised HS256 and an oct key in the JWKS must not verify a token."""
    secret = OctKey.import_key("upstream-secret-upstream-secret-32", parameters={"kid": "hmac"})
    fake_issuer.discovery["id_token_signing_alg_values_supported"] = ["HS256", "RS256"]
    fake_issuer.jwks = {"keys": [*fake_issuer.jwks["keys"], dict(secret.as_dict(private=True))]}
    now = int(fake_issuer.clock())
    claims = {"iss": fake_issuer.issuer, "aud": "ratatoskr", "email": "a@x", "nonce": "nn", "iat": now, "exp": now + 60}
    fake_issuer.queue_token_response(id_token=jwt.encode({"alg": "HS256", "kid": "hmac"}, claims, secret))
    with pytest.raises(IdentityError, match="signature"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_unknown_kid_refetch_is_rate_limited(oidc, fake_issuer, other_rsa_key, clock) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    await oidc.complete("c", VERIFIER, "nn")
    # The first unknown kid refetches; the issuer really does not publish it: a definitive verification failure.
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(key=other_rsa_key, nonce="nn"))
    with pytest.raises(IdentityError, match="signature") as info:
        await oidc.complete("c", VERIFIER, "nn")
    assert not isinstance(info.value, UpstreamUnavailableError)
    # During the cooldown nothing is fetched, so nothing is known: retry later, do not revoke.
    for _ in range(4):
        fake_issuer.queue_token_response(id_token=fake_issuer.id_token(key=other_rsa_key, nonce="nn"))
        with pytest.raises(UpstreamUnavailableError):
            await oidc.complete("c", VERIFIER, "nn")
    assert fake_issuer.jwks_fetches == 2  # initial load + one forced refresh, not one per bad token
    clock.advance(JWKS_REFRESH_COOLDOWN_SECONDS + 1)
    fake_issuer.jwks = dict(KeySet([other_rsa_key]).as_dict(private=False))
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(key=other_rsa_key, nonce="nn"))
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.subject == "alice@example.com"
    assert fake_issuer.jwks_fetches == 3


async def test_cached_jwks_expires(oidc, fake_issuer, clock) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    await oidc.complete("c", VERIFIER, "nn")
    clock.advance(JWKS_MAX_AGE_SECONDS + 1)
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    await oidc.complete("c", VERIFIER, "nn")
    assert fake_issuer.jwks_fetches == 2


async def test_unusable_jwks_entries_are_skipped(oidc, fake_issuer) -> None:
    fake_issuer.jwks = {"keys": [{"kty": "unknown"}, {"kty": "RSA", "use": "enc", "n": "x", "e": "AQAB"}, "junk",
                                 *fake_issuer.jwks["keys"]]}  # fmt: skip
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.subject == "alice@example.com"


@pytest.mark.parametrize(
    "overrides",
    [
        {"nbf": "future"},
        {"iat": "future"},
        {"azp": "someone-else"},
        {"nonce": ["nn"]},
        {"exp": None},
        {"iat": None},
    ],
)
async def test_more_invalid_claims_are_rejected(oidc, fake_issuer, overrides) -> None:
    future = int(fake_issuer.clock()) + 3600
    claims = {"nonce": "nn", **{k: (future if v == "future" else v) for k, v in overrides.items()}}
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(**claims))
    with pytest.raises(IdentityError):
        await oidc.complete("c", VERIFIER, "nn")


@pytest.mark.parametrize("subject", ["", "   ", 42, ["alice@example.com"]])
async def test_subject_must_be_a_non_empty_string(oidc, fake_issuer, subject) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn", email=subject))
    with pytest.raises(IdentityError, match="missing"):
        await oidc.complete("c", VERIFIER, "nn")


@pytest.mark.parametrize(
    ("groups", "expected"),
    [
        ("admins", frozenset()),
        ({"admins": True}, frozenset()),
        (["devops", 7, None, {"x": 1}, "ops"], frozenset({"devops", "ops"})),
    ],
)
async def test_groups_claim_must_be_a_list_of_strings(oidc, fake_issuer, groups, expected) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn", groups=groups))
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.groups == expected


async def test_complete_requires_a_nonce(oidc, fake_issuer) -> None:
    with pytest.raises(IdentityError, match="nonce"):
        await oidc.complete("c", VERIFIER, "")
    assert fake_issuer.token_requests == []


async def test_upstream_error_code_is_not_copied_verbatim_when_odd(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(400, error="bad\nfake log line <script>")
    with pytest.raises(UpstreamRejectedError) as info:
        await oidc.refresh("up-1")
    assert "script" not in str(info.value) and "\n" not in str(info.value)


async def test_errors_never_contain_tokens_or_client_secret(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(400, error="invalid_grant")
    with pytest.raises(UpstreamRejectedError) as info:
        await oidc.refresh("up-refresh-secret-value")
    assert "up-refresh-secret-value" not in str(info.value)
    assert "upstream-secret" not in str(info.value)


# ── retry (UpstreamUnavailableError) versus revoke (any other IdentityError) ──

HTML = {"content": b"<html>maintenance</html>", "headers": {"Content-Type": "text/html"}}


@pytest.mark.parametrize(
    ("status", "kwargs"),
    [
        (429, {"json": {"error": "slow_down"}}),
        (408, {}),
        (302, {"headers": {"Location": "https://elsewhere.example.com/"}}),
        (404, HTML),
        (200, HTML),
        (200, {"json": ["not", "an", "object"]}),
    ],
)
async def test_token_endpoint_non_answers_are_retryable(oidc, fake_issuer, status, kwargs) -> None:
    fake_issuer.token_responses.append(httpx.Response(status, **kwargs))
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")


@pytest.mark.parametrize(("status", "error"), [(400, "invalid_grant"), (401, "invalid_client")])
async def test_token_endpoint_refusals_revoke(oidc, fake_issuer, status, error) -> None:
    fake_issuer.queue_token_response(status, error=error)
    with pytest.raises(UpstreamRejectedError, match=error):
        await oidc.refresh("up-1")


def _userinfo_replies(fake_issuer, response: httpx.Response) -> None:
    fake_issuer.router.get(fake_issuer.userinfo_endpoint).mock(return_value=response)
    fake_issuer.queue_token_response(access_token="up-access")


@pytest.mark.parametrize("status", [401, 403])
async def test_userinfo_refusals_revoke(oidc, fake_issuer, status) -> None:
    _userinfo_replies(fake_issuer, httpx.Response(status))
    with pytest.raises(UpstreamRejectedError):
        await oidc.refresh("up-1")


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(429),
        httpx.Response(500),
        httpx.Response(302, headers={"Location": "/x"}),
        httpx.Response(200, **HTML),
    ],
)
async def test_userinfo_non_answers_are_retryable(oidc, fake_issuer, response) -> None:
    _userinfo_replies(fake_issuer, response)
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(404),
        httpx.Response(429),
        httpx.Response(401),
        httpx.Response(302, headers={"Location": "/"}),
        httpx.Response(200, **HTML),
    ],
)
async def test_discovery_failures_are_retryable(oidc, fake_issuer, response) -> None:
    fake_issuer.router.get(fake_issuer.issuer + ".well-known/openid-configuration").mock(return_value=response)
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")


@pytest.mark.parametrize("response", [httpx.Response(404), httpx.Response(429), httpx.Response(200, **HTML)])
async def test_jwks_failures_without_cached_keys_are_retryable(oidc, fake_issuer, response) -> None:
    fake_issuer.router.get(fake_issuer.jwks_uri).mock(return_value=response)
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(), refresh_token="up-2")
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")


async def test_jwks_refetch_failure_keeps_serving_cached_keys(
    oidc, fake_issuer, clock, caplog: pytest.LogCaptureFixture
) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    await oidc.complete("c", VERIFIER, "nn")
    clock.advance(JWKS_MAX_AGE_SECONDS + 1)
    route = fake_issuer.router.get(fake_issuer.jwks_uri).mock(return_value=httpx.Response(429))
    before = route.call_count  # respx reuses the route of the same pattern, so count from here
    caplog.set_level("WARNING")
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.subject == "alice@example.com"
    assert route.call_count - before == 1 and "JWKS" in caplog.text
    # The failed refetch is not retried on every sign-in, only after the cooldown.
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    await oidc.complete("c", VERIFIER, "nn")
    assert route.call_count - before == 1
    clock.advance(JWKS_REFRESH_COOLDOWN_SECONDS + 1)
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"))
    await oidc.complete("c", VERIFIER, "nn")
    assert route.call_count - before == 2


async def test_failed_id_token_verification_revokes(oidc, fake_issuer, other_rsa_key) -> None:
    forged = fake_issuer.id_token(key=other_rsa_key, header={"alg": "RS256", "kid": "key-1"})
    fake_issuer.queue_token_response(id_token=forged)
    with pytest.raises(IdentityError) as info:
        await oidc.refresh("up-1")
    assert not isinstance(info.value, UpstreamUnavailableError)


# ── deadlines and malformed input ──


async def test_slow_drip_response_hits_the_overall_deadline(oidc, fake_issuer, monkeypatch) -> None:
    import ratatoskr.auth.identity.oidc as oidc_module

    monkeypatch.setattr(oidc_module, "UPSTREAM_TIMEOUT_SECONDS", 0.3)

    async def drip() -> AsyncIterator[bytes]:
        while True:
            yield b" "
            await asyncio.sleep(0.05)

    fake_issuer.router.get(fake_issuer.issuer + ".well-known/openid-configuration").mock(
        side_effect=lambda request: httpx.Response(200, content=drip())
    )
    started = time.monotonic()
    with pytest.raises(UpstreamUnavailableError):
        await oidc.metadata()
    assert time.monotonic() - started < 2


async def test_stream_error_is_retryable(oidc, fake_issuer) -> None:
    fake_issuer.router.post(fake_issuer.token_endpoint).mock(side_effect=httpx.StreamClosed())
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")


async def test_unparseable_endpoint_url_is_refused(oidc, fake_issuer) -> None:
    fake_issuer.discovery["token_endpoint"] = "https://[::1/token"
    with pytest.raises(IdentityError):
        await oidc.metadata()


async def test_non_ascii_access_token_is_not_sent_to_userinfo(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(access_token="töken")
    with pytest.raises(UpstreamUnavailableError):
        await oidc.refresh("up-1")


# ── subject (sub) continuity ──


async def test_id_token_must_carry_sub(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn", sub=None))
    with pytest.raises(IdentityError, match="sub"):
        await oidc.complete("c", VERIFIER, "nn")


async def test_userinfo_must_carry_sub(oidc, fake_issuer) -> None:
    fake_issuer.userinfo = {"email": "alice@example.com", "groups": ["ops"]}
    fake_issuer.queue_token_response(access_token="up-access")
    with pytest.raises(IdentityError, match="sub") as info:
        await oidc.refresh("up-1")
    assert not isinstance(info.value, UpstreamUnavailableError)


async def test_userinfo_sub_must_match_the_id_token_sub(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"), refresh_token="up-1")
    await oidc.complete("c", VERIFIER, "nn")
    fake_issuer.userinfo = {"sub": "someone-else", "email": "alice@example.com"}
    fake_issuer.queue_token_response(access_token="up-access")
    with pytest.raises(IdentityError, match="sub") as info:
        await oidc.refresh("up-1")
    assert not isinstance(info.value, UpstreamUnavailableError)


async def test_sub_is_tracked_across_upstream_rotation(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(nonce="nn"), refresh_token="up-1")
    await oidc.complete("c", VERIFIER, "nn")
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(), refresh_token="up-2")
    assert (await oidc.refresh("up-1")).refresh_token == "up-2"
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(sub="someone-else"), refresh_token="up-3")
    with pytest.raises(IdentityError, match="sub"):
        await oidc.refresh("up-2")


# ── header-supplied key locations and kid-less tokens ──


@pytest.mark.parametrize("location", ["jku", "x5u"])
async def test_key_location_headers_are_never_fetched(oidc, fake_issuer, rsa_key, other_rsa_key, location) -> None:
    attacker = fake_issuer.router.get("https://attacker.example.com/keys").mock(
        return_value=httpx.Response(200, json=dict(KeySet([other_rsa_key]).as_dict(private=False)))
    )
    header = {"alg": "RS256", "kid": "key-2", location: "https://attacker.example.com/keys"}
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(key=other_rsa_key, header=header, nonce="nn"))
    with pytest.raises(IdentityError, match="signature"):
        await oidc.complete("c", VERIFIER, "nn")
    header = {"alg": "RS256", "kid": "key-1", location: "https://attacker.example.com/keys"}
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(key=rsa_key, header=header, nonce="nn"))
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.subject == "alice@example.com"
    assert attacker.call_count == 0


async def test_token_without_kid_uses_the_only_published_key(oidc, fake_issuer) -> None:
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(header={"alg": "RS256"}, nonce="nn"))
    assert (await oidc.complete("c", VERIFIER, "nn")).principal.subject == "alice@example.com"


async def test_token_without_kid_is_rejected_when_several_keys_are_published(
    oidc, fake_issuer, rsa_key, other_rsa_key
) -> None:
    fake_issuer.jwks = dict(KeySet([rsa_key, other_rsa_key]).as_dict(private=False))
    fake_issuer.queue_token_response(id_token=fake_issuer.id_token(header={"alg": "RS256"}, nonce="nn"))
    with pytest.raises(IdentityError, match="signature") as info:
        await oidc.complete("c", VERIFIER, "nn")
    assert not isinstance(info.value, UpstreamUnavailableError)
