from __future__ import annotations

import logging
import sqlite3
from urllib.parse import parse_qs, urlsplit

import pytest
from mcp.server.auth.provider import AuthorizationParams, AuthorizeError, RegistrationError, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl, SecretStr

from ratatoskr.auth.crypto import Keyring, hash_token, pkce_challenge
from ratatoskr.auth.identity.base import ExternalLogin, UpstreamRejectedError, UpstreamUnavailableError
from ratatoskr.auth.identity.local import LocalIdentityProvider
from ratatoskr.auth.oauth_server import MAX_REDIRECT_URIS, RatatoskrOAuthProvider
from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import LocalUser
from ratatoskr.state.records import StoredClient

REDIRECT = "https://claude.ai/api/mcp/auth_callback"
VERIFIER = "x" * 64
CLIENT_SECRET = "client-secret-value"
KEREM = Principal(subject="kerem", display_name="kerem", groups=frozenset({"admins"}), auth_source="local")
ALICE = Principal(subject="alice@example.com", display_name="Alice", groups=frozenset({"devops"}), auth_source="oidc")


class FakeUpstream:
    def __init__(self) -> None:
        self.result: ExternalLogin | Exception = ExternalLogin(ALICE, "up-2")
        self.refreshed_with: list[str] = []

    async def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        return f"https://idp.example.com/authorize?state={state}"

    async def complete(self, code: str, code_verifier: str, nonce: str) -> ExternalLogin:
        return ExternalLogin(ALICE, "up-1")

    async def refresh(self, refresh_token: str) -> ExternalLogin:
        self.refreshed_with.append(refresh_token)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def local_users(password_hash: str, groups: list[str]) -> LocalIdentityProvider:
    return LocalIdentityProvider([LocalUser(username="kerem", password_hash=SecretStr(password_hash), groups=groups)])


@pytest.fixture
def build(make_config, store, audit, clock, password_hash):
    def factory(
        *, mode: str = "local", local=None, oidc=None, keyring=None, server_extra=None
    ) -> RatatoskrOAuthProvider:
        config = make_config(
            mode=mode,
            auth_extra={"access_token_ttl": "1h", "refresh_token_ttl": "30d"},
            server_extra=server_extra,
        )
        return RatatoskrOAuthProvider(
            config,
            store=store,
            keyring=keyring if keyring is not None else Keyring("k" * 48),
            audit=audit,
            clock=clock,
            local=local if local is not None else (local_users(password_hash, ["admins"]) if mode == "local" else None),
            oidc=oidc,
        )

    return factory


async def register(provider: RatatoskrOAuthProvider, client_id: str = "client-1") -> OAuthClientInformationFull:
    client = OAuthClientInformationFull(
        client_id=client_id,
        client_secret=CLIENT_SECRET,
        redirect_uris=[AnyUrl(REDIRECT)],
        token_endpoint_auth_method="client_secret_post",
        client_name="Claude",
        scope="mcp",
    )
    await provider.register_client(client)
    loaded = await provider.get_client(client_id)
    assert loaded is not None
    return loaded


def params(**overrides: object) -> AuthorizationParams:
    values: dict[str, object] = {
        "state": "client-state",
        "scopes": ["mcp"],
        "code_challenge": pkce_challenge(VERIFIER),
        "redirect_uri": AnyUrl(REDIRECT),
        "redirect_uri_provided_explicitly": True,
        "resource": "https://mcp.example.com/mcp",
        **overrides,
    }
    return AuthorizationParams.model_validate(values)


async def issue_code(
    provider: RatatoskrOAuthProvider, client: OAuthClientInformationFull, principal: Principal, upstream: str | None
) -> str:
    login_url = await provider.authorize(client, params())
    request_id = parse_qs(urlsplit(login_url).query)["request"][0]
    pending = await provider.take_pending(request_id)
    assert pending is not None
    redirect = await provider.complete_authorization(pending, principal, upstream)
    query = parse_qs(urlsplit(redirect).query)
    assert query["state"] == ["client-state"]
    return query["code"][0]


async def tokens_for(provider, client, principal=KEREM, upstream=None):
    code = await issue_code(provider, client, principal, upstream)
    loaded = await provider.load_authorization_code(client, code)
    assert loaded is not None
    return await provider.exchange_authorization_code(client, loaded)


# ── registration ────────────────────────────────────────────────────────────


async def test_registration_seals_client_secret(build, store, tmp_path) -> None:
    provider = build()
    client = await register(provider)
    assert client.client_secret == CLIENT_SECRET
    with sqlite3.connect(tmp_path / "state.db") as raw:
        row = raw.execute("SELECT metadata_json, secret_blob FROM clients").fetchone()
    assert CLIENT_SECRET not in row[0]
    assert CLIENT_SECRET.encode() not in row[1]


@pytest.mark.parametrize(
    "uri", ["https://evil.example/cb", "http://claude.ai/api/mcp/auth_callback", "https://claude.ai.evil.example/cb"]
)
async def test_registration_rejects_disallowed_redirects(build, uri) -> None:
    client = OAuthClientInformationFull(client_id="c", redirect_uris=[AnyUrl(uri)], token_endpoint_auth_method="none")
    with pytest.raises(RegistrationError) as info:
        await build().register_client(client)
    assert info.value.error == "invalid_redirect_uri"


async def test_registration_checks_every_redirect_uri(build) -> None:
    client = OAuthClientInformationFull(
        client_id="c",
        redirect_uris=[AnyUrl(REDIRECT), AnyUrl("https://evil.example/cb")],
        token_endpoint_auth_method="none",
    )
    with pytest.raises(RegistrationError) as info:
        await build().register_client(client)
    assert info.value.error == "invalid_redirect_uri"


async def test_registration_caps_the_number_of_redirect_uris(build) -> None:
    provider = build()
    allowed = OAuthClientInformationFull(
        client_id="ok",
        redirect_uris=[AnyUrl(f"{REDIRECT}/{i}") for i in range(MAX_REDIRECT_URIS)],
        token_endpoint_auth_method="none",
    )
    await provider.register_client(allowed)
    too_many = OAuthClientInformationFull(
        client_id="many",
        redirect_uris=[AnyUrl(f"{REDIRECT}/{i}") for i in range(MAX_REDIRECT_URIS + 1)],
        token_endpoint_auth_method="none",
    )
    with pytest.raises(RegistrationError) as info:
        await provider.register_client(too_many)
    assert info.value.error == "invalid_redirect_uri"
    assert await provider.get_client("many") is None


async def test_registration_rejects_overlong_redirect_uri(build) -> None:
    client = OAuthClientInformationFull(
        client_id="c", redirect_uris=[AnyUrl(REDIRECT + "/" + "a" * 2100)], token_endpoint_auth_method="none"
    )
    with pytest.raises(RegistrationError) as info:
        await build().register_client(client)
    assert info.value.error == "invalid_redirect_uri"


async def test_registration_rejects_unsupported_client_auth(build) -> None:
    client = OAuthClientInformationFull(
        client_id="c", redirect_uris=[AnyUrl(REDIRECT)], token_endpoint_auth_method="private_key_jwt"
    )
    with pytest.raises(RegistrationError) as info:
        await build().register_client(client)
    assert info.value.error == "invalid_client_metadata"


async def test_registration_rejects_confidential_client_without_secret(build) -> None:
    client = OAuthClientInformationFull(
        client_id="c", redirect_uris=[AnyUrl(REDIRECT)], token_endpoint_auth_method="client_secret_post"
    )
    with pytest.raises(RegistrationError) as info:
        await build().register_client(client)
    assert info.value.error == "invalid_client_metadata"


async def test_registration_rejects_scopes_beyond_mcp(build) -> None:
    client = OAuthClientInformationFull(
        client_id="c", redirect_uris=[AnyUrl(REDIRECT)], token_endpoint_auth_method="none", scope="mcp admin"
    )
    with pytest.raises(RegistrationError) as info:
        await build().register_client(client)
    assert info.value.error == "invalid_client_metadata"


async def test_secret_sealed_under_other_key_hides_client(build, caplog) -> None:
    await register(build())
    other = build(keyring=Keyring("z" * 48))
    with caplog.at_level(logging.WARNING, logger="ratatoskr.auth.oauth"):
        assert await other.get_client("client-1") is None
    assert "key-mismatch" in caplog.text
    assert CLIENT_SECRET not in caplog.text


async def test_confidential_client_without_stored_secret_is_unknown(build, store, clock) -> None:
    """Fail closed: the SDK skips the secret check when ``client_secret`` is empty."""
    metadata = OAuthClientInformationFull(
        client_id="c", redirect_uris=[AnyUrl(REDIRECT)], token_endpoint_auth_method="client_secret_post"
    ).model_dump_json(exclude_none=True)
    await store.save_client(StoredClient("c", metadata, None, clock()))
    assert await build().get_client("c") is None


async def test_unreadable_client_metadata_is_unknown(build, store, clock) -> None:
    await store.save_client(StoredClient("c", "{not json", None, clock()))
    assert await build().get_client("c") is None
    assert await build().get_client("missing") is None


# ── authorize ───────────────────────────────────────────────────────────────


async def test_authorize_returns_login_url_with_opaque_request(build) -> None:
    provider = build()
    client = await register(provider)
    url = await provider.authorize(client, params())
    parts = urlsplit(url)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://mcp.example.com/login"
    request_id = parse_qs(parts.query)["request"][0]
    pending = await provider.load_pending(request_id)
    assert pending is not None
    assert pending.client.client_name == "Claude"
    assert pending.pending.nonce is None


async def test_authorize_prepares_oidc_nonce_and_verifier(build) -> None:
    provider = build(mode="oidc", oidc=FakeUpstream())
    client = await register(provider)
    url = await provider.authorize(client, params())
    pending = await provider.load_pending(parse_qs(urlsplit(url).query)["request"][0])
    assert pending is not None
    assert pending.pending.nonce and pending.pending.upstream_verifier
    assert len(pending.pending.upstream_verifier) >= 43


@pytest.mark.parametrize(
    "overrides",
    [
        {"resource": "https://other-server.example.com/mcp"},
        {"resource": "https://mcp.example.com/other"},
        {"code_challenge": "too-short"},
        {"code_challenge": "!" * 43},
        {"code_challenge": "a" * 44},
    ],
)
async def test_authorize_rejects_bad_requests(build, overrides) -> None:
    provider = build()
    client = await register(provider)
    with pytest.raises(AuthorizeError) as info:
        await provider.authorize(client, params(**overrides))
    assert info.value.error == "invalid_request"


async def test_authorize_rejects_scopes_beyond_mcp(build) -> None:
    provider = build()
    client = await register(provider)
    with pytest.raises(AuthorizeError) as info:
        await provider.authorize(client, params(scopes=["mcp", "admin"]))
    assert info.value.error == "invalid_scope"


async def test_authorize_rechecks_redirect_host_against_current_allowlist(build) -> None:
    client = await register(build())
    tightened = build(server_extra={"allowed_redirect_hosts": ["claude.com"]})
    with pytest.raises(AuthorizeError) as info:
        await tightened.authorize(client, params())
    assert info.value.error == "invalid_request"


async def test_authorize_accepts_origin_as_resource_or_none(build) -> None:
    provider = build()
    client = await register(provider)
    await provider.authorize(client, params(resource="https://mcp.example.com"))
    await provider.authorize(client, params(resource=None))


async def test_pending_request_is_single_use(build) -> None:
    provider = build()
    client = await register(provider)
    url = await provider.authorize(client, params())
    request_id = parse_qs(urlsplit(url).query)["request"][0]
    assert await provider.take_pending(request_id) is not None
    assert await provider.take_pending(request_id) is None
    assert await provider.load_pending(request_id) is None


async def test_denied_redirect_carries_error_and_state(build) -> None:
    provider = build()
    client = await register(provider)
    url = await provider.authorize(client, params())
    pending = await provider.take_pending(parse_qs(urlsplit(url).query)["request"][0])
    assert pending is not None
    query = parse_qs(urlsplit(provider.denied_redirect(pending)).query)
    assert query == {"error": ["access_denied"], "state": ["client-state"]}


# ── codes ───────────────────────────────────────────────────────────────────


async def test_code_is_single_use_and_bound_to_client(build) -> None:
    provider = build()
    client = await register(provider)
    other = await register(provider, "client-2")
    code = await issue_code(provider, client, KEREM, None)
    assert await provider.load_authorization_code(other, code) is None
    loaded = await provider.load_authorization_code(client, code)
    assert loaded is not None
    assert loaded.code_challenge == pkce_challenge(VERIFIER)
    assert str(loaded.redirect_uri) == REDIRECT
    assert loaded.resource == "https://mcp.example.com/mcp"
    assert loaded.subject == "kerem"
    tokens = await provider.exchange_authorization_code(client, loaded)
    assert tokens.access_token and tokens.refresh_token and tokens.expires_in == 3600
    assert await provider.load_authorization_code(client, code) is None
    with pytest.raises(TokenError) as info:
        await provider.exchange_authorization_code(client, loaded)
    assert info.value.error == "invalid_grant"


async def test_code_is_stored_only_as_hash(build, tmp_path) -> None:
    provider = build()
    client = await register(provider)
    code = await issue_code(provider, client, KEREM, None)
    dump = "\n".join(sqlite3.connect(tmp_path / "state.db").iterdump())
    assert code not in dump and hash_token(code) in dump


async def test_code_expires_after_five_minutes(build, clock) -> None:
    provider = build()
    client = await register(provider)
    code = await issue_code(provider, client, KEREM, None)
    loaded = await provider.load_authorization_code(client, code)
    assert loaded is not None
    clock.advance(301)
    assert await provider.load_authorization_code(client, code) is None
    with pytest.raises(TokenError):
        await provider.exchange_authorization_code(client, loaded)


async def test_pending_request_expires_after_ten_minutes(build, clock) -> None:
    provider = build()
    client = await register(provider)
    url = await provider.authorize(client, params())
    clock.advance(601)
    assert await provider.load_pending(parse_qs(urlsplit(url).query)["request"][0]) is None


async def test_code_without_requested_scope_gets_the_default(build) -> None:
    provider = build()
    client = await register(provider)
    url = await provider.authorize(client, params(scopes=None))
    pending = await provider.take_pending(parse_qs(urlsplit(url).query)["request"][0])
    assert pending is not None
    code = parse_qs(urlsplit(await provider.complete_authorization(pending, KEREM, None)).query)["code"][0]
    loaded = await provider.load_authorization_code(client, code)
    assert loaded is not None and loaded.scopes == ["mcp"]


async def test_stdio_principal_never_gets_a_code(build) -> None:
    provider = build()
    client = await register(provider)
    url = await provider.authorize(client, params())
    pending = await provider.take_pending(parse_qs(urlsplit(url).query)["request"][0])
    assert pending is not None
    with pytest.raises(ValueError):
        await provider.complete_authorization(pending, Principal("stdio", "s", frozenset(), "stdio"), None)


# ── access tokens ───────────────────────────────────────────────────────────


async def test_tokens_are_stored_only_as_hashes(build, tmp_path) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    dump = "\n".join(sqlite3.connect(tmp_path / "state.db").iterdump())
    assert tokens.access_token not in dump and tokens.refresh_token not in dump
    assert hash_token(tokens.access_token) in dump


async def test_access_token_carries_identity(build) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    access = await provider.load_access_token(tokens.access_token)
    assert access is not None
    assert (access.subject, access.display_name, access.groups, access.auth_source) == (
        "kerem",
        "kerem",
        ["admins"],
        "local",
    )
    assert access.client_id == "client-1" and access.scopes == ["mcp"]
    assert access.resource == "https://mcp.example.com/mcp"
    assert await provider.load_access_token("not-a-token") is None
    assert await provider.load_access_token(tokens.refresh_token) is None


async def test_access_token_expires(build, clock) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    clock.advance(3601)
    assert await provider.load_access_token(tokens.access_token) is None


async def test_local_groups_follow_configuration(build, password_hash) -> None:
    issuing = build(local=local_users(password_hash, ["admins"]))
    client = await register(issuing)
    tokens = await tokens_for(issuing, client)
    regrouped = build(local=local_users(password_hash, ["analyst"]))
    access = await regrouped.load_access_token(tokens.access_token)
    assert access is not None and access.groups == ["analyst"]


async def test_removed_local_user_loses_access(build, password_hash) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    without_user = build(local=LocalIdentityProvider([]))
    assert await without_user.load_access_token(tokens.access_token) is None


# ── refresh rotation and reuse detection ───────────────────────────────────


async def refresh(provider, client, refresh_token: str):
    loaded = await provider.load_refresh_token(client, refresh_token)
    assert loaded is not None
    return await provider.exchange_refresh_token(client, loaded, loaded.scopes)


async def test_refresh_rotates_both_tokens(build) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    second = await refresh(provider, client, first.refresh_token)
    assert second.refresh_token != first.refresh_token and second.access_token != first.access_token
    assert second.expires_in == 3600 and second.scope == "mcp"
    assert await provider.load_access_token(first.access_token) is None
    assert await provider.load_access_token(second.access_token) is not None


async def test_refresh_cannot_widen_scopes(build) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    loaded = await provider.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError) as info:
        await provider.exchange_refresh_token(client, loaded, ["mcp", "admin"])
    assert info.value.error == "invalid_scope"
    assert await provider.load_access_token(first.access_token) is not None


async def test_refresh_reuse_revokes_the_family(build, audit) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    second = await refresh(provider, client, first.refresh_token)
    assert await provider.load_refresh_token(client, first.refresh_token) is None
    assert "token_reuse_detected" in audit.names()
    event = next(e for e in audit.events if e.tool == "token_reuse_detected")
    assert (event.subject, event.auth_source, event.connection) == ("kerem", "local", None)
    assert event.result == "denied" and event.error_class == "token_reuse_detected"
    assert await provider.load_access_token(second.access_token) is None
    assert await provider.load_refresh_token(client, second.refresh_token) is None


async def test_concurrent_refresh_is_treated_as_reuse(build, audit) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    loaded_a = await provider.load_refresh_token(client, first.refresh_token)
    loaded_b = await provider.load_refresh_token(client, first.refresh_token)
    assert loaded_a is not None and loaded_b is not None
    winner = await provider.exchange_refresh_token(client, loaded_a, ["mcp"])
    with pytest.raises(TokenError) as info:
        await provider.exchange_refresh_token(client, loaded_b, ["mcp"])
    assert info.value.error == "invalid_grant"
    assert "token_reuse_detected" in audit.names()
    assert await provider.load_access_token(winner.access_token) is None


async def test_refresh_token_belongs_to_its_client(build) -> None:
    provider = build()
    client = await register(provider)
    other = await register(provider, "client-2")
    first = await tokens_for(provider, client)
    assert await provider.load_refresh_token(other, first.refresh_token) is None
    assert await provider.load_refresh_token(client, first.access_token) is None


async def test_refresh_token_expires(build, clock) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    clock.advance(30 * 86400 + 1)
    assert await provider.load_refresh_token(client, first.refresh_token) is None


async def test_refresh_fails_for_removed_local_user(build, password_hash) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    without_user = build(local=LocalIdentityProvider([]))
    loaded = await without_user.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError):
        await without_user.exchange_refresh_token(client, loaded, ["mcp"])
    assert await provider.load_refresh_token(client, first.refresh_token) is None


# ── revoke ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("which", ["access", "refresh"])
async def test_revoke_kills_the_whole_family(build, audit, which) -> None:
    provider = build()
    client = await register(provider)
    tokens = await tokens_for(provider, client)
    if which == "access":
        target = await provider.load_access_token(tokens.access_token)
    else:
        target = await provider.load_refresh_token(client, tokens.refresh_token)
    assert target is not None
    await provider.revoke_token(target)
    assert await provider.load_access_token(tokens.access_token) is None
    assert await provider.load_refresh_token(client, tokens.refresh_token) is None
    assert audit.names().count("token_revoked") == 1
    event = next(e for e in audit.events if e.tool == "token_revoked")
    assert event.result == "ok" and event.error_class is None
    await provider.revoke_token(target)
    assert audit.names().count("token_revoked") == 1


async def test_revoking_one_family_leaves_others(build) -> None:
    provider = build()
    client = await register(provider)
    first = await tokens_for(provider, client)
    second = await tokens_for(provider, client)
    target = await provider.load_access_token(first.access_token)
    assert target is not None
    await provider.revoke_token(target)
    assert await provider.load_access_token(second.access_token) is not None


# ── OIDC upstream re-validation ─────────────────────────────────────────────


async def test_oidc_refresh_rereads_groups_and_reseals_upstream(build, tmp_path) -> None:
    upstream = FakeUpstream()
    upstream.result = ExternalLogin(
        Principal(ALICE.subject, ALICE.display_name, frozenset({"analyst"}), "oidc"), "up-2"
    )
    provider = build(mode="oidc", oidc=upstream)
    client = await register(provider)
    first = await tokens_for(provider, client, ALICE, upstream="up-1")
    second = await refresh(provider, client, first.refresh_token)
    assert upstream.refreshed_with == ["up-1"]
    access = await provider.load_access_token(second.access_token)
    assert access is not None and access.groups == ["analyst"] and access.auth_source == "oidc"
    third = await refresh(provider, client, second.refresh_token)
    assert upstream.refreshed_with == ["up-1", "up-2"]
    assert third.access_token
    dump = "\n".join(sqlite3.connect(tmp_path / "state.db").iterdump())
    assert "up-1" not in dump and "up-2" not in dump


@pytest.mark.parametrize("failure", [UpstreamRejectedError("inactive"), None])
async def test_oidc_upstream_failure_revokes_family(build, audit, failure) -> None:
    upstream = FakeUpstream()
    provider = build(mode="oidc", oidc=upstream)
    client = await register(provider)
    first = await tokens_for(provider, client, ALICE, upstream=None if failure is None else "up-1")
    if failure is not None:
        upstream.result = failure
    loaded = await provider.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError) as info:
        await provider.exchange_refresh_token(client, loaded, ["mcp"])
    assert info.value.error == "invalid_grant"
    assert "upstream_refresh_failed" in audit.names()
    event = next(e for e in audit.events if e.tool == "upstream_refresh_failed")
    assert event.result == "denied" and event.error_class == "upstream_refresh_failed"
    assert await provider.load_access_token(first.access_token) is None


async def test_oidc_upstream_sealed_under_other_key_revokes_family(build, audit) -> None:
    upstream = FakeUpstream()
    provider = build(mode="oidc", oidc=upstream)
    client = await register(provider)
    first = await tokens_for(provider, client, ALICE, upstream="up-1")
    rekeyed = build(mode="oidc", oidc=upstream, keyring=Keyring("z" * 48))
    # the client secret is unreadable under the new key too; use the client object from before
    loaded = await rekeyed.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError) as info:
        await rekeyed.exchange_refresh_token(client, loaded, ["mcp"])
    assert info.value.error == "invalid_grant"
    assert upstream.refreshed_with == []
    assert "upstream_refresh_failed" in audit.names()
    assert await provider.load_access_token(first.access_token) is None


async def test_oidc_subject_change_revokes_family(build, audit) -> None:
    upstream = FakeUpstream()
    upstream.result = ExternalLogin(Principal("mallory@example.com", "M", frozenset(), "oidc"), "up-2")
    provider = build(mode="oidc", oidc=upstream)
    client = await register(provider)
    first = await tokens_for(provider, client, ALICE, upstream="up-1")
    loaded = await provider.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError):
        await provider.exchange_refresh_token(client, loaded, ["mcp"])
    assert await provider.load_access_token(first.access_token) is None
    assert "upstream_refresh_failed" in audit.names()


async def test_oidc_outage_keeps_the_family(build, audit) -> None:
    upstream = FakeUpstream()
    upstream.result = UpstreamUnavailableError("timeout")
    provider = build(mode="oidc", oidc=upstream)
    client = await register(provider)
    first = await tokens_for(provider, client, ALICE, upstream="up-1")
    loaded = await provider.load_refresh_token(client, first.refresh_token)
    assert loaded is not None
    with pytest.raises(TokenError) as info:
        await provider.exchange_refresh_token(client, loaded, ["mcp"])
    assert info.value.error == "invalid_request"
    assert await provider.load_access_token(first.access_token) is not None
    event = next(e for e in audit.events if e.tool == "upstream_refresh_failed")
    assert event.result == "error" and event.error_class == "upstream_unavailable"
    upstream.result = ExternalLogin(ALICE, None)
    assert (await refresh(provider, client, first.refresh_token)).access_token
    assert upstream.refreshed_with == ["up-1", "up-1"]


# ── secrets stay out of logs and error texts ────────────────────────────────


async def test_no_token_or_secret_in_logs_or_errors(build, caplog) -> None:
    upstream = FakeUpstream()
    provider = build(mode="oidc", oidc=upstream)
    with caplog.at_level(logging.DEBUG):
        client = await register(provider)
        first = await tokens_for(provider, client, ALICE, upstream="up-1")
        second = await refresh(provider, client, first.refresh_token)
        loaded = await provider.load_refresh_token(client, first.refresh_token)  # reuse
        assert loaded is None
        upstream.result = UpstreamRejectedError("inactive")
        errors: list[str] = []
        for token in (first.refresh_token, second.refresh_token):
            try:
                again = await provider.load_refresh_token(client, token)
                if again is not None:
                    await provider.exchange_refresh_token(client, again, ["mcp"])
            except TokenError as exc:
                errors.append(f"{exc.error} {exc.error_description}")
    secrets = [CLIENT_SECRET, "up-1", "up-2", first.access_token, first.refresh_token]
    secrets += [second.access_token, second.refresh_token]
    for secret in secrets:
        assert secret not in caplog.text
        assert all(secret not in text for text in errors)
