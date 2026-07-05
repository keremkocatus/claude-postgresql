from __future__ import annotations

import pytest

from claude_postgresql.auth import LoginError, SimplePasswordOAuthProvider
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull


@pytest.fixture
def provider() -> SimplePasswordOAuthProvider:
    return SimplePasswordOAuthProvider("correct-horse-battery-staple")


@pytest.fixture
def client() -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="abc123",
        redirect_uris=["https://claude.ai/api/mcp/callback"],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
    )


@pytest.fixture
def auth_params() -> AuthorizationParams:
    return AuthorizationParams(
        state="xyz",
        scopes=None,
        code_challenge="challenge123",
        redirect_uri="https://claude.ai/api/mcp/callback",
        redirect_uri_provided_explicitly=True,
    )


class TestClientRegistration:
    async def test_register_and_lookup(self, provider, client) -> None:
        await provider.register_client(client)
        assert await provider.get_client("abc123") is client

    async def test_unknown_client_returns_none(self, provider) -> None:
        assert await provider.get_client("nope") is None


class TestLoginFlow:
    async def test_wrong_password_is_retryable_and_keeps_session(self, provider, client, auth_params) -> None:
        await provider.register_client(client)
        login_url = await provider.authorize(client, auth_params)
        login_id = login_url.split("login_id=")[1]

        with pytest.raises(LoginError) as exc_info:
            await provider.complete_login(login_id, "wrong-password")
        assert exc_info.value.retryable
        assert provider.has_pending(login_id)

    async def test_unknown_login_id_is_not_retryable(self, provider) -> None:
        with pytest.raises(LoginError) as exc_info:
            await provider.complete_login("does-not-exist", "anything")
        assert not exc_info.value.retryable

    async def test_correct_password_issues_code_and_consumes_session(self, provider, client, auth_params) -> None:
        await provider.register_client(client)
        login_url = await provider.authorize(client, auth_params)
        login_id = login_url.split("login_id=")[1]

        redirect = await provider.complete_login(login_id, "correct-horse-battery-staple")

        assert redirect.startswith("https://claude.ai/api/mcp/callback?")
        assert "state=xyz" in redirect
        assert "code=" in redirect
        assert not provider.has_pending(login_id)

    async def test_login_session_cannot_be_reused(self, provider, client, auth_params) -> None:
        await provider.register_client(client)
        login_url = await provider.authorize(client, auth_params)
        login_id = login_url.split("login_id=")[1]

        await provider.complete_login(login_id, "correct-horse-battery-staple")

        with pytest.raises(LoginError):
            await provider.complete_login(login_id, "correct-horse-battery-staple")


class TestTokenLifecycle:
    async def _issue_token(self, provider, client, auth_params):
        await provider.register_client(client)
        login_url = await provider.authorize(client, auth_params)
        login_id = login_url.split("login_id=")[1]
        redirect = await provider.complete_login(login_id, "correct-horse-battery-staple")
        code = redirect.split("code=")[1].split("&")[0]
        auth_code = await provider.load_authorization_code(client, code)
        return await provider.exchange_authorization_code(client, auth_code)

    async def test_issued_access_token_verifies(self, provider, client, auth_params) -> None:
        token = await self._issue_token(provider, client, auth_params)
        access = await provider.load_access_token(token.access_token)
        assert access is not None
        assert access.client_id == "abc123"

    async def test_authorization_code_is_single_use(self, provider, client, auth_params) -> None:
        await provider.register_client(client)
        login_url = await provider.authorize(client, auth_params)
        login_id = login_url.split("login_id=")[1]
        redirect = await provider.complete_login(login_id, "correct-horse-battery-staple")
        code = redirect.split("code=")[1].split("&")[0]

        auth_code = await provider.load_authorization_code(client, code)
        await provider.exchange_authorization_code(client, auth_code)

        assert await provider.load_authorization_code(client, code) is None

    async def test_refresh_token_rotates(self, provider, client, auth_params) -> None:
        token = await self._issue_token(provider, client, auth_params)
        refresh = await provider.load_refresh_token(client, token.refresh_token)
        assert refresh is not None

        rotated = await provider.exchange_refresh_token(client, refresh, [])

        assert rotated.access_token != token.access_token
        assert await provider.load_refresh_token(client, token.refresh_token) is None
        assert await provider.load_access_token(rotated.access_token) is not None

    async def test_revoke_invalidates_access_token(self, provider, client, auth_params) -> None:
        token = await self._issue_token(provider, client, auth_params)
        access = await provider.load_access_token(token.access_token)

        await provider.revoke_token(access)

        assert await provider.load_access_token(token.access_token) is None

    async def test_wrong_client_cannot_load_anothers_token(self, provider, client, auth_params) -> None:
        token = await self._issue_token(provider, client, auth_params)
        other_client = OAuthClientInformationFull(
            client_id="other",
            redirect_uris=["https://example.com/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
        )
        assert await provider.load_refresh_token(other_client, token.refresh_token) is None
