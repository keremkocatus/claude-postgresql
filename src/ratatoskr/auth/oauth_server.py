"""MCP OAuth 2.1 authorization server backed by the state store (spec §5.2).

The SDK handlers already enforce: ``code_challenge`` present and method ``S256`` (``/authorize``), redirect_uri
registered for the client, scope within the client's registered scope, PKCE verifier match, redirect_uri equality
between ``/authorize`` and ``/token``, code and refresh-token expiry, client authentication and refresh scope
narrowing. This provider adds what the SDK leaves to us: the redirect host allowlist, S256 challenge shape, RFC 8707
resource binding, the ``mcp`` scope limit, request and metadata size limits, single-use codes, hashed storage, an
absolute session lifetime (``auth.session_max_age``), refresh rotation with a short retry grace and reuse detection,
family revocation, local password-change detection and upstream (OIDC) re-validation.

Error descriptions returned to clients are fixed texts. Logs name the subject and client id, never a token, code,
client secret, password hash or upstream refresh token.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
import secrets
import weakref
from dataclasses import dataclass
from typing import NoReturn
from urllib.parse import urlencode

from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import ValidationError

from ratatoskr.auth.crypto import DecryptionError, Keyring, hash_token, new_token
from ratatoskr.auth.events import record_auth_event
from ratatoskr.auth.identity.base import (
    IdentityError,
    PasswordIdentityProvider,
    RedirectIdentityProvider,
    UpstreamRejectedError,
    UpstreamUnavailableError,
)
from ratatoskr.auth.identity.local import normalize_username
from ratatoskr.auth.principal import Principal
from ratatoskr.auth.redirects import MAX_REDIRECT_URI_LENGTH, redirect_uri_problem
from ratatoskr.auth.tokens import AuthSource, RatatoskrAccessToken, RatatoskrRefreshToken
from ratatoskr.config.models import RatatoskrConfig
from ratatoskr.observability.audit import AuditSink
from ratatoskr.state.records import (
    AuthCodeRecord,
    Clock,
    PendingAuthorization,
    StoredClient,
    TokenFamily,
    TokenKind,
    TokenRecord,
)
from ratatoskr.state.store import Store

logger = logging.getLogger("ratatoskr.auth.oauth")

PENDING_TTL_SECONDS = 600.0
CODE_TTL_SECONDS = 300.0
# Short on purpose: a thief who refreshes first survives a victim retry inside this window (review Q5).
REFRESH_GRACE_SECONDS = 5.0
DEFAULT_SCOPES = ("mcp",)
MAX_REDIRECT_URIS = 10
MAX_STATE_LENGTH = 512
MAX_SCOPES = 4
MAX_CLIENT_NAME_LENGTH = 200
MAX_CONTACTS = 5
MAX_CONTACT_LENGTH = 254
MAX_CLIENT_METADATA_BYTES = 8192
MCP_PATH = "/mcp"
_ALLOWED_SCOPES = frozenset(DEFAULT_SCOPES)
_S256_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{43}")
_SUPPORTED_CLIENT_AUTH = frozenset({"none", "client_secret_post", "client_secret_basic"})
_MAX_LOGGED_NAME = 100


def _client_id(client: OAuthClientInformationFull) -> str:
    if client.client_id is None:
        raise RegistrationError("invalid_client_metadata", "client_id is missing")
    return client.client_id


def _source(principal: Principal) -> AuthSource:
    if principal.auth_source == "stdio":
        raise ValueError("stdio principals never receive OAuth tokens")
    return principal.auth_source


def _unique(scopes: list[str] | tuple[str, ...]) -> list[str]:
    return list(dict.fromkeys(scopes))


def _code_aad(subject: str) -> str:
    """Associated data of an upstream refresh token while it waits in an authorization code."""
    return json.dumps(["code", subject])


def _family_aad(subject: str, family_id: str) -> str:
    """Associated data of an upstream refresh token stored for a token family: subject and family, unambiguously."""
    return json.dumps(["family", subject, family_id])


def _metadata_problem(client: OAuthClientInformationFull) -> str | None:
    """Why the client metadata is unsupported or too large, or ``None``. Texts never echo the values."""
    if client.jwks is not None or client.jwks_uri is not None:
        return "jwks and jwks_uri are not supported"
    if client.client_name is not None and len(client.client_name) > MAX_CLIENT_NAME_LENGTH:
        return f"client_name is longer than {MAX_CLIENT_NAME_LENGTH} characters"
    contacts = client.contacts or []
    if len(contacts) > MAX_CONTACTS or any(len(contact) > MAX_CONTACT_LENGTH for contact in contacts):
        return f"at most {MAX_CONTACTS} contacts of at most {MAX_CONTACT_LENGTH} characters are allowed"
    for name in ("client_uri", "logo_uri", "tos_uri", "policy_uri"):
        value = getattr(client, name)
        if value is not None and len(str(value)) > MAX_REDIRECT_URI_LENGTH:
            return f"{name} is longer than {MAX_REDIRECT_URI_LENGTH} characters"
    return None


@dataclass(frozen=True)
class PendingRequest:
    """A pending authorization joined with its client and the original ``/authorize`` parameters."""

    pending: PendingAuthorization
    client: OAuthClientInformationFull
    params: AuthorizationParams


class RatatoskrOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RatatoskrRefreshToken, RatatoskrAccessToken]
):
    def __init__(
        self,
        config: RatatoskrConfig,
        *,
        store: Store,
        keyring: Keyring,
        audit: AuditSink,
        clock: Clock,
        local: PasswordIdentityProvider | None = None,
        oidc: RedirectIdentityProvider | None = None,
    ) -> None:
        if config.auth is None or config.server.public_url is None:
            raise ValueError("the OAuth provider needs auth settings and server.public_url")
        self._public_url = str(config.server.public_url).rstrip("/")
        self.resource_url = self._public_url + MCP_PATH
        self._resources = frozenset({self._public_url, self.resource_url})
        self._allowed_hosts = list(config.server.allowed_redirect_hosts)
        self._access_ttl = config.auth.access_token_ttl.total_seconds()
        self._refresh_ttl = config.auth.refresh_token_ttl.total_seconds()
        self._max_age = config.auth.session_max_age.total_seconds()
        # Configured password hashes, only ever used through their keyed fingerprint.
        users = config.auth.local.users if config.auth.local is not None else []
        self._password_hashes = {normalize_username(u.username): u.password_hash.get_secret_value() for u in users}
        self._store = store
        self._keyring = keyring
        self._audit = audit
        self._clock = clock
        self._local = local
        self._oidc = oidc
        self._family_locks: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()

    # ── clients (DCR) ───────────────────────────────────────────────────

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """The registered client, or ``None``; anything that cannot be read back intact counts as unknown.

        ``None`` makes the SDK answer ``invalid_client`` and the client registers again. A confidential client is
        never returned without its secret: the SDK skips the secret check when ``client_secret`` is empty.
        """
        stored = await self._store.get_client(client_id)
        if stored is None:
            return None
        try:
            client = OAuthClientInformationFull.model_validate_json(stored.metadata_json)
        except ValidationError:
            logger.warning("client %s has unreadable stored metadata; treating it as unknown", client_id)
            return None
        if stored.secret_blob is None:
            if client.token_endpoint_auth_method != "none":
                logger.warning("client %s requires a secret but none is stored; treating it as unknown", client_id)
                return None
            return client
        try:
            secret = self._keyring.client_secrets.open(stored.secret_blob, aad=client_id)
        except DecryptionError as exc:
            logger.warning(
                "client %s secret cannot be opened (%s; e.g. server.secret_key changed); treating it as unknown",
                client_id,
                exc.reason,
            )
            return None
        return client.model_copy(update={"client_secret": secret})

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        client_id = _client_id(client_info)
        method = client_info.token_endpoint_auth_method
        if method not in _SUPPORTED_CLIENT_AUTH:
            raise RegistrationError(
                "invalid_client_metadata",
                "token_endpoint_auth_method must be none, client_secret_post or client_secret_basic",
            )
        if method != "none" and not client_info.client_secret:
            raise RegistrationError("invalid_client_metadata", "a confidential client needs a client_secret")
        if client_info.scope is not None and not set(client_info.scope.split()) <= _ALLOWED_SCOPES:
            raise RegistrationError("invalid_client_metadata", "the only supported scope is 'mcp'")
        problem = _metadata_problem(client_info)
        if problem is not None:
            raise RegistrationError("invalid_client_metadata", problem)
        uris = client_info.redirect_uris or []
        if not uris:
            raise RegistrationError("invalid_redirect_uri", "at least one redirect_uri is required")
        if len(uris) > MAX_REDIRECT_URIS:
            raise RegistrationError("invalid_redirect_uri", f"at most {MAX_REDIRECT_URIS} redirect_uris are allowed")
        for uri in uris:
            problem = redirect_uri_problem(str(uri), self._allowed_hosts)
            if problem is not None:
                raise RegistrationError("invalid_redirect_uri", problem)
        metadata = client_info.model_copy(update={"client_secret": None}).model_dump_json(exclude_none=True)
        if len(metadata.encode("utf-8")) > MAX_CLIENT_METADATA_BYTES:
            raise RegistrationError(
                "invalid_client_metadata", f"client metadata is larger than {MAX_CLIENT_METADATA_BYTES} bytes"
            )
        secret_blob = (
            self._keyring.client_secrets.seal(client_info.client_secret, aad=client_id)
            if method != "none" and client_info.client_secret
            else None
        )
        await self._store.save_client(StoredClient(client_id, metadata, secret_blob, self._clock()))
        name = (client_info.client_name or "unnamed")[:_MAX_LOGGED_NAME]
        logger.info("registered OAuth client %s (%s)", client_id, name)

    # ── authorization ───────────────────────────────────────────────────

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        if params.resource is not None and params.resource.rstrip("/") not in self._resources:
            raise AuthorizeError("invalid_request", "resource does not identify this MCP server")
        if not _S256_CHALLENGE.fullmatch(params.code_challenge):
            raise AuthorizeError("invalid_request", "code_challenge must be a base64url S256 challenge")
        if params.state is not None and len(params.state) > MAX_STATE_LENGTH:
            raise AuthorizeError("invalid_request", f"state is longer than {MAX_STATE_LENGTH} characters")
        if params.scopes is not None and len(_unique(params.scopes)) > MAX_SCOPES:
            raise AuthorizeError("invalid_request", f"at most {MAX_SCOPES} scopes may be requested")
        if params.scopes is not None and not set(params.scopes) <= _ALLOWED_SCOPES:
            raise AuthorizeError("invalid_scope", "the only supported scope is 'mcp'")
        # The allowlist may have been tightened since the client registered.
        if redirect_uri_problem(str(params.redirect_uri), self._allowed_hosts) is not None:
            raise AuthorizeError("invalid_request", "redirect_uri is not allowed by this server")
        pending_id = new_token()
        oidc_flow = self._oidc is not None
        await self._store.save_pending(
            PendingAuthorization(
                id=pending_id,
                client_id=_client_id(client),
                params_json=params.model_dump_json(),
                expires_at=self._clock() + PENDING_TTL_SECONDS,
                nonce=new_token() if oidc_flow else None,
                upstream_verifier=secrets.token_urlsafe(64) if oidc_flow else None,
            )
        )
        return f"{self._public_url}/login?{urlencode({'request': pending_id})}"

    async def _join(self, pending: PendingAuthorization | None) -> PendingRequest | None:
        if pending is None:
            return None
        client = await self.get_client(pending.client_id)
        if client is None:
            return None
        return PendingRequest(pending, client, AuthorizationParams.model_validate_json(pending.params_json))

    async def load_pending(self, pending_id: str) -> PendingRequest | None:
        return await self._join(await self._store.get_pending(pending_id, self._clock()))

    async def take_pending(self, pending_id: str) -> PendingRequest | None:
        """Consume the pending authorization (single use); ``None`` if missing, expired or its client is gone."""
        return await self._join(await self._store.take_pending(pending_id, self._clock()))

    async def complete_authorization(
        self, request: PendingRequest, principal: Principal, upstream_refresh_token: str | None
    ) -> str:
        """Issue a single-use code for ``principal`` and return the client redirect URL carrying it.

        The upstream refresh token is sealed for this subject; the code exchange re-seals it for the token family.
        """
        _source(principal)
        code = new_token()
        upstream_blob = (
            self._keyring.upstream.seal(upstream_refresh_token, aad=_code_aad(principal.subject))
            if upstream_refresh_token
            else None
        )
        await self._store.save_code(
            AuthCodeRecord(
                code_hash=hash_token(code),
                client_id=request.pending.client_id,
                params_json=request.pending.params_json,
                principal=principal,
                upstream_blob=upstream_blob,
                expires_at=self._clock() + CODE_TTL_SECONDS,
            )
        )
        return construct_redirect_uri(str(request.params.redirect_uri), code=code, state=request.params.state)

    @staticmethod
    def denied_redirect(request: PendingRequest) -> str:
        return construct_redirect_uri(
            str(request.params.redirect_uri), error="access_denied", state=request.params.state
        )

    # ── authorization codes ─────────────────────────────────────────────

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        record = await self._store.get_code(hash_token(authorization_code), self._clock())
        if record is None or record.client_id != client.client_id:
            return None
        params = AuthorizationParams.model_validate_json(record.params_json)
        return AuthorizationCode(
            code=authorization_code,
            scopes=_unique(params.scopes or DEFAULT_SCOPES),
            expires_at=record.expires_at,
            client_id=record.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=record.principal.subject,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Consume the code and start a token family.

        A replayed code gets ``invalid_grant`` but does not revoke the tokens issued from it (RFC 6749 §4.1.2 says
        SHOULD). The SDK checks the PKCE verifier before this runs, so a replay needs the verifier, which never
        leaves the legitimate client; the atomic delete makes the code single use; and the usual replay is that
        client retrying a ``/token`` call whose response it lost, which must not end the session it just started.
        """
        now = self._clock()
        record = await self._store.take_code(hash_token(authorization_code.code), now)
        if record is None or record.client_id != client.client_id:
            raise TokenError("invalid_grant", "authorization code is invalid or was already used")
        principal = record.principal
        fingerprint: str | None = None
        if principal.auth_source == "local":
            fingerprint = self._password_fingerprint(principal.subject)
            if fingerprint is None:
                raise TokenError("invalid_grant", "the user no longer exists")
        family_id = new_token()
        upstream_blob: bytes | None = None
        if record.upstream_blob is not None:
            try:
                upstream = self._keyring.upstream.open(record.upstream_blob, aad=_code_aad(principal.subject))
            except DecryptionError as exc:
                logger.warning("upstream session of a code for %s cannot be opened (%s)", principal.subject, exc.reason)
                raise TokenError("invalid_grant", "authorization code is invalid or was already used") from None
            upstream_blob = self._keyring.upstream.seal(upstream, aad=_family_aad(principal.subject, family_id))
        params = AuthorizationParams.model_validate_json(record.params_json)
        access, refresh, response = self._new_pair(
            family_id=family_id,
            client_id=record.client_id,
            scopes=_unique(params.scopes or DEFAULT_SCOPES),
            principal=principal,
            now=now,
            session_end=now + self._max_age,
        )
        await self._store.create_family(access, refresh, upstream_blob, password_fingerprint=fingerprint)
        return response

    # ── tokens ──────────────────────────────────────────────────────────

    def _new_pair(
        self,
        *,
        family_id: str,
        client_id: str,
        scopes: list[str],
        principal: Principal,
        now: float,
        session_end: float,
    ) -> tuple[TokenRecord, TokenRecord, OAuthToken]:
        """A new access/refresh pair; neither outlives the family's absolute session end."""
        access_token = new_token()
        refresh_token = new_token()
        access_expires = min(now + self._access_ttl, session_end)
        refresh_expires = min(now + self._refresh_ttl, session_end)

        def record(token: str, kind: TokenKind, expires_at: float) -> TokenRecord:
            return TokenRecord(
                token_hash=hash_token(token),
                kind=kind,
                family_id=family_id,
                client_id=client_id,
                scopes=tuple(scopes),
                resource=self.resource_url,
                principal=principal,
                created_at=now,
                expires_at=expires_at,
            )

        response = OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=int(access_expires - now),
            refresh_token=refresh_token,
            scope=" ".join(scopes),
        )
        return (
            record(access_token, "access", access_expires),
            record(refresh_token, "refresh", refresh_expires),
            response,
        )

    def _password_fingerprint(self, subject: str) -> str | None:
        """Keyed fingerprint of the configured password hash of ``subject``; ``None`` if the user is not configured."""
        stored = self._password_hashes.get(normalize_username(subject))
        return None if stored is None else self._keyring.password_fingerprint.sign(stored)

    def _password_changed(self, family: TokenFamily) -> bool:
        current = self._password_fingerprint(family.subject)
        recorded = family.password_fingerprint
        if current is None or recorded is None:
            return True
        return not hmac.compare_digest(current.encode("ascii"), recorded.encode("ascii"))

    def _family_problem(self, family: TokenFamily | None, principal: Principal, now: float) -> str | None:
        """Why tokens of this family are no longer valid: unknown family, session too old or password changed."""
        if family is None:
            return "unknown token family"
        if now >= family.created_at + self._max_age:
            return "session max age reached"
        if principal.auth_source == "local" and self._password_changed(family):
            return "password changed"
        return None

    async def load_access_token(self, token: str) -> RatatoskrAccessToken | None:
        record = await self._store.get_token(hash_token(token))
        if record is None or record.kind != "access" or record.revoked_at is not None:
            return None
        now = self._clock()
        if record.expires_at <= now or record.principal.auth_source == "stdio":
            return None
        if self._family_problem(await self._store.get_family(record.family_id), record.principal, now) is not None:
            return None
        principal = record.principal
        if principal.auth_source == "local":
            # Groups follow the configuration on every request; a removed user loses access at once.
            current = self._local.lookup(principal.subject) if self._local is not None else None
            if current is None:
                return None
            principal = current
        return RatatoskrAccessToken(
            token=token,
            client_id=record.client_id,
            scopes=list(record.scopes),
            expires_at=int(record.expires_at),
            resource=record.resource,
            subject=principal.subject,
            display_name=principal.display_name,
            groups=sorted(principal.groups),
            auth_source=_source(principal),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RatatoskrRefreshToken | None:
        record = await self._store.get_token(hash_token(refresh_token))
        if record is None or record.kind != "refresh" or record.client_id != client.client_id:
            return None
        now = self._clock()
        if record.revoked_at is not None or record.expires_at <= now or record.principal.auth_source == "stdio":
            return None
        problem = self._family_problem(await self._store.get_family(record.family_id), record.principal, now)
        if problem is not None:
            await self._end_family(record, problem, now)
            return None
        if record.used_at is not None:
            await self._refuse_used(record, now)
            return None
        return RatatoskrRefreshToken(
            token=refresh_token,
            client_id=record.client_id,
            scopes=list(record.scopes),
            expires_at=int(record.expires_at),
            resource=record.resource,
            family_id=record.family_id,
            subject=record.principal.subject,
            display_name=record.principal.display_name,
            groups=sorted(record.principal.groups),
            auth_source=_source(record.principal),
        )

    async def _end_family(self, record: TokenRecord, problem: str, now: float) -> None:
        """A password change revokes the family; an expired session or a missing family just stops working."""
        if problem == "password changed" and await self._store.revoke_family(record.family_id, now):
            logger.warning("password of %s changed; token family revoked", record.principal.subject)

    async def _refuse_used(self, record: TokenRecord, now: float) -> None:
        """A rotated refresh token came back: a retry inside the grace window, or reuse (revoke the family)."""
        if record.used_at is not None and now - record.used_at < REFRESH_GRACE_SECONDS:
            self._report_retry(record.principal)
            return
        if await self._store.revoke_family(record.family_id, now):
            self._report_reuse(record.principal)

    def _family_lock(self, family_id: str) -> asyncio.Lock:
        """Serialises refreshes of one family in this process (re-check, upstream refresh and rotation).

        A plain lock rather than a context-manager generator: the SDK's ``TokenError`` is a frozen dataclass, and
        ``contextlib`` cannot set ``__traceback__`` on it while re-raising. Callers hold the returned lock, which
        keeps it in the weak map for as long as it is in use.
        """
        lock = self._family_locks.get(family_id)
        if lock is None:
            lock = asyncio.Lock()
            self._family_locks[family_id] = lock
        return lock

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: RatatoskrRefreshToken, scopes: list[str]
    ) -> OAuthToken:
        requested = _unique(scopes or refresh_token.scopes)
        # The SDK already refuses scopes beyond the refresh token's; this is the provider's own guarantee.
        if not set(requested) <= set(refresh_token.scopes) or not set(requested) <= _ALLOWED_SCOPES:
            raise TokenError("invalid_scope", "requested scope exceeds the scope of the refresh token")
        old_hash = hash_token(refresh_token.token)
        async with self._family_lock(refresh_token.family_id):
            now = self._clock()
            # Re-check under the lock: a concurrent refresh of the same token may have rotated it meanwhile.
            record = await self._store.get_token(old_hash)
            if (
                record is None
                or record.kind != "refresh"
                or record.client_id != client.client_id
                or record.revoked_at is not None
                or record.expires_at <= now
                or record.principal.auth_source == "stdio"
            ):
                raise TokenError("invalid_grant", "refresh token is no longer valid")
            family = await self._store.get_family(record.family_id)
            problem = self._family_problem(family, record.principal, now)
            if family is None or problem is not None:
                await self._end_family(record, problem or "unknown token family", now)
                raise TokenError("invalid_grant", "refresh token is no longer valid")
            if record.used_at is not None:
                await self._refuse_used(record, now)
                raise TokenError("invalid_grant", "refresh token was already used")
            principal = record.principal
            upstream_blob: bytes | None = None
            if principal.auth_source == "oidc":
                principal, upstream_blob = await self._refresh_upstream(record.family_id, principal, now)
            else:
                current = self._local.lookup(principal.subject) if self._local is not None else None
                if current is None:
                    await self._store.revoke_family(record.family_id, now)
                    logger.warning("refresh refused for %s: the local user no longer exists", principal.subject)
                    raise TokenError("invalid_grant", "the user no longer exists")
                principal = current
            access, refresh, response = self._new_pair(
                family_id=record.family_id,
                client_id=record.client_id,
                scopes=requested,
                principal=principal,
                now=now,
                session_end=family.created_at + self._max_age,
            )
            outcome = await self._store.rotate_refresh(
                old_hash, access, refresh, upstream_blob, now, max_age=self._max_age, grace=REFRESH_GRACE_SECONDS
            )
        if outcome == "reused":
            self._report_reuse(principal)
            raise TokenError("invalid_grant", "refresh token was already used; the session has been revoked")
        if outcome == "retry":
            self._report_retry(principal)
            raise TokenError("invalid_grant", "refresh token was already used")
        if outcome == "invalid":
            raise TokenError("invalid_grant", "refresh token is no longer valid")
        return response

    async def _refresh_upstream(self, family_id: str, principal: Principal, now: float) -> tuple[Principal, bytes]:
        """Re-validate the session at the issuer; the new identity and the re-sealed upstream refresh token.

        - Issuer unreachable (:class:`UpstreamUnavailableError`): our tokens stay valid and the client gets
          ``invalid_request``; OAuth has no retryable token error, but the same refresh token works again later.
        - Definitive refusal (:class:`UpstreamRejectedError`), a changed subject, a missing or unopenable upstream
          session, or OIDC no longer configured: the family is revoked.
        - Any other :class:`IdentityError` (an answer that cannot be verified): ``invalid_grant`` without revoking,
          because the cause may be on the issuer's or our side rather than the user's.
        """
        if self._oidc is None:
            await self._upstream_failed(family_id, principal, now, "OIDC is not configured")
        blob = await self._store.get_upstream(family_id)
        if blob is None:
            await self._upstream_failed(family_id, principal, now, "no upstream session is stored")
        aad = _family_aad(principal.subject, family_id)
        try:
            upstream_token = self._keyring.upstream.open(blob, aad=aad)
        except DecryptionError as exc:
            await self._upstream_failed(family_id, principal, now, f"upstream session cannot be opened ({exc.reason})")
        try:
            login = await self._oidc.refresh(upstream_token)
        except UpstreamUnavailableError as exc:
            logger.warning("upstream refresh for %s deferred, issuer unavailable: %s", principal.subject, exc)
            self._report_upstream_error(principal, "upstream_unavailable")
            raise TokenError("invalid_request", "identity provider is temporarily unavailable; retry later") from exc
        except UpstreamRejectedError as exc:
            await self._upstream_failed(family_id, principal, now, str(exc))
        except IdentityError as exc:
            logger.warning("upstream refresh for %s failed, token family kept: %s", principal.subject, exc)
            self._report_upstream_error(principal, "upstream_invalid_response")
            raise TokenError("invalid_grant", "the identity provider could not confirm this session") from exc
        if login.principal.subject != principal.subject:
            await self._upstream_failed(family_id, principal, now, "upstream subject changed")
        new_upstream = login.refresh_token or upstream_token
        return login.principal, self._keyring.upstream.seal(new_upstream, aad=aad)

    async def _upstream_failed(self, family_id: str, principal: Principal, now: float, reason: str) -> NoReturn:
        await self._store.revoke_family(family_id, now)
        logger.warning("upstream refresh failed for %s; token family revoked: %s", principal.subject, reason)
        record_auth_event(
            self._audit,
            "upstream_refresh_failed",
            subject=principal.subject,
            auth_source=principal.auth_source,
            result="denied",
            error_class="upstream_refresh_failed",
        )
        raise TokenError("invalid_grant", "the identity provider no longer accepts this session")

    def _report_upstream_error(self, principal: Principal, error_class: str) -> None:
        record_auth_event(
            self._audit,
            "upstream_refresh_failed",
            subject=principal.subject,
            auth_source=principal.auth_source,
            result="error",
            error_class=error_class,
        )

    def _report_reuse(self, principal: Principal) -> None:
        logger.warning("refresh token reuse detected for %s; token family revoked", principal.subject)
        record_auth_event(
            self._audit,
            "token_reuse_detected",
            subject=principal.subject,
            auth_source=principal.auth_source,
            result="denied",
            error_class="token_reuse_detected",
        )

    def _report_retry(self, principal: Principal) -> None:
        logger.info("refresh token presented again within the grace window for %s; refused", principal.subject)
        record_auth_event(
            self._audit,
            "refresh_retry_within_grace",
            subject=principal.subject,
            auth_source=principal.auth_source,
            result="denied",
        )

    async def revoke_token(self, token: RatatoskrAccessToken | RatatoskrRefreshToken) -> None:
        """Revoke the whole family of ``token``; a no-op (and no audit event) when it is already revoked."""
        record = await self._store.get_token(hash_token(token.token))
        if record is None:
            return
        revoked = await self._store.revoke_family(record.family_id, self._clock())
        if revoked:
            record_auth_event(
                self._audit,
                "token_revoked",
                subject=record.principal.subject,
                auth_source=record.principal.auth_source,
                result="ok",
            )
