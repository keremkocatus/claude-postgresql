"""OIDC relying party for an upstream issuer such as Authentik (spec §5.2 ``oidc``, §5.3).

Authorization code flow with PKCE (S256), ``state`` and ``nonce``. ID tokens are verified against the issuer's
JWKS (signature, ``iss``, ``sub``, ``aud``/``azp``, ``exp``, ``nbf``, ``iat``, ``nonce``); only asymmetric algorithms
and only RSA/EC signing keys are accepted, so ``alg: none`` and HMAC tokens never verify. Key locations in token
headers (``jku``, ``x5u``) are never fetched.

Upstream hardening: the issuer and every endpoint from discovery must be https (unless ``allow_insecure_http``, for
``--insecure-dev`` only); the discovery ``issuer`` must equal the configured one; every request has an overall
deadline, does not follow redirects and reads at most :data:`MAX_RESPONSE_BYTES`. The JWKS is cached for
:data:`JWKS_MAX_AGE_SECONDS` (stale-if-error: a failed age-based refetch keeps the cached keys); an unknown ``kid``
forces a refetch at most once per :data:`JWKS_REFRESH_COOLDOWN_SECONDS`, so made-up key ids cannot make us hammer
the issuer.

Errors — retry versus revoke. Only a definitive answer about the user's session is a plain :class:`IdentityError` or
:class:`UpstreamRejectedError` (the caller revokes our tokens): token endpoint 400/401, userinfo 401/403, an ID token
that fails verification, a changed ``sub``, a discovery document that names another issuer or plain-http endpoints.
Everything else — network errors, timeouts, 3xx, 408, 429, 5xx, any other non-200, a non-JSON or oversized body,
every failure of discovery or JWKS, an unknown ``kid`` while refetching is cooling down — is
:class:`UpstreamUnavailableError` (keep our tokens, retry later). Messages never contain tokens or secrets.

``sub`` continuity (OIDC Core §5.3.2, §12.2): the ``sub`` seen for an upstream refresh token is remembered in memory
(bounded, keyed by the token's hash), and a refresh whose ID token or userinfo names another ``sub`` is refused.
After a restart the first refresh only requires ``sub`` to be present; the caller still compares the subject claim.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import logging
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import Key, KeySet, import_key

from ratatoskr.auth.crypto import hash_token, pkce_challenge
from ratatoskr.auth.identity.base import (
    ExternalLogin,
    IdentityError,
    UpstreamRejectedError,
    UpstreamUnavailableError,
)
from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import OidcSettings
from ratatoskr.state.records import Clock

logger = logging.getLogger(__name__)

ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
_SIGNING_KEY_TYPES = ("RSA", "EC")
CLOCK_LEEWAY_SECONDS = 60
UPSTREAM_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1024 * 1024
JWKS_MAX_AGE_SECONDS = 3600.0
JWKS_REFRESH_COOLDOWN_SECONDS = 60.0
MAX_TRACKED_SESSIONS = 10_000
_OAUTH_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_BEARER_TOKEN = re.compile(r"[\x21-\x7e]{1,4096}")
_TOKEN_REFUSALS = frozenset({400, 401})
_USERINFO_REFUSALS = frozenset({401, 403})
_NO_REFUSALS: frozenset[int] = frozenset()


@dataclass(frozen=True)
class OidcMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None
    algorithms: tuple[str, ...]


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise UpstreamUnavailableError(f"OIDC discovery document has no {key!r}")
    return value


def _same_secret(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass"))


def _signing_keys(data: dict[str, Any]) -> KeySet:
    """RSA/EC signature keys from a JWKS document; anything else (oct, OKP, ``use: enc``, junk) is skipped."""
    entries = data.get("keys")
    if not isinstance(entries, list):
        raise UpstreamUnavailableError("issuer JWKS has no 'keys' list")
    keys: list[Key] = []
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("kty") not in _SIGNING_KEY_TYPES:
            continue
        if entry.get("use", "sig") != "sig":
            continue
        try:
            keys.append(import_key(entry))
        except (JoseError, KeyError, TypeError, ValueError):
            continue
    if not keys:
        raise UpstreamUnavailableError("issuer JWKS contains no usable RSA or EC signing key")
    return KeySet(keys)


def _json_object(body: bytes, what: str) -> dict[str, Any]:
    """A garbage 200 (HTML maintenance page, truncated JSON, a list) is an outage, not an answer."""
    try:
        data = json.loads(body)
    except (ValueError, RecursionError) as exc:
        raise UpstreamUnavailableError(f"{what} did not return JSON") from exc
    if not isinstance(data, dict):
        raise UpstreamUnavailableError(f"{what} did not return a JSON object")
    return data


def _check_status(status: int, what: str, refusals: frozenset[int]) -> None:
    if status == 200:
        return
    if status in refusals:
        raise UpstreamRejectedError(f"{what} returned HTTP {status}")
    raise UpstreamUnavailableError(f"{what} returned HTTP {status}")


class OidcIdentityProvider:
    def __init__(
        self,
        settings: OidcSettings,
        redirect_uri: str,
        http: httpx.AsyncClient,
        clock: Clock,
        *,
        allow_insecure_http: bool = False,
    ) -> None:
        self._settings = settings
        self._issuer = str(settings.issuer)
        self._redirect_uri = redirect_uri
        self._http = http
        self._clock = clock
        self._allow_insecure_http = allow_insecure_http
        if not self._is_allowed_url(self._issuer):
            raise ValueError("auth.oidc.issuer must use https (plain http is only possible with --insecure-dev)")
        self._metadata: OidcMetadata | None = None
        self._lock = asyncio.Lock()
        self._keys: KeySet | None = None
        self._keys_generation = 0
        self._keys_fetched_at = 0.0
        self._last_forced_refresh: float | None = None
        self._keys_lock = asyncio.Lock()
        self._subjects: OrderedDict[str, str] = OrderedDict()

    def _is_allowed_url(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        return bool(parts.netloc) and (
            parts.scheme == "https" or (self._allow_insecure_http and parts.scheme == "http")
        )

    def _issuer_matches(self, advertised: str) -> bool:
        """Exact match. Only the trailing ``/`` pydantic adds to a path-less issuer URL is tolerated."""
        if advertised == self._issuer:
            return True
        return urlsplit(self._issuer).path == "/" and advertised == self._issuer[:-1]

    # ── upstream HTTP ───────────────────────────────────────────────────

    async def _send(self, method: str, url: str, **kwargs: Any) -> tuple[int, bytes]:
        """Status and body (empty unless the status may carry an answer). One overall deadline covers connecting,
        sending and reading; the body is capped; redirects are never followed."""
        what = f"{method} {url}"
        try:
            async with asyncio.timeout(UPSTREAM_TIMEOUT_SECONDS):
                async with self._http.stream(
                    method, url, timeout=UPSTREAM_TIMEOUT_SECONDS, follow_redirects=False, **kwargs
                ) as response:
                    status = response.status_code
                    if status >= 500 or status in (408, 429) or 300 <= status < 400:
                        return status, b""
                    declared = response.headers.get("content-length", "")
                    if declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                        raise UpstreamUnavailableError(f"{what}: response too large")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body += chunk
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise UpstreamUnavailableError(f"{what}: response too large")
                    return status, bytes(body)
        except TimeoutError as exc:
            raise UpstreamUnavailableError(f"{what} timed out") from exc
        except (httpx.HTTPError, httpx.StreamError) as exc:
            raise UpstreamUnavailableError(f"{what} failed: {type(exc).__name__}") from exc
        except (httpx.InvalidURL, UnicodeError, ValueError) as exc:
            raise IdentityError(f"{what} could not be sent: {type(exc).__name__}") from exc

    async def _get_json(
        self, url: str, what: str, refusals: frozenset[int], headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        status, body = await self._send("GET", url, headers={"Accept": "application/json", **(headers or {})})
        _check_status(status, what, refusals)
        return _json_object(body, what)

    async def _token_request(self, form: dict[str, str]) -> dict[str, Any]:
        meta = await self.metadata()
        status, body = await self._send(
            "POST",
            meta.token_endpoint,
            data=form,
            auth=(self._settings.client_id, self._settings.client_secret.get_secret_value()),
            headers={"Accept": "application/json"},
        )
        if status in _TOKEN_REFUSALS:
            error = "unknown"
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    code = parsed.get("error")
                    if isinstance(code, str) and _OAUTH_ERROR_CODE.fullmatch(code):
                        error = code
            except (ValueError, RecursionError):
                pass
            raise UpstreamRejectedError(f"token endpoint returned HTTP {status} ({error})")
        _check_status(status, "token endpoint", _NO_REFUSALS)
        return _json_object(body, "token endpoint")

    # ── discovery and keys ──────────────────────────────────────────────

    async def metadata(self) -> OidcMetadata:
        # The lock makes concurrent first callers share one fetch; _send's deadline bounds how long it is held.
        async with self._lock:
            if self._metadata is None:
                data = await self._get_json(
                    self._issuer.rstrip("/") + "/.well-known/openid-configuration", "OIDC discovery", _NO_REFUSALS
                )
                issuer = _require_str(data, "issuer")
                if not self._issuer_matches(issuer):
                    raise IdentityError("OIDC discovery issuer does not match the configured issuer")
                advertised = data.get("id_token_signing_alg_values_supported")
                algorithms = (
                    tuple(a for a in advertised if a in ALLOWED_ALGORITHMS) if isinstance(advertised, list) else ()
                )
                userinfo = data.get("userinfo_endpoint")
                metadata = OidcMetadata(
                    issuer=issuer,
                    authorization_endpoint=_require_str(data, "authorization_endpoint"),
                    token_endpoint=_require_str(data, "token_endpoint"),
                    jwks_uri=_require_str(data, "jwks_uri"),
                    userinfo_endpoint=userinfo if isinstance(userinfo, str) and userinfo else None,
                    algorithms=algorithms or ("RS256",),
                )
                endpoints = {
                    "authorization_endpoint": metadata.authorization_endpoint,
                    "token_endpoint": metadata.token_endpoint,
                    "jwks_uri": metadata.jwks_uri,
                    "userinfo_endpoint": metadata.userinfo_endpoint,
                }
                for name, url in endpoints.items():
                    if url is not None and not self._is_allowed_url(url):
                        raise IdentityError(f"OIDC discovery {name} must be an https URL")
                self._metadata = metadata
            return self._metadata

    async def _fetch_keys(self, meta: OidcMetadata, now: float) -> KeySet:
        keys = _signing_keys(await self._get_json(meta.jwks_uri, "issuer JWKS", _NO_REFUSALS))
        self._keys = keys
        self._keys_fetched_at = now
        self._keys_generation += 1
        return keys

    async def _key_set(self, *, force: bool) -> tuple[KeySet, int]:
        """Cached JWKS and its generation (bumped on every successful fetch).

        ``force`` (unknown ``kid``) refetches at most once per cooldown; during the cooldown the cached set is
        returned unchanged (possibly just refreshed by a concurrent caller). An age-based refetch that fails keeps
        serving the cached keys and is retried after the cooldown.
        """
        meta = await self.metadata()
        async with self._keys_lock:
            now = self._clock()
            if self._keys is None:
                return await self._fetch_keys(meta, now), self._keys_generation
            if force:
                last = self._last_forced_refresh
                if last is None or now - last >= JWKS_REFRESH_COOLDOWN_SECONDS:
                    self._last_forced_refresh = now
                    await self._fetch_keys(meta, now)
            elif now - self._keys_fetched_at >= JWKS_MAX_AGE_SECONDS:
                try:
                    await self._fetch_keys(meta, now)
                except IdentityError as exc:
                    logger.warning("issuer JWKS refetch failed; keeping the cached keys: %s", exc)
                    self._keys_fetched_at = now - JWKS_MAX_AGE_SECONDS + JWKS_REFRESH_COOLDOWN_SECONDS
            return self._keys, self._keys_generation

    # ── ID token validation ─────────────────────────────────────────────

    @staticmethod
    def _decode(id_token: str, keys: KeySet, algorithms: tuple[str, ...]) -> dict[str, Any]:
        """Verified claims; ``InvalidKeyIdError`` passes through, every other failure is an ``IdentityError``."""
        try:
            return jwt.decode(id_token, keys, algorithms=list(algorithms)).claims
        except InvalidKeyIdError:
            raise
        except (JoseError, KeyError, TypeError, ValueError) as exc:
            raise IdentityError(f"ID token signature rejected: {type(exc).__name__}: {exc}") from exc

    async def _verify_id_token(self, id_token: str, nonce: str | None) -> dict[str, Any]:
        meta = await self.metadata()
        keys, generation = await self._key_set(force=False)
        try:
            claims = self._decode(id_token, keys, meta.algorithms)
        except InvalidKeyIdError:
            keys, refreshed = await self._key_set(force=True)
            if refreshed == generation:
                raise UpstreamUnavailableError(
                    "ID token signature key is unknown and the issuer JWKS was refetched recently; retry later"
                ) from None
            try:
                claims = self._decode(id_token, keys, meta.algorithms)
            except InvalidKeyIdError as exc:
                raise IdentityError("ID token signature cannot be verified: no such key published") from exc
        options: dict[str, jwt.ClaimsOption] = {
            "iss": {"essential": True, "value": meta.issuer},
            "sub": {"essential": True},
            "aud": {"essential": True, "value": self._settings.client_id},
            "exp": {"essential": True},
            "iat": {"essential": True},
        }
        registry = jwt.JWTClaimsRegistry(now=int(self._clock()), leeway=CLOCK_LEEWAY_SECONDS, **options)
        try:
            registry.validate(claims)
        except JoseError as exc:
            raise IdentityError(f"ID token claims rejected: {exc}") from exc
        if nonce is not None:
            claimed = claims.get("nonce")
            if not isinstance(claimed, str) or not _same_secret(claimed, nonce):
                raise IdentityError("ID token claims rejected: nonce does not match")
        audience = claims["aud"]
        several = isinstance(audience, list) and len(audience) > 1
        azp = claims.get("azp")
        if (several or azp is not None) and azp != self._settings.client_id:
            raise IdentityError("ID token azp is not this client (required when there are several audiences)")
        return claims

    def _principal(self, claims: dict[str, Any]) -> Principal:
        subject = claims.get(self._settings.subject_claim)
        if not isinstance(subject, str) or not subject.strip():
            raise IdentityError(f"claim {self._settings.subject_claim!r} is missing from the identity")
        raw_groups = claims.get(self._settings.groups_claim, [])
        groups = frozenset(g for g in raw_groups if isinstance(g, str)) if isinstance(raw_groups, list) else frozenset()
        display = claims.get("name") or claims.get("preferred_username") or subject
        return Principal(
            subject=subject,
            display_name=display if isinstance(display, str) else subject,
            groups=groups,
            auth_source="oidc",
        )

    # ── sub continuity ──────────────────────────────────────────────────

    def _remember_sub(self, refresh_token: str | None, sub: str) -> None:
        if refresh_token is None:
            return
        key = hash_token(refresh_token)
        self._subjects[key] = sub
        self._subjects.move_to_end(key)
        while len(self._subjects) > MAX_TRACKED_SESSIONS:
            self._subjects.popitem(last=False)

    # ── public API ──────────────────────────────────────────────────────

    async def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        meta = await self.metadata()
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self._settings.client_id,
                "redirect_uri": self._redirect_uri,
                "scope": " ".join(self._settings.scopes),
                "state": state,
                "nonce": nonce,
                "code_challenge": pkce_challenge(code_verifier),
                "code_challenge_method": "S256",
            }
        )
        separator = "&" if "?" in meta.authorization_endpoint else "?"
        return f"{meta.authorization_endpoint}{separator}{query}"

    async def complete(self, code: str, code_verifier: str, nonce: str) -> ExternalLogin:
        if not nonce:
            raise IdentityError("sign-in has no nonce to check the ID token against")
        data = await self._token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self._redirect_uri,
                "code_verifier": code_verifier,
            }
        )
        id_token = data.get("id_token")
        if not isinstance(id_token, str):
            raise IdentityError("token response has no id_token")
        claims = await self._verify_id_token(id_token, nonce)
        principal = self._principal(claims)
        refresh = data.get("refresh_token")
        upstream_refresh = refresh if isinstance(refresh, str) and refresh else None
        self._remember_sub(upstream_refresh, claims["sub"])
        return ExternalLogin(principal, upstream_refresh)

    async def refresh(self, refresh_token: str) -> ExternalLogin:
        """Re-read the identity with the upstream refresh token.

        Raises :class:`UpstreamUnavailableError` when the issuer gives no usable answer (keep our tokens, retry later)
        and any other :class:`IdentityError` when the session is refused or the answer fails verification (revoke).
        """
        known_sub = self._subjects.get(hash_token(refresh_token))
        data = await self._token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})
        id_token = data.get("id_token")
        if isinstance(id_token, str):
            claims = await self._verify_id_token(id_token, None)
        else:
            claims = await self._userinfo(data.get("access_token"))
        sub = claims.get("sub")
        if not isinstance(sub, str) or not sub:
            raise IdentityError("upstream identity has no 'sub'")
        if known_sub is not None and not _same_secret(sub, known_sub):
            raise IdentityError("upstream 'sub' differs from the one this session signed in with")
        principal = self._principal(claims)
        new_refresh = data.get("refresh_token")
        upstream_refresh = new_refresh if isinstance(new_refresh, str) and new_refresh else refresh_token
        if upstream_refresh != refresh_token:
            self._subjects.pop(hash_token(refresh_token), None)
        self._remember_sub(upstream_refresh, sub)
        return ExternalLogin(principal, upstream_refresh)

    async def _userinfo(self, access_token: object) -> dict[str, Any]:
        meta = await self.metadata()
        if not isinstance(access_token, str) or meta.userinfo_endpoint is None:
            raise IdentityError("refresh response has neither id_token nor a usable access token for userinfo")
        if _BEARER_TOKEN.fullmatch(access_token) is None:
            raise UpstreamUnavailableError("token endpoint returned an access token that cannot be sent as a bearer")
        return await self._get_json(
            meta.userinfo_endpoint, "userinfo endpoint", _USERINFO_REFUSALS, {"Authorization": f"Bearer {access_token}"}
        )
