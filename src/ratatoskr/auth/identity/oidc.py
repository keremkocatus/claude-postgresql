"""OIDC relying party for an upstream issuer such as Authentik (spec §5.2 ``oidc``, §5.3).

Authorization code flow with PKCE (S256), ``state`` and ``nonce``. ID tokens are verified against the issuer's
JWKS (signature, ``iss``, ``aud``/``azp``, ``exp``, ``nbf``, ``iat``, ``nonce``); only asymmetric algorithms and only
RSA/EC signing keys are accepted, so ``alg: none`` and HMAC tokens never verify.

Upstream hardening: the issuer and every endpoint from discovery must be https (unless ``allow_insecure_http``, for
``--insecure-dev`` only); the discovery ``issuer`` must equal the configured one; every request has a timeout, does
not follow redirects and reads at most :data:`MAX_RESPONSE_BYTES`. The JWKS is cached for
:data:`JWKS_MAX_AGE_SECONDS`; an unknown ``kid`` forces a refetch at most once per
:data:`JWKS_REFRESH_COOLDOWN_SECONDS`, so tokens with made-up key ids cannot make us hammer the issuer.

Errors: :class:`UpstreamUnavailableError` (network, timeout, 5xx: retry later, keep our tokens) versus every other
:class:`IdentityError` (refused or unverifiable: revoke our tokens). Messages never contain tokens or secrets.
"""

from __future__ import annotations

import asyncio
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpx
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import Key, KeySet, import_key

from ratatoskr.auth.crypto import pkce_challenge
from ratatoskr.auth.identity.base import (
    ExternalLogin,
    IdentityError,
    UpstreamRejectedError,
    UpstreamUnavailableError,
)
from ratatoskr.auth.principal import Principal
from ratatoskr.config.models import OidcSettings
from ratatoskr.state.records import Clock

ALLOWED_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512")
_SIGNING_KEY_TYPES = ("RSA", "EC")
CLOCK_LEEWAY_SECONDS = 60
UPSTREAM_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 1024 * 1024
JWKS_MAX_AGE_SECONDS = 3600.0
JWKS_REFRESH_COOLDOWN_SECONDS = 60.0
_OAUTH_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


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
        raise IdentityError(f"OIDC discovery document has no {key!r}")
    return value


def _same_secret(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8", "surrogatepass"), b.encode("utf-8", "surrogatepass"))


def _signing_keys(data: dict[str, Any]) -> KeySet:
    """RSA/EC signature keys from a JWKS document; anything else (oct, OKP, ``use: enc``, junk) is skipped."""
    entries = data.get("keys")
    if not isinstance(entries, list):
        raise IdentityError("issuer JWKS has no 'keys' list")
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
        raise IdentityError("issuer JWKS contains no usable RSA or EC signing key")
    return KeySet(keys)


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
        self._keys_fetched_at = 0.0
        self._last_forced_refresh: float | None = None
        self._keys_lock = asyncio.Lock()

    def _is_allowed_url(self, url: str) -> bool:
        scheme = urlsplit(url).scheme
        return scheme == "https" or (self._allow_insecure_http and scheme == "http")

    def _issuer_matches(self, advertised: str) -> bool:
        """Exact match. Only the trailing ``/`` pydantic adds to a path-less issuer URL is tolerated."""
        if advertised == self._issuer:
            return True
        return urlsplit(self._issuer).path == "/" and advertised == self._issuer[:-1]

    # ── upstream HTTP ───────────────────────────────────────────────────

    async def _send(self, method: str, url: str, **kwargs: Any) -> tuple[int, bytes]:
        """Status and body (empty for 5xx). Bounded in time and size; never follows redirects."""
        try:
            async with self._http.stream(
                method, url, timeout=UPSTREAM_TIMEOUT_SECONDS, follow_redirects=False, **kwargs
            ) as response:
                if response.status_code >= 500:
                    return response.status_code, b""
                declared = response.headers.get("content-length", "")
                if declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
                    raise IdentityError(f"{method} {url}: response too large")
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise IdentityError(f"{method} {url}: response too large")
                return response.status_code, bytes(body)
        except httpx.HTTPError as exc:
            raise UpstreamUnavailableError(f"{method} {url} failed: {type(exc).__name__}") from exc

    async def _get_json(self, url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        status, body = await self._send("GET", url, headers={"Accept": "application/json", **(headers or {})})
        if status >= 500:
            raise UpstreamUnavailableError(f"GET {url} returned HTTP {status}")
        if status != 200:
            raise UpstreamRejectedError(f"GET {url} returned HTTP {status}")
        return self._json_object(body, url)

    @staticmethod
    def _json_object(body: bytes, url: str) -> dict[str, Any]:
        try:
            data = json.loads(body)
        except (ValueError, RecursionError) as exc:
            raise IdentityError(f"{url} did not return JSON") from exc
        if not isinstance(data, dict):
            raise IdentityError(f"{url} did not return a JSON object")
        return data

    async def _token_request(self, form: dict[str, str]) -> dict[str, Any]:
        meta = await self.metadata()
        status, body = await self._send(
            "POST",
            meta.token_endpoint,
            data=form,
            auth=(self._settings.client_id, self._settings.client_secret.get_secret_value()),
            headers={"Accept": "application/json"},
        )
        if status >= 500:
            raise UpstreamUnavailableError(f"token endpoint returned HTTP {status}")
        if status != 200:
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
        return self._json_object(body, meta.token_endpoint)

    # ── discovery and keys ──────────────────────────────────────────────

    async def metadata(self) -> OidcMetadata:
        async with self._lock:
            if self._metadata is None:
                data = await self._get_json(self._issuer.rstrip("/") + "/.well-known/openid-configuration")
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
                        raise IdentityError(f"OIDC discovery {name} must use https")
                self._metadata = metadata
            return self._metadata

    async def _key_set(self, *, force: bool) -> KeySet:
        """Cached JWKS. ``force`` (unknown ``kid``) refetches at most once per cooldown; otherwise the cached
        set is returned, which may already have been refreshed by a concurrent caller."""
        meta = await self.metadata()
        async with self._keys_lock:
            now = self._clock()
            stale = self._keys is None or now - self._keys_fetched_at >= JWKS_MAX_AGE_SECONDS
            if force and not stale:
                cooling = (
                    self._last_forced_refresh is not None
                    and now - self._last_forced_refresh < JWKS_REFRESH_COOLDOWN_SECONDS
                )
                if cooling and self._keys is not None:
                    return self._keys
                self._last_forced_refresh = now
            if stale or force or self._keys is None:
                self._keys = _signing_keys(await self._get_json(meta.jwks_uri))
                self._keys_fetched_at = now
            return self._keys

    # ── ID token validation ─────────────────────────────────────────────

    async def _verify_id_token(self, id_token: str, nonce: str | None) -> dict[str, Any]:
        meta = await self.metadata()
        claims: dict[str, Any] | None = None
        for force in (False, True):
            keys = await self._key_set(force=force)
            try:
                claims = jwt.decode(id_token, keys, algorithms=list(meta.algorithms)).claims
                break
            except InvalidKeyIdError as exc:
                if force:
                    raise IdentityError("ID token signature cannot be verified: no such key published") from exc
            except (JoseError, KeyError, TypeError, ValueError) as exc:
                raise IdentityError(f"ID token signature rejected: {type(exc).__name__}: {exc}") from exc
        if claims is None:
            raise IdentityError("ID token could not be verified")
        options: dict[str, jwt.ClaimsOption] = {
            "iss": {"essential": True, "value": meta.issuer},
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
        refresh = data.get("refresh_token")
        return ExternalLogin(self._principal(claims), refresh if isinstance(refresh, str) and refresh else None)

    async def refresh(self, refresh_token: str) -> ExternalLogin:
        """Re-read the identity with the upstream refresh token.

        Raises :class:`UpstreamUnavailableError` when the issuer cannot be reached (keep our tokens, retry later) and
        any other :class:`IdentityError` when the session is refused or the answer cannot be verified (revoke).
        """
        data = await self._token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})
        id_token = data.get("id_token")
        if isinstance(id_token, str):
            claims = await self._verify_id_token(id_token, None)
        else:
            claims = await self._userinfo(data.get("access_token"))
        new_refresh = data.get("refresh_token")
        return ExternalLogin(
            self._principal(claims), new_refresh if isinstance(new_refresh, str) and new_refresh else refresh_token
        )

    async def _userinfo(self, access_token: object) -> dict[str, Any]:
        meta = await self.metadata()
        if not isinstance(access_token, str) or not access_token or meta.userinfo_endpoint is None:
            raise IdentityError("refresh response has neither id_token nor a usable access token for userinfo")
        return await self._get_json(meta.userinfo_endpoint, {"Authorization": f"Bearer {access_token}"})
