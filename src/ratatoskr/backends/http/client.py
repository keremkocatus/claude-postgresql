"""One httpx client per HTTP connection: auth, headers, TLS, deadlines, a capped body read and user-safe errors.

No message built here names a URL, host, header or credential: transport failures become ``BackendError``s that
name only the connection, and the details go to the log.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

import httpx
from pydantic import SecretStr

from ratatoskr import __version__
from ratatoskr.backends.errors import BackendError, BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.http.options import build_auth, build_verify
from ratatoskr.config.http_models import HttpAuth, HttpTlsSettings

CONNECT_TIMEOUT_SECONDS = 10.0
# The server's own timeout (sent as a parameter) should answer first, with a clearer message.
TIMEOUT_GRACE_SECONDS = 5.0
MAX_CONNECTIONS = 10
_MIB = 1024 * 1024

Fields = Mapping[str, str | Sequence[str]]

logger = logging.getLogger("ratatoskr.backends.http")


class ResponseTooLargeError(BackendQueryError):
    """The response body exceeded the connection's ``limits.max_body_bytes`` while it was being read."""


class EndpointNotFoundError(BackendQueryError):
    """HTTP 404: the server does not offer this endpoint (or the url is not the API root)."""


@dataclass(frozen=True)
class HttpReply:
    status: int
    body: bytes


class HttpClient:
    def __init__(
        self,
        connection: str,
        *,
        base_url: str,
        auth: HttpAuth,
        headers: Mapping[str, SecretStr],
        tls: HttpTlsSettings,
        timeout: float,
        max_body_bytes: int,
    ) -> None:
        self._connection = connection
        self._base_url = base_url
        self._auth = auth
        self._headers = headers
        self._tls = tls
        self.timeout = timeout
        self._max_body_bytes = max_body_bytes
        self._client: httpx.AsyncClient | None = None
        self._closed = False

    @property
    def is_open(self) -> bool:
        return self._client is not None

    async def open(self) -> None:
        """Create the httpx client (no network traffic). Proxy settings come from the environment, as for the
        OIDC client: ``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``NO_PROXY``."""
        if self._closed:
            raise BackendUnavailableError(f"Connection '{self._connection}' is closed.")
        if self._client is None:
            headers, auth = build_auth(self._auth, self._headers)
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={"User-Agent": f"ratatoskr/{__version__}", "Accept": "application/json", **headers},
                auth=auth,
                verify=build_verify(self._tls),
                timeout=httpx.Timeout(self.timeout, connect=min(CONNECT_TIMEOUT_SECONDS, self.timeout)),
                limits=httpx.Limits(max_connections=MAX_CONNECTIONS, max_keepalive_connections=MAX_CONNECTIONS),
                follow_redirects=False,
            )

    async def aclose(self) -> None:
        self._closed = True
        client, self._client = self._client, None
        if client is not None:
            await client.aclose()

    async def request(
        self,
        method: Literal["GET", "POST"],
        path: str,
        *,
        params: Fields | None = None,
        form: Fields | None = None,
        too_large_hint: str = "",
    ) -> HttpReply:
        """Send one request and read at most ``max_body_bytes`` of the (decoded) body. Any status is returned."""
        client = self._client
        if client is None:
            state = "closed" if self._closed else "not open"
            raise BackendUnavailableError(f"Connection '{self._connection}' is {state}.")
        try:
            async with (
                asyncio.timeout(self.timeout + TIMEOUT_GRACE_SECONDS),
                client.stream(method, path, params=params, data=form) as response,
            ):
                body = await self._read_capped(response, too_large_hint)
                return HttpReply(status=response.status_code, body=body)
        except BackendError:
            raise
        except (TimeoutError, httpx.TimeoutException):
            raise BackendTimeoutError(
                f"Connection '{self._connection}' did not answer within {self.timeout:.0f}s."
            ) from None
        except httpx.HTTPError as exc:
            raise self._unavailable(exc) from None

    async def _read_capped(self, response: httpx.Response, hint: str) -> bytes:
        declared = response.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max_body_bytes:
            raise self._too_large(hint)
        chunks: list[bytes] = []
        size = 0
        async for chunk in response.aiter_bytes():
            size += len(chunk)
            if size > self._max_body_bytes:
                raise self._too_large(hint)
            chunks.append(chunk)
        return b"".join(chunks)

    def _too_large(self, hint: str) -> ResponseTooLargeError:
        limit = self._max_body_bytes
        size = f"{limit / _MIB:g} MiB" if limit >= _MIB else f"{limit} bytes"
        message = (
            f"The answer from connection '{self._connection}' is larger than {size}, the limit for this "
            f"connection. {hint}"
        )
        return ResponseTooLargeError(message.strip())

    def _unavailable(self, exc: httpx.HTTPError) -> BackendUnavailableError:
        logger.warning("request to connection %s failed (%s)", self._connection, type(exc).__name__, exc_info=exc)
        if is_certificate_error(exc):
            return BackendUnavailableError(
                f"Connection '{self._connection}' is unavailable: its TLS certificate could not be verified. "
                "Ask the administrator to check the connection's tls settings; details are in the server log."
            )
        return BackendUnavailableError(
            f"Connection '{self._connection}' is unavailable ({type(exc).__name__}); details are in the server log."
        )


def is_certificate_error(exc: BaseException) -> bool:
    """Whether a certificate verification failure is anywhere in the cause/context chain (cycles are skipped)."""
    pending: list[BaseException] = [exc]
    seen: set[int] = set()
    while pending and len(seen) < 20:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        pending.extend(linked for linked in (current.__cause__, current.__context__) if linked is not None)
    return False


def parse_json(body: bytes) -> Any | None:
    """The decoded JSON body, or None when it is not JSON."""
    try:
        return json.loads(body)
    except ValueError:
        return None


def status_error(connection: str, status: int) -> BackendError:
    """A user-safe error for an HTTP status that did not come with an API error body."""
    if status in (401, 403):
        return BackendQueryError(
            f"Connection '{connection}' refused the request (HTTP {status}): its configured credentials or headers "
            "were not accepted. Ask the administrator to check them."
        )
    if status == 404:
        return EndpointNotFoundError(
            f"Connection '{connection}' answered HTTP 404: the server does not offer this API endpoint, or the "
            "connection's url is not the API root."
        )
    if status == 429:
        return BackendQueryError(f"Connection '{connection}' is rate limiting requests (HTTP 429); try again later.")
    if 300 <= status < 400:
        return BackendUnavailableError(
            f"Connection '{connection}' answered with a redirect (HTTP {status}), which is not followed; the "
            "connection's url must be the final address."
        )
    if status >= 500:
        return BackendUnavailableError(
            f"Connection '{connection}' answered HTTP {status}; details are in the server log."
        )
    return BackendQueryError(f"Connection '{connection}' rejected the request (HTTP {status}).")
