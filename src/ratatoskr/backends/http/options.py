"""Turn the shared HTTP connection settings (auth, headers, TLS) into what httpx needs."""

from __future__ import annotations

import functools
import ssl
from collections.abc import Mapping

import httpx
from pydantic import SecretStr

from ratatoskr.config.http_models import BasicAuth, BearerAuth, HttpAuth, HttpTlsSettings


@functools.cache
def default_ssl_context() -> ssl.SSLContext:
    """httpx's own default trust (certifi, or ``SSL_CERT_FILE`` / ``SSL_CERT_DIR``), built once per process:
    loading a CA bundle takes about half a second, too long to repeat for every connection."""
    return httpx.create_ssl_context()


def build_verify(tls: HttpTlsSettings) -> ssl.SSLContext | bool:
    if not tls.verify:
        return False
    if tls.ca_file is not None:
        return ssl.create_default_context(cafile=str(tls.ca_file))
    return default_ssl_context()


def build_auth(auth: HttpAuth, headers: Mapping[str, SecretStr]) -> tuple[dict[str, str], httpx.Auth | None]:
    """The request headers (configured ones plus a bearer token) and the httpx auth (basic) of a connection."""
    plain = {name: value.get_secret_value() for name, value in headers.items()}
    if isinstance(auth, BearerAuth):
        plain["Authorization"] = f"Bearer {auth.token.get_secret_value()}"
        return plain, None
    if isinstance(auth, BasicAuth):
        return plain, httpx.BasicAuth(auth.username, auth.password.get_secret_value())
    return plain, None
