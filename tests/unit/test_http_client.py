import logging
import ssl
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
import respx
from pydantic import SecretStr

from ratatoskr import __version__
from ratatoskr.backends.errors import BackendQueryError, BackendTimeoutError, BackendUnavailableError
from ratatoskr.backends.http import options
from ratatoskr.backends.http.client import (
    EndpointNotFoundError,
    HttpClient,
    ResponseTooLargeError,
    is_certificate_error,
    parse_json,
    status_error,
)
from ratatoskr.config.http_models import BasicAuth, BearerAuth, HttpAuth, HttpTlsSettings, NoAuth

BASE = "http://mimir.internal:8080/prometheus"
SECRET = "tok-VALUE-never-shown"


def _client(auth: HttpAuth | None = None, *, max_body_bytes: int = 1000, **headers: str) -> HttpClient:
    return HttpClient(
        "prom",
        base_url=BASE,
        auth=auth or NoAuth(type="none"),
        headers={name.replace("_", "-"): SecretStr(value) for name, value in headers.items()},
        tls=HttpTlsSettings(),
        timeout=2.0,
        max_body_bytes=max_body_bytes,
    )


@pytest.fixture
def router() -> Iterator[respx.Router]:
    """Every outbound request is mocked; an unmatched one fails the test instead of reaching the network."""
    with respx.mock(base_url=BASE, assert_all_called=False) as mocked:
        yield mocked


@pytest.fixture
async def client() -> AsyncIterator[HttpClient]:
    opened = _client()
    await opened.open()
    yield opened
    await opened.aclose()


async def test_post_form_keeps_the_path_prefix_and_repeats_list_fields(
    router: respx.Router, client: HttpClient
) -> None:
    route = router.post("/api/v1/query").mock(return_value=httpx.Response(200, json={"status": "success"}))
    reply = await client.request("POST", "/api/v1/query", form={"query": "up", "match[]": ["a", "b"]})
    assert (reply.status, parse_json(reply.body)) == (200, {"status": "success"})
    request = route.calls.last.request
    assert request.url.path == "/prometheus/api/v1/query"
    assert parse_qs(request.content.decode()) == {"query": ["up"], "match[]": ["a", "b"]}
    assert request.headers["user-agent"] == f"ratatoskr/{__version__}"
    assert request.headers["accept"] == "application/json"


async def test_get_sends_query_parameters(router: respx.Router, client: HttpClient) -> None:
    route = router.get("/api/v1/labels").mock(return_value=httpx.Response(200, json={}))
    await client.request("GET", "/api/v1/labels", params={"start": "1", "match[]": ["x"]})
    assert parse_qs(route.calls.last.request.url.query.decode()) == {"start": ["1"], "match[]": ["x"]}


@pytest.mark.parametrize(
    ("auth", "expected"),
    [
        (BearerAuth(type="bearer", token=SecretStr(SECRET)), f"Bearer {SECRET}"),
        (BasicAuth(type="basic", username="reader", password=SecretStr("pw")), "Basic cmVhZGVyOnB3"),
        (NoAuth(type="none"), None),
    ],
)
async def test_auth_and_extra_headers_are_sent(router: respx.Router, auth: HttpAuth, expected: str | None) -> None:
    route = router.get("/x").mock(return_value=httpx.Response(200))
    client = _client(auth, X_Scope_OrgID="team-a")
    await client.open()
    await client.request("GET", "/x")
    await client.aclose()
    headers = route.calls.last.request.headers
    assert headers.get("authorization") == expected
    assert headers["x-scope-orgid"] == "team-a"


async def test_any_status_is_returned(router: respx.Router, client: HttpClient) -> None:
    router.get("/x").mock(return_value=httpx.Response(503, text="busy"))
    reply = await client.request("GET", "/x")
    assert (reply.status, reply.body) == (503, b"busy")


async def test_declared_large_body_is_refused(router: respx.Router, client: HttpClient) -> None:
    router.get("/x").mock(return_value=httpx.Response(200, content=b"y" * 2000))
    with pytest.raises(ResponseTooLargeError) as caught:
        await client.request("GET", "/x", too_large_hint="Narrow it.")
    assert str(caught.value) == (
        "The answer from connection 'prom' is larger than 1000 bytes, the limit for this connection. Narrow it."
    )


async def test_streamed_body_is_cut_while_reading(router: respx.Router, client: HttpClient) -> None:
    async def chunks() -> AsyncIterator[bytes]:
        for _ in range(5):
            yield b"x" * 400

    router.get("/x").mock(return_value=httpx.Response(200, content=chunks()))
    with pytest.raises(ResponseTooLargeError):
        await client.request("GET", "/x")


async def test_large_limits_are_named_in_mib(router: respx.Router) -> None:
    router.get("/x").mock(return_value=httpx.Response(200, content=b"y" * (2 * 1024 * 1024 + 1)))
    client = _client(max_body_bytes=2 * 1024 * 1024)
    await client.open()
    with pytest.raises(ResponseTooLargeError, match="larger than 2 MiB"):
        await client.request("GET", "/x")
    await client.aclose()


async def test_timeout_names_only_the_connection(router: respx.Router, client: HttpClient) -> None:
    router.get("/x").mock(side_effect=httpx.ReadTimeout("timed out"))
    with pytest.raises(BackendTimeoutError) as caught:
        await client.request("GET", "/x")
    assert str(caught.value) == "Connection 'prom' did not answer within 2s."


async def test_transport_error_hides_the_address(
    router: respx.Router, client: HttpClient, caplog: pytest.LogCaptureFixture
) -> None:
    router.get("/x").mock(side_effect=httpx.ConnectError("[Errno 111] connect to 10.0.0.5:8080 refused"))
    with (
        caplog.at_level(logging.WARNING, logger="ratatoskr.backends.http"),
        pytest.raises(BackendUnavailableError) as caught,
    ):
        await client.request("GET", "/x")
    assert str(caught.value) == "Connection 'prom' is unavailable (ConnectError); details are in the server log."
    assert "request to connection prom failed (ConnectError)" in caplog.text


def test_certificate_errors_are_found_in_the_cause_chain() -> None:
    try:
        try:
            raise ssl.SSLCertVerificationError(1, "certificate verify failed")
        except ssl.SSLCertVerificationError as inner:
            raise httpx.ConnectError("failed") from inner
    except httpx.ConnectError as outer:
        assert is_certificate_error(outer) is True
    assert is_certificate_error(httpx.ConnectError("refused")) is False


def test_certificate_error_text(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ratatoskr.backends.http.client.is_certificate_error", lambda exc: True)
    error = _client()._unavailable(httpx.ConnectError("x"))
    assert "its TLS certificate could not be verified" in str(error)


async def test_closed_and_unopened_clients_refuse() -> None:
    client = _client()
    with pytest.raises(BackendUnavailableError, match="is not open"):
        await client.request("GET", "/x")
    await client.open()
    assert client.is_open
    await client.aclose()
    assert not client.is_open
    with pytest.raises(BackendUnavailableError, match="is closed"):
        await client.request("GET", "/x")
    with pytest.raises(BackendUnavailableError, match="is closed"):
        await client.open()


@pytest.mark.parametrize(
    ("status", "error", "text"),
    [
        (401, BackendQueryError, "refused the request (HTTP 401)"),
        (403, BackendQueryError, "refused the request (HTTP 403)"),
        (404, EndpointNotFoundError, "answered HTTP 404"),
        (429, BackendQueryError, "rate limiting"),
        (302, BackendUnavailableError, "redirect (HTTP 302)"),
        (502, BackendUnavailableError, "answered HTTP 502"),
        (418, BackendQueryError, "rejected the request (HTTP 418)"),
    ],
)
def test_status_errors(status: int, error: type[Exception], text: str) -> None:
    result = status_error("prom", status)
    assert type(result) is error
    assert text in str(result)


def test_parse_json() -> None:
    assert parse_json(b'{"a": 1}') == {"a": 1}
    assert parse_json(b"<html>") is None


def test_default_ssl_context_is_built_once() -> None:
    assert options.build_verify(HttpTlsSettings()) is options.build_verify(HttpTlsSettings())
    assert options.build_verify(HttpTlsSettings(verify=False)) is False


def test_ca_file_builds_its_own_context(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("pem", encoding="utf-8")
    seen: dict[str, Any] = {}

    def fake_context(cafile: str) -> str:
        seen["cafile"] = cafile
        return "context"

    monkeypatch.setattr(options.ssl, "create_default_context", fake_context)
    assert options.build_verify(HttpTlsSettings(ca_file=ca)) == "context"
    assert seen == {"cafile": str(ca)}
