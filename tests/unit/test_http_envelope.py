import contextlib
import logging
from collections.abc import AsyncIterator

import pytest

from ratatoskr.backends.errors import BackendQueryError, BackendTimeoutError
from ratatoskr.backends.http.envelope import ApiResult, decode_json, scrub_server_text, success_result
from ratatoskr.backends.http.health import timed_health
from ratatoskr.backends.output import MAX_NOTES


def _upper(text: str) -> str:
    return text.upper()


def test_success_result_takes_data_and_scrubbed_notes() -> None:
    payload = {"status": "success", "data": [1], "warnings": ["w"], "infos": ["i"]}
    assert success_result(200, payload, _upper) == ApiResult(data=[1], notes=["warning: W", "info: I"])


def test_success_result_counts_notes_beyond_the_limit() -> None:
    payload = {"status": "success", "data": None, "warnings": [str(i) for i in range(MAX_NOTES + 3)]}
    result = success_result(200, payload, _upper)
    assert result is not None
    assert (len(result.notes), result.omitted_notes) == (MAX_NOTES, 3)


@pytest.mark.parametrize(
    ("status", "payload"),
    [(200, {"status": "error"}), (200, ["x"]), (200, None), (400, {"status": "success"})],
)
def test_anything_else_is_not_a_success(status: int, payload: object) -> None:
    assert success_result(status, payload, _upper) is None


async def test_decode_json_returns_none_for_other_bodies() -> None:
    assert await decode_json(b'{"a": 1}') == {"a": 1}
    assert await decode_json(b"parse error at line 1") is None


def test_scrub_server_text_removes_addresses_and_secrets() -> None:
    text = scrub_server_text("dial tcp 10.0.0.5:9095 with password=hunter2 to loki:3100", hosts={"loki"})
    assert text == "dial tcp <address> with password=*** to <host>"


async def test_timed_health_reports_version_latency_and_safe_errors(caplog: pytest.LogCaptureFixture) -> None:
    async def version() -> str:
        return "Loki 3.7.9"

    async def refused() -> str:
        raise BackendQueryError("Connection 'logs' refused the request (HTTP 401).")

    async def broken() -> str:
        raise RuntimeError("secret detail at 10.0.0.1")

    ok = await timed_health("logs", version, deadline=contextlib.nullcontext)
    assert (ok.ok, ok.version, ok.error) == (True, "Loki 3.7.9", None)
    assert ok.latency_ms is not None
    assert (
        await timed_health("logs", refused, deadline=contextlib.nullcontext)
    ).error == "Connection 'logs' refused the request (HTTP 401)."
    with caplog.at_level(logging.WARNING, logger="ratatoskr.backends.http"):
        failed = await timed_health("logs", broken, deadline=contextlib.nullcontext)
    assert (failed.ok, failed.error) == (False, "RuntimeError")
    assert "health check of logs failed" in caplog.text


async def test_timed_health_reports_the_deadline() -> None:
    async def version() -> str:
        return "Loki 3.7.9"

    @contextlib.asynccontextmanager
    async def expired() -> AsyncIterator[None]:
        yield
        raise BackendTimeoutError("Connection 'logs' did not answer within 1s.")

    health = await timed_health("logs", version, deadline=expired)
    assert (health.ok, health.error) == (False, "Connection 'logs' did not answer within 1s.")
