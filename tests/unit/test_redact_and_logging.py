import io
import json
import logging
import sys
import time
from typing import Any

import pytest

from ratatoskr.observability.logging import JsonFormatter, setup_logging
from ratatoskr.observability.redact import redact


def test_redacts_urls() -> None:
    text = "failed: postgresql://admin:hunter2@db.internal:5432/app?sslmode=require and postgres://x@y/z"
    result = redact(text)
    assert "hunter2" not in result
    assert "db.internal" not in result
    assert result == "failed: postgresql://*** and postgres://***"


def test_redacts_key_value_passwords() -> None:
    assert redact("host=db password=hunter2 user=app") == "host=db password=*** user=app"
    assert redact("PASSWORD = 'a b c'") == "PASSWORD=***"


def test_leaves_plain_text_alone() -> None:
    assert redact('relation "users" does not exist') == 'relation "users" does not exist'


def test_json_formatter_includes_extra_and_masks() -> None:
    record = logging.LogRecord("ratatoskr.x", logging.INFO, __file__, 1, "dsn %s", ("postgresql://u:p@h/d",), None)
    record.__dict__["connection"] = "main"
    record.__dict__["query_text"] = "SELECT dblink('postgresql://u:pw@h/d', 'x')"
    entry = json.loads(JsonFormatter().format(record))
    assert entry["level"] == "INFO"
    assert entry["logger"] == "ratatoskr.x"
    assert entry["msg"] == "dsn postgresql://***"
    assert entry["connection"] == "main"
    assert "pw@" not in entry["query_text"]
    assert "ts" in entry


def test_setup_logging_writes_json_to_stream() -> None:
    stream = io.StringIO()
    setup_logging("INFO", stream=stream)
    logging.getLogger("ratatoskr.test").info("hello", extra={"tool": "pg_query"})
    entry = json.loads(stream.getvalue().strip().splitlines()[-1])
    assert entry["msg"] == "hello"
    assert entry["tool"] == "pg_query"


@pytest.mark.parametrize(("level", "shown"), [("INFO", False), ("DEBUG", True)])
def test_setup_logging_hides_per_request_mcp_lines_at_info(level: str, shown: bool) -> None:
    stream = io.StringIO()
    setup_logging(level, stream=stream)
    logging.getLogger("mcp.server.lowlevel.server").info("Processing request of type %s", "CallToolRequest")
    logging.getLogger("mcp.server.lowlevel.server").warning("still visible")
    assert ("Processing request" in stream.getvalue()) is shown
    assert "still visible" in stream.getvalue()


# --- review fixes: wider redaction, structured extras, root logger ---

SECRET_URL = "postgresql://u:hunter2@h/d"


def test_redacts_authorization_headers() -> None:
    assert redact("Authorization: Bearer abc.def.ghi") == "Authorization: Bearer ***"
    assert redact("authorization=Basic dXNlcjpwYXNz rest") == "authorization=Basic *** rest"
    assert redact('{"Authorization": "Bearer abc.def-ghi_0"}') == '{"Authorization": "Bearer ***"}'
    assert redact("{'authorization': 'Basic dXNlcjpwYXNz'}") == "{'authorization': 'Basic ***'}"


def test_bearer_needs_a_token_like_value() -> None:
    assert redact("sent Bearer eyJhbGciOiJIUzI1NiJ9.e30.abc here") == "sent Bearer *** here"
    assert redact("bearer abcdefghij0123456789+/==") == "bearer ***"
    assert redact("The Ring Bearer of bad news") == "The Ring Bearer of bad news"
    assert redact("Bearer Frodo Baggins") == "Bearer Frodo Baggins"
    assert redact("bearer short.token") == "bearer short.token"  # under 16 characters: not token-like


@pytest.mark.parametrize("key", ["token", "access_token", "refresh_token", "secret", "client_secret", "api_key"])
def test_redacts_token_keys(key: str) -> None:
    assert redact(f"x {key}=abc123 y") == f"x {key}=*** y"
    assert redact(f"{key.upper()}: abc123") == f"{key.upper()}: ***"


def test_redacts_pgpassword_and_driver_urls() -> None:
    assert redact("PGPASSWORD=abc") == "PGPASSWORD=***"
    assert redact("postgresql+asyncpg://u:p@h/d") == "postgresql+asyncpg://***"
    assert redact("postgres+psycopg://u:p@h/d x") == "postgres+psycopg://*** x"


def test_redacts_json_and_dict_style() -> None:
    assert redact('{"password": "abc", "user": "app"}') == '{"password": "***", "user": "app"}'
    assert redact("{'password': 'abc'}") == "{'password': '***'}"


def _format(record: logging.LogRecord) -> tuple[str, dict[str, object]]:
    line = JsonFormatter().format(record)
    return line, json.loads(line)


def _record(msg: str = "x", exc_info: object = None) -> logging.LogRecord:
    return logging.LogRecord("ratatoskr.x", logging.INFO, __file__, 1, msg, (), exc_info)  # type: ignore[arg-type]


def test_non_string_extras_are_redacted() -> None:
    record = _record()
    record.__dict__["cfg"] = {"dsn": SECRET_URL, "password": "abc", "nested": [SECRET_URL]}
    record.__dict__["err"] = ValueError(SECRET_URL)
    line, entry = _format(record)
    assert "hunter2" not in line
    assert "abc" not in line
    assert entry["cfg"] == {"dsn": "***", "password": "***", "nested": ["postgresql://***"]}
    assert entry["err"] == "postgresql://***"


def test_exc_info_is_redacted() -> None:
    try:
        raise ValueError(f"cannot connect {SECRET_URL} password=hunter2")
    except ValueError:
        record = _record(exc_info=sys.exc_info())
    line, entry = _format(record)
    assert "hunter2" not in line
    assert "ValueError" in str(entry["exc"])


def test_json_style_message_stays_valid_json() -> None:
    _, entry = _format(_record('payload {"password": "a\\"b", "token": "t"} sent'))
    assert entry["msg"] == 'payload {"password": "***", "token": "***"} sent'


def test_setup_logging_redacts_third_party_and_avoids_duplicates() -> None:
    stream = io.StringIO()
    setup_logging("INFO", stream=stream)
    setup_logging("INFO", stream=stream)  # idempotent: no second handler
    logging.getLogger("asyncpg").warning("connect %s", SECRET_URL)
    logging.getLogger("ratatoskr.y").info("once")
    lines = [json.loads(line) for line in stream.getvalue().strip().splitlines()]
    assert [entry["logger"] for entry in lines] == ["asyncpg", "ratatoskr.y"]
    assert lines[0]["msg"] == "connect postgresql://***"


# --- second review: formatter robustness, prefixed keys, escapes, performance ---


def _log_to_stream(*args: object, **kwargs: Any) -> tuple[str, list[dict[str, Any]]]:
    stream = io.StringIO()
    setup_logging("INFO", stream=stream)
    logging.getLogger("ratatoskr.z").info(*args, **kwargs)
    out = stream.getvalue()
    return out, [json.loads(line) for line in out.strip().splitlines()]


def test_bad_format_args_never_leak(capsys: pytest.CaptureFixture[str]) -> None:
    out, entries = _log_to_stream("bad fmt %s %s", SECRET_URL)
    err = capsys.readouterr().err
    assert "hunter2" not in out
    assert err == ""
    assert entries[-1]["msg"] == "bad fmt %s %s"
    assert entries[-1]["format_error"] == "TypeError"
    assert entries[-1]["level"] == "INFO"


class _Unprintable:
    def __str__(self) -> str:
        raise RuntimeError(SECRET_URL)

    __repr__ = __str__


def test_unprintable_extra_is_replaced() -> None:
    out, entries = _log_to_stream("x", extra={"obj": _Unprintable(), "items": [_Unprintable()]})
    assert "hunter2" not in out
    assert entries[-1]["obj"] == "<unprintable _Unprintable>"
    assert entries[-1]["items"] == ["<unprintable _Unprintable>"]


def test_self_referencing_extra_does_not_raise() -> None:
    cyclic: dict[str, object] = {"name": "n"}
    cyclic["self"] = cyclic
    shared = ["a"]
    _, entries = _log_to_stream("x", extra={"c": cyclic, "pair": [shared, shared]})
    assert entries[-1]["c"] == {"name": "n", "self": "<...>"}
    assert entries[-1]["pair"] == [["a"], ["a"]]  # shared, not cyclic: kept


def test_deep_nesting_is_cut() -> None:
    deep: list[object] = []
    current = deep
    for _ in range(100):
        inner: list[object] = []
        current.append(inner)
        current = inner
    out, _ = _log_to_stream("x", extra={"deep": deep})
    assert "<...>" in out


def test_failing_stream_does_not_leak(capsys: pytest.CaptureFixture[str]) -> None:
    class _Broken(io.StringIO):
        def write(self, text: str) -> int:
            raise OSError("disk gone")

    setup_logging("INFO", stream=_Broken())
    logging.getLogger("ratatoskr.z").info("connect %s", SECRET_URL)
    assert "hunter2" not in capsys.readouterr().err


def test_redacts_prefixed_secret_keys_in_text() -> None:
    assert redact("db_password=hunter2 user=app") == "db_password=*** user=app"
    assert redact('{"db_password": "x", "user": "app"}') == '{"db_password": "***", "user": "app"}'
    assert redact("X-Api-Key: abc123") == "X-Api-Key: ***"
    assert redact("apikey=abc api-key=def") == "apikey=*** api-key=***"
    assert redact("PGPASSWORD=abc") == "PGPASSWORD=***"


def test_redacts_prefixed_secret_keys_in_structured_extras() -> None:
    secrets = {"db_password": "s1", "user_token": "s2", "password_hash": "s3", "X-Api-Key": "s4"}
    out, entries = _log_to_stream("x", extra={"cfg": secrets})
    assert entries[-1]["cfg"] == {key: "***" for key in secrets}
    assert all(value not in out for value in secrets.values())


def test_normal_fields_are_never_masked() -> None:
    fields = {
        "connection": "main",
        "subject": "alice",
        "tool": "pg_query",
        "rows": 3,
        "duration_ms": 1.5,
        "query_sha256": "ab" * 32,
        "auth_source": "local",
        "result": "ok",
        "error_class": None,
        "audit_ts": "2026-01-01T00:00:00+00:00",
    }
    _, entries = _log_to_stream("hello", extra=fields)
    entry = entries[-1]
    assert entry["msg"] == "hello"
    assert entry["logger"] == "ratatoskr.z"
    assert entry["level"] == "INFO"
    assert "ts" in entry
    for key, value in fields.items():
        assert entry[key] == value


def test_redacts_libpq_escaped_quote() -> None:
    assert redact(r"password='a\'b' user=x") == "password=*** user=x"
    assert redact(r'password="a\"b" user=x') == "password=*** user=x"


@pytest.mark.parametrize(
    "text",
    [
        "a-" * 500_000,
        "x" * 1_000_000,
        '"' * 1_000_000,
        "password='" * 100_000,
        '"password": "' * 80_000,
        "Authorization: " * 70_000,
        "postgresql://" * 80_000,
        ("lorem ipsum db_password=x " * 40_000)[:1_000_000],
    ],
    ids=["dashes", "word", "quotes", "unterminated-kv", "unterminated-json", "auth", "urls", "mixed"],
)
def test_redaction_is_fast_on_one_megabyte(text: str) -> None:
    started = time.perf_counter()
    redact(text)
    assert time.perf_counter() - started < 2.0


def test_overlong_quoted_password_leaves_no_tail() -> None:
    spaced = 'password="' + "a" * 600 + ' SECRETTAIL"'
    escaped = 'password="' + "a" * 300 + '\\"SECRETTAIL' + "b" * 300 + '"'
    assert "SECRETTAIL" not in redact(spaced)
    assert "SECRETTAIL" not in redact(escaped)


def test_uvicorn_color_message_extra_is_dropped() -> None:
    # uvicorn adds an ANSI-coloured copy of each message as extra={"color_message": ...}; JSON lines carry msg only.
    stream = io.StringIO()
    setup_logging("INFO", stream=stream)
    logging.getLogger("uvicorn.error").info(
        "Started server process [%d]", 7, extra={"color_message": "Started server process [\x1b[36m%d\x1b[0m]"}
    )
    entry = json.loads(stream.getvalue().strip().splitlines()[-1])
    assert entry["msg"] == "Started server process [7]"
    assert "color_message" not in entry
