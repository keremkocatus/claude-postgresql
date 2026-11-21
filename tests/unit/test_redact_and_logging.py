import io
import json
import logging
import sys

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


# --- review fixes: wider redaction, structured extras, root logger ---

SECRET_URL = "postgresql://u:hunter2@h/d"


def test_redacts_authorization_headers() -> None:
    assert redact("Authorization: Bearer abc.def.ghi") == "Authorization: Bearer ***"
    assert redact("authorization=Basic dXNlcjpwYXNz rest") == "authorization=Basic *** rest"
    assert redact('{"Authorization": "Bearer abc.def-ghi_0"}') == '{"Authorization": "Bearer ***"}'


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
