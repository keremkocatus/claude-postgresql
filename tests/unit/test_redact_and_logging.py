import io
import json
import logging

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
