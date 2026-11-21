import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres.guard import check_explain_target, check_sql, check_write_sql


@pytest.mark.parametrize("sql", ["", "   ", "-- only a comment", "/* nothing */"])
def test_empty_is_rejected(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="empty"):
        check_sql(sql, max_length=100)


def test_length_limit() -> None:
    with pytest.raises(InvalidRequestError, match="limit is 10"):
        check_sql("SELECT 1 + 1 + 1", max_length=10)
    check_sql("SELECT 1", max_length=10)


@pytest.mark.parametrize(
    "sql",
    [
        "DROP DATABASE prod",
        "ALTER SYSTEM SET work_mem = '1GB'",
        "COPY t TO PROGRAM 'rm -rf /'",
        "COPY t FROM PROGRAM 'curl x'",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_write_file('/tmp/x', 'y')",
        "SELECT lo_import('/etc/passwd')",
        "CREATE EXTENSION dblink",
    ],
)
def test_dangerous_write_statements(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="Blocked operation"):
        check_write_sql(sql, max_length=1000)


@pytest.mark.parametrize(
    "sql",
    ["COMMIT", "begin", "ROLLBACK", "  -- note\nCOMMIT", "/* x */ SAVEPOINT a", "START TRANSACTION", "END"],
)
def test_transaction_control_is_rejected_for_writes(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="Transaction control"):
        check_write_sql(sql, max_length=1000)


def test_normal_write_passes() -> None:
    check_write_sql("UPDATE accounts SET note = 'copy program' WHERE id = $1", max_length=1000)
    check_write_sql("-- comment\nINSERT INTO t VALUES (1)", max_length=1000)


def test_explain_prefix_rejected() -> None:
    with pytest.raises(InvalidRequestError, match="without EXPLAIN"):
        check_explain_target("EXPLAIN SELECT 1", max_length=1000)
    check_explain_target("SELECT 1", max_length=1000)
