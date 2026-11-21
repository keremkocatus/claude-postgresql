import pytest

from ratatoskr.backends.errors import InvalidRequestError
from ratatoskr.backends.postgres.guard import check_explain_target, check_read_sql, check_sql, check_write_sql

# -- read path (pg_query, pg_explain) -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "COPY (SELECT 1) TO PROGRAM 'sleep 2'",
        "COPY items TO '/tmp/x'",
        "copy items to stdout",
        "/* a /* b */ */ COPY items TO STDOUT",
        "  -- c\nCOPY (SELECT 1) TO STDOUT",
    ],
)
def test_read_path_rejects_copy(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="COPY is not supported here"):
        check_read_sql(sql, max_length=1000)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT pg_read_binary_file('/etc/passwd')",
        "SELECT lo_import('/etc/passwd')",
        "SELECT lo_export(1, '/tmp/x')",
        "SELECT pg_write_file('/tmp/x', 'y')",
        "SELECT * FROM pg_ls_dir('.')",
        "SELECT pg_stat_file('postgresql.conf')",
        "SELECT * FROM pg_ls_logdir()",
        "SELECT * FROM PG_LS_WALDIR()",
        "SELECT * FROM pg_ls_tmpdir()",
        "SELECT * FROM pg_ls_archive_statusdir()",
    ],
)
def test_read_path_applies_the_dangerous_function_list(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="Blocked operation"):
        check_read_sql(sql, max_length=1000)


@pytest.mark.parametrize("sql", ["SELECT * FROM pg_ls_dir('.')", "SELECT pg_stat_file('postgresql.conf')"])
def test_write_path_blocks_the_file_listing_functions_too(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="Blocked operation"):
        check_write_sql(sql, max_length=1000)


@pytest.mark.parametrize(
    "sql",
    [
        "DO $$ BEGIN EXECUTE 'CO' || 'PY (SELECT 1) TO PROGRAM ''true'''; END $$",
        "/* x */ do language plpgsql $$ BEGIN NULL; END $$",
    ],
)
def test_read_path_rejects_do_blocks(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="DO blocks are not supported"):
        check_read_sql(sql, max_length=1000)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM copy_log WHERE note = 'do it'",
        "WITH c AS (SELECT 1) SELECT * FROM c",
        "SELECT pg_size_pretty(pg_database_size(current_database()))",
        "SHOW work_mem",
    ],
)
def test_read_path_allows_ordinary_reads(sql: str) -> None:
    check_read_sql(sql, max_length=1000)


def test_read_path_keeps_the_basic_checks() -> None:
    with pytest.raises(InvalidRequestError, match="empty"):
        check_read_sql(" -- nothing", max_length=1000)
    with pytest.raises(InvalidRequestError, match="limit is 5"):
        check_read_sql("SELECT 1 + 1", max_length=5)


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


@pytest.mark.parametrize(
    "sql",
    [
        "/* /* */ */ COMMIT",
        "/* a /* b /* c */ */ */\nROLLBACK",
        "/* /* -- */ */ -- x\n/**/ END",
        "; COMMIT",
        " ;\n; /* x */ ; BEGIN",
        "--x\r\nCOMMIT",
        "--x\rCOMMIT",
    ],
)
def test_transaction_control_behind_nested_comments_or_empty_statements(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="Transaction control"):
        check_write_sql(sql, max_length=1000)


@pytest.mark.parametrize("sql", ["/* /* */ COMMIT", "/* never closed", "/* x */ /* y"])
def test_unterminated_leading_comment_is_rejected(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="unterminated"):
        check_sql(sql, max_length=1000)


@pytest.mark.parametrize("sql", ["/* /* */ */", "; ;", "/* a */ -- b"])
def test_nested_comments_only_is_empty(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="empty"):
        check_sql(sql, max_length=100)


def test_explain_behind_nested_comment_rejected() -> None:
    with pytest.raises(InvalidRequestError, match="without EXPLAIN"):
        check_explain_target("/* /* */ */ EXPLAIN SELECT 1", max_length=1000)


@pytest.mark.parametrize(
    "sql",
    [
        "PREPARE/**/TRANSACTION 'x'",
        "prepare /* a /* b */ */ transaction 'x'",
        "PREPARE\n-- c\nTRANSACTION 'x'",
        "PREPARE\tTRANSACTION 'x'",
        "START/**/TRANSACTION",
        "COMMIT PREPARED 'x'",
        "ROLLBACK/**/PREPARED 'x'",
        "/* x */ commit\nprepared 'x'",
    ],
)
def test_two_word_transaction_control_with_comments_between(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="Transaction control"):
        check_write_sql(sql, max_length=1000)


def test_prepare_of_a_statement_is_not_transaction_control() -> None:
    check_write_sql("PREPARE ins (int) AS INSERT INTO t VALUES ($1)", max_length=1000)


@pytest.mark.parametrize(
    "sql",
    ["COPY t FROM STDIN", "copy t to stdout", "/* x */ COPY (SELECT 1) TO STDOUT", "  -- c\nCOPY t FROM STDIN"],
)
def test_copy_is_rejected_for_writes(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match=r"COPY is not supported; use INSERT \.\.\. SELECT or pg_query"):
        check_write_sql(sql, max_length=1000)


def test_copy_inside_a_string_is_not_rejected() -> None:
    check_write_sql("INSERT INTO notes VALUES ('COPY t FROM STDIN')", max_length=1000)


def test_normal_write_passes() -> None:
    check_write_sql("UPDATE accounts SET note = 'copy program' WHERE id = $1", max_length=1000)
    check_write_sql("-- comment\nINSERT INTO t VALUES (1)", max_length=1000)


def test_explain_prefix_rejected() -> None:
    with pytest.raises(InvalidRequestError, match="without EXPLAIN"):
        check_explain_target("EXPLAIN SELECT 1", max_length=1000)
    check_explain_target("SELECT 1", max_length=1000)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT dblink_exec('dbname=app', 'DELETE FROM items')",
        "SELECT * FROM dblink('dbname=app', 'SELECT 1') AS t(x int)",
        "SELECT dblink_connect('c', 'dbname=app')",
        "select public.DBLINK_EXEC('x', 'y')",
    ],
)
def test_read_path_rejects_dblink(sql: str) -> None:
    with pytest.raises(InvalidRequestError, match="dblink"):
        check_read_sql(sql, max_length=10_000)


def test_write_path_still_allows_dblink() -> None:
    check_write_sql("SELECT dblink_exec('dbname=app', 'DELETE FROM items')", max_length=10_000)
