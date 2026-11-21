"""Early, readable rejections. NOT the security boundary: that is the read-only pool, single-statement
prepared statements, READ ONLY transactions and, above all, a restricted database role (spec 6.2)."""

from __future__ import annotations

import re

from ratatoskr.backends.errors import InvalidRequestError

_DANGEROUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("DROP DATABASE", re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE)),
    ("ALTER SYSTEM", re.compile(r"\bALTER\s+SYSTEM\b", re.IGNORECASE)),
    ("COPY ... PROGRAM", re.compile(r"\bCOPY\b.*\b(?:TO|FROM)\s+PROGRAM\b", re.IGNORECASE | re.DOTALL)),
    ("pg_read_file", re.compile(r"\bpg_read_file\b", re.IGNORECASE)),
    ("pg_read_binary_file", re.compile(r"\bpg_read_binary_file\b", re.IGNORECASE)),
    ("pg_write_file", re.compile(r"\bpg_write_file\b", re.IGNORECASE)),
    ("lo_import", re.compile(r"\blo_import\b", re.IGNORECASE)),
    ("lo_export", re.compile(r"\blo_export\b", re.IGNORECASE)),
    ("CREATE EXTENSION", re.compile(r"\bCREATE\s+EXTENSION\b", re.IGNORECASE)),
)

# First words that always end or split the surrounding transaction (COMMIT/ROLLBACK PREPARED included) ...
_TRANSACTION_CONTROL_WORDS = frozenset({"BEGIN", "COMMIT", "END", "ROLLBACK", "ABORT", "SAVEPOINT", "RELEASE"})
# ... and two-word forms: START TRANSACTION, PREPARE TRANSACTION (PREPARE name AS ... is allowed).
_TRANSACTION_CONTROL_PAIRS = frozenset({("START", "TRANSACTION"), ("PREPARE", "TRANSACTION")})
_WORD_RE = re.compile(r"[A-Za-z_]+")
_EXPLAIN_RE = re.compile(r"\AEXPLAIN\b", re.IGNORECASE)


def _skip_block_comment(sql: str, start: int) -> int:
    """Index just after the block comment opening at *start*. Block comments nest, as in PostgreSQL."""
    depth = 0
    index = start
    while index < len(sql):
        if sql.startswith("/*", index):
            depth += 1
            index += 2
        elif sql.startswith("*/", index):
            depth -= 1
            index += 2
            if depth == 0:
                return index
        else:
            index += 1
    raise InvalidRequestError("The SQL statement has an unterminated /* comment.")


def _skip_noise(sql: str, index: int) -> int:
    """Index of the next token: skips whitespace, comments (nested block comments included) and ``;``."""
    while index < len(sql):
        if sql[index].isspace() or sql[index] == ";":
            index += 1
        elif sql.startswith("--", index):
            while index < len(sql) and sql[index] not in "\r\n":
                index += 1
        elif sql.startswith("/*", index):
            index = _skip_block_comment(sql, index)
        else:
            break
    return index


def _body(sql: str) -> str:
    """The statement without leading whitespace, comments and empty ``;``."""
    return sql[_skip_noise(sql, 0) :]


def _leading_words(sql: str, count: int) -> list[str]:
    """Up to *count* leading words in upper case; comments and whitespace between them are skipped."""
    words: list[str] = []
    index = 0
    while len(words) < count:
        match = _WORD_RE.match(sql, _skip_noise(sql, index))
        if match is None:
            break
        words.append(match.group(0).upper())
        index = match.end()
    return words


def leading_keyword(sql: str) -> str:
    """The first word of the statement in upper case (``""`` if there is none), comments skipped."""
    words = _leading_words(sql, 1)
    return words[0] if words else ""


def _is_transaction_control(sql: str) -> bool:
    words = _leading_words(sql, 2)
    if not words:
        return False
    return words[0] in _TRANSACTION_CONTROL_WORDS or tuple(words) in _TRANSACTION_CONTROL_PAIRS


def check_sql(sql: str, *, max_length: int) -> None:
    """Reject empty and over-long statements."""
    if not sql or not _body(sql).strip():
        raise InvalidRequestError("The SQL statement is empty.")
    if len(sql) > max_length:
        raise InvalidRequestError(f"The SQL statement is {len(sql)} characters long; the limit is {max_length}.")


def check_write_sql(sql: str, *, max_length: int) -> None:
    """Extra checks for statements that run on the write pool (pg_execute, write-level EXPLAIN ANALYZE)."""
    check_sql(sql, max_length=max_length)
    for label, pattern in _DANGEROUS_PATTERNS:
        if pattern.search(sql):
            raise InvalidRequestError(f"Blocked operation: {label} is not allowed through this server.")
    if _is_transaction_control(sql):
        raise InvalidRequestError(
            "Transaction control statements (BEGIN, COMMIT, ROLLBACK, SAVEPOINT, ...) are not allowed: "
            "pg_execute already runs all statements in one transaction."
        )
    if leading_keyword(sql) == "COPY":
        # COPY FROM STDIN would leave the connection waiting for client data forever.
        raise InvalidRequestError("COPY is not supported; use INSERT ... SELECT or pg_query.")


def check_explain_target(sql: str, *, max_length: int) -> None:
    """pg_explain takes the bare statement; EXPLAIN options come from its arguments."""
    check_sql(sql, max_length=max_length)
    if _EXPLAIN_RE.match(_body(sql)):
        raise InvalidRequestError("Pass the statement without EXPLAIN; use the analyze and buffers arguments.")
