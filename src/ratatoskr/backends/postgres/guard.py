"""Early, readable rejections. NOT the security boundary: that is the read-only pool, single-statement
prepared statements, READ ONLY transactions and, above all, a restricted database role (spec 6.2)."""

from __future__ import annotations

import re

from ratatoskr.backends.errors import InvalidRequestError

_LEADING_NOISE_RE = re.compile(r"\A(?:\s+|--[^\n]*(?:\n|\Z)|/\*.*?\*/)*", re.DOTALL)

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

_TRANSACTION_CONTROL_RE = re.compile(
    r"\A(?:BEGIN|START\s+TRANSACTION|COMMIT|END|ROLLBACK|ABORT|SAVEPOINT|RELEASE|PREPARE\s+TRANSACTION)\b",
    re.IGNORECASE,
)
_EXPLAIN_RE = re.compile(r"\AEXPLAIN\b", re.IGNORECASE)


def _body(sql: str) -> str:
    """The statement with leading whitespace and comments removed."""
    return _LEADING_NOISE_RE.sub("", sql, count=1)


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
    if _TRANSACTION_CONTROL_RE.match(_body(sql)):
        raise InvalidRequestError(
            "Transaction control statements (BEGIN, COMMIT, ROLLBACK, SAVEPOINT, ...) are not allowed: "
            "pg_execute already runs all statements in one transaction."
        )


def check_explain_target(sql: str, *, max_length: int) -> None:
    """pg_explain takes the bare statement; EXPLAIN options come from its arguments."""
    check_sql(sql, max_length=max_length)
    if _EXPLAIN_RE.match(_body(sql)):
        raise InvalidRequestError("Pass the statement without EXPLAIN; use the analyze and buffers arguments.")
