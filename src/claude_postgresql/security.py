from __future__ import annotations

import re
import logging
from dataclasses import dataclass

from claude_postgresql.config import ServerConfig

logger = logging.getLogger("claude_postgresql.security")

# ── Dangerous SQL patterns that are ALWAYS blocked ─────────────────────────
_DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("DROP DATABASE", re.compile(r"\bDROP\s+DATABASE\b", re.IGNORECASE)),
    ("ALTER SYSTEM", re.compile(r"\bALTER\s+SYSTEM\b", re.IGNORECASE)),
    ("COPY … TO PROGRAM", re.compile(r"\bCOPY\b.*\bTO\s+PROGRAM\b", re.IGNORECASE | re.DOTALL)),
    ("pg_read_file", re.compile(r"\bpg_read_file\b", re.IGNORECASE)),
    ("pg_write_file", re.compile(r"\bpg_write_file\b", re.IGNORECASE)),
    ("lo_import", re.compile(r"\blo_import\b", re.IGNORECASE)),
    ("lo_export", re.compile(r"\blo_export\b", re.IGNORECASE)),
    ("CREATE EXTENSION", re.compile(r"\bCREATE\s+EXTENSION\b", re.IGNORECASE)),
]

# Write-class keywords used to detect DML / DDL in read-only mode
_WRITE_KEYWORDS = re.compile(
    r"^\s*(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|DROP|ALTER|CREATE|GRANT|REVOKE|COMMENT)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of a query validation check."""

    valid: bool
    error: str | None = None


class QueryValidator:
    """Validates SQL queries against security rules derived from *ServerConfig*."""

    def __init__(self, config: ServerConfig) -> None:
        self._config = config

    # ── Public API ────────────────────────────────────────────────────────

    def validate(self, sql: str) -> ValidationResult:
        """Run **all** validation checks and return the first failure (or success)."""
        for check in (
            self._check_empty,
            self._check_length,
            self._check_dangerous,
            self._check_read_only,
        ):
            result = check(sql)
            if not result.valid:
                logger.warning("Query rejected: %s", result.error, extra={"query": sql[:200]})
                return result
        return ValidationResult(valid=True)

    def check_schema_access(self, schema: str) -> ValidationResult:
        """Verify that *schema* is within the allowed whitelist (if configured)."""
        allowed = self._config.allowed_schemas
        if allowed and schema not in allowed:
            return ValidationResult(valid=False, error=f"Schema '{schema}' is not in the allowed list: {allowed}")
        return ValidationResult(valid=True)

    def check_table_access(self, schema: str, table: str) -> ValidationResult:
        """Verify that *schema.table* is within the allowed whitelist (if configured)."""
        # First check schema-level access
        schema_result = self.check_schema_access(schema)
        if not schema_result.valid:
            return schema_result

        allowed = self._config.allowed_tables
        if allowed:
            fqn = f"{schema}.{table}"
            if fqn not in allowed:
                return ValidationResult(
                    valid=False,
                    error=f"Table '{fqn}' is not in the allowed list: {allowed}",
                )
        return ValidationResult(valid=True)

    # ── Individual checks ─────────────────────────────────────────────────

    def _check_empty(self, sql: str) -> ValidationResult:
        if not sql or not sql.strip():
            return ValidationResult(valid=False, error="Query is empty.")
        return ValidationResult(valid=True)

    def _check_length(self, sql: str) -> ValidationResult:
        if len(sql) > self._config.max_query_length:
            return ValidationResult(
                valid=False,
                error=f"Query length ({len(sql)}) exceeds maximum ({self._config.max_query_length}).",
            )
        return ValidationResult(valid=True)

    def _check_dangerous(self, sql: str) -> ValidationResult:
        for label, pattern in _DANGEROUS_PATTERNS:
            if pattern.search(sql):
                return ValidationResult(valid=False, error=f"Dangerous operation blocked: {label}")
        return ValidationResult(valid=True)

    def _check_read_only(self, sql: str) -> ValidationResult:
        if not self._config.read_only:
            return ValidationResult(valid=True)
        if _WRITE_KEYWORDS.match(sql):
            return ValidationResult(
                valid=False,
                error="Server is in read-only mode. Only SELECT queries are allowed.",
            )
        return ValidationResult(valid=True)

    # ── Utilities ─────────────────────────────────────────────────────────

    @staticmethod
    def sanitize_identifier(name: str) -> str:
        """Escape a SQL identifier (table / column name) to prevent injection.

        Only allows alphanumeric characters, underscores, and dots. This is NOT
        meant as a replacement for parameterised queries — it guards dynamic
        identifier insertion in ``information_schema`` look-ups.
        """
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name):
            raise ValueError(f"Invalid SQL identifier: {name!r}")
        return name
