import pytest

from claude_postgresql.security import QueryValidator


class TestValidation:
    """Core query validation tests."""

    def test_valid_select(self, config) -> None:
        v = QueryValidator(config)
        result = v.validate("SELECT * FROM users")
        assert result.valid

    def test_empty_query(self, config) -> None:
        v = QueryValidator(config)
        result = v.validate("")
        assert not result.valid
        assert "empty" in result.error.lower()

    def test_whitespace_only(self, config) -> None:
        v = QueryValidator(config)
        result = v.validate("   ")
        assert not result.valid

    def test_query_too_long(self, config) -> None:
        v = QueryValidator(config)
        result = v.validate("SELECT " + "x" * 20000)
        assert not result.valid
        assert "length" in result.error.lower()


class TestDangerousOperations:
    """Dangerous SQL patterns should always be blocked."""

    @pytest.mark.parametrize(
        "sql",
        [
            "DROP DATABASE production",
            "drop database mydb",
            "ALTER SYSTEM SET max_connections = 999",
            "COPY users TO PROGRAM 'cat /etc/passwd'",
            "SELECT pg_read_file('/etc/passwd')",
            "SELECT pg_write_file('/tmp/evil', 'data')",
            "SELECT lo_import('/etc/passwd')",
            "SELECT lo_export(1234, '/tmp/out')",
            "CREATE EXTENSION dblink",
        ],
    )
    def test_dangerous_blocked(self, config, sql: str) -> None:
        v = QueryValidator(config)
        result = v.validate(sql)
        assert not result.valid
        assert "blocked" in result.error.lower() or "dangerous" in result.error.lower()

    def test_safe_drop_table_allowed(self, config) -> None:
        """DROP TABLE (not DATABASE) is not in the always-blocked list."""
        v = QueryValidator(config)
        result = v.validate("DROP TABLE temp_data")
        assert result.valid


class TestReadOnly:
    """Read-only mode enforcement."""

    @pytest.mark.parametrize(
        "sql",
        [
            "INSERT INTO users VALUES (1)",
            "UPDATE users SET name = 'x'",
            "DELETE FROM users",
            "TRUNCATE users",
            "DROP TABLE users",
            "ALTER TABLE users ADD COLUMN foo INT",
            "CREATE TABLE new_table (id INT)",
        ],
    )
    def test_write_blocked_in_readonly(self, readonly_config, sql: str) -> None:
        v = QueryValidator(readonly_config)
        result = v.validate(sql)
        assert not result.valid
        assert "read-only" in result.error.lower()

    def test_select_allowed_in_readonly(self, readonly_config) -> None:
        v = QueryValidator(readonly_config)
        result = v.validate("SELECT * FROM users")
        assert result.valid


class TestWhitelists:
    """Schema and table whitelist tests."""

    def test_allowed_schema(self, whitelist_config) -> None:
        v = QueryValidator(whitelist_config)
        assert v.check_schema_access("public").valid
        assert v.check_schema_access("app").valid

    def test_denied_schema(self, whitelist_config) -> None:
        v = QueryValidator(whitelist_config)
        result = v.check_schema_access("secret")
        assert not result.valid
        assert "not in the allowed list" in result.error

    def test_allowed_table(self, whitelist_config) -> None:
        v = QueryValidator(whitelist_config)
        assert v.check_table_access("public", "users").valid
        assert v.check_table_access("app", "settings").valid

    def test_denied_table(self, whitelist_config) -> None:
        v = QueryValidator(whitelist_config)
        result = v.check_table_access("public", "secrets")
        assert not result.valid
        assert "not in the allowed list" in result.error

    def test_denied_table_wrong_schema(self, whitelist_config) -> None:
        v = QueryValidator(whitelist_config)
        result = v.check_table_access("secret", "users")
        assert not result.valid

    def test_empty_whitelist_allows_all(self, config) -> None:
        v = QueryValidator(config)
        assert v.check_schema_access("anything").valid
        assert v.check_table_access("any_schema", "any_table").valid


class TestSanitizeIdentifier:
    """Identifier sanitization."""

    def test_valid_identifiers(self) -> None:
        assert QueryValidator.sanitize_identifier("users") == "users"
        assert QueryValidator.sanitize_identifier("my_table_2") == "my_table_2"
        assert QueryValidator.sanitize_identifier("_private") == "_private"

    def test_invalid_identifiers(self) -> None:
        with pytest.raises(ValueError):
            QueryValidator.sanitize_identifier("users; DROP TABLE --")
        with pytest.raises(ValueError):
            QueryValidator.sanitize_identifier("Robert'); DROP TABLE")
        with pytest.raises(ValueError):
            QueryValidator.sanitize_identifier("")
        with pytest.raises(ValueError):
            QueryValidator.sanitize_identifier("123abc")
