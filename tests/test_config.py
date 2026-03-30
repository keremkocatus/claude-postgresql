from claude_postgresql.config import ServerConfig


def test_default_values(config: ServerConfig) -> None:
    assert config.pool_min_size == 2
    assert config.pool_max_size == 10
    assert config.command_timeout == 30
    assert config.statement_timeout == 30000
    assert config.read_only is False
    assert config.max_result_rows == 500
    assert config.max_query_length == 10000
    assert config.allowed_schemas == []
    assert config.allowed_tables == []
    assert config.ssl_enabled is False
    assert config.log_queries is True
    assert config.log_level == "INFO"


def test_query_history_disabled_by_default(config: ServerConfig) -> None:
    assert config.query_history_enabled is False
    assert config.query_history_table is None


def test_query_history_enabled(history_config: ServerConfig) -> None:
    assert history_config.query_history_enabled is True
    assert history_config.query_history_table == "public.mcp_query_history"
    # Falls back to main DSN
    assert history_config.query_history_dsn == history_config.database_url


def test_query_history_custom_db() -> None:
    cfg = ServerConfig(  # type: ignore[call-arg]
        database_url="postgresql://a@localhost/main",
        query_history_db="postgresql://b@localhost/history",
        query_history_table="audit.query_log",
    )
    assert cfg.query_history_dsn == "postgresql://b@localhost/history"


def test_ssl_context_none_when_disabled(config: ServerConfig) -> None:
    assert config.create_ssl_context() is None


def test_pool_size_validation() -> None:
    import pytest

    with pytest.raises(ValueError, match="pool_min_size"):
        ServerConfig(  # type: ignore[call-arg]
            database_url="postgresql://a@localhost/db",
            pool_min_size=20,
            pool_max_size=5,
        )
