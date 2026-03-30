# Claude PostgreSQL MCP Server

High-performance PostgreSQL connector for Claude via the **Model Context Protocol (MCP)**. Provides schema discovery, safe query execution, performance monitoring, and admin tools — all accessible as MCP tools from Claude Desktop or any MCP client.

## Features

- **18 MCP tools** — schema browsing, query execution, database info, admin & performance
- **Connection pooling** — async `asyncpg` with configurable pool sizing
- **Security** — read-only mode, dangerous operation blocking, query length limits, schema/table whitelists
- **Query history** — optional persistence to a PostgreSQL table (configurable DB + table name)
- **SSL/TLS** — optional client certificate authentication
- **Structured logging** — JSON logs to stderr with query timing and row counts

---

## Quick Start

### 1. Install

```bash
# Using uv (recommended)
uv pip install -e .

# Or with pip
pip install -e .
```

### 2. Configure

Create a `.env` file (or set environment variables):

```bash
cp .env.example .env
# Edit .env with your PostgreSQL connection string
```

### 3. Run

```bash
# Direct
claude-postgresql

# Or via Python
python -m claude_postgresql.server
```

### 4. Add to Claude Desktop

Edit your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "postgresql": {
      "command": "claude-postgresql",
      "env": {
        "PG_MCP_DATABASE_URL": "postgresql://user:password@localhost:5432/mydb"
      }
    }
  }
}
```

Or if using `uv`:

```json
{
  "mcpServers": {
    "postgresql": {
      "command": "uv",
      "args": ["run", "claude-postgresql"],
      "cwd": "/path/to/claude-postgresql",
      "env": {
        "PG_MCP_DATABASE_URL": "postgresql://user:password@localhost:5432/mydb"
      }
    }
  }
}
```

---

## Configuration

All settings use the `PG_MCP_` prefix and can be set via environment variables or `.env` file.

### Connection

| Variable | Default | Description |
|----------|---------|-------------|
| `PG_MCP_DATABASE_URL` | *(required)* | PostgreSQL connection DSN |

### Pool

| Variable | Default | Description |
|----------|---------|-------------|
| `PG_MCP_POOL_MIN_SIZE` | `2` | Minimum pool connections |
| `PG_MCP_POOL_MAX_SIZE` | `10` | Maximum pool connections |
| `PG_MCP_COMMAND_TIMEOUT` | `30` | Command timeout (seconds) |
| `PG_MCP_STATEMENT_TIMEOUT` | `30000` | PostgreSQL statement_timeout (ms) |

### Safety & Limits

| Variable | Default | Description |
|----------|---------|-------------|
| `PG_MCP_READ_ONLY` | `false` | Block all write operations |
| `PG_MCP_MAX_RESULT_ROWS` | `500` | Maximum rows returned per query |
| `PG_MCP_MAX_QUERY_LENGTH` | `10000` | Maximum allowed query length |

### Whitelists

| Variable | Default | Description |
|----------|---------|-------------|
| `PG_MCP_ALLOWED_SCHEMAS` | `[]` (all) | Schema whitelist (JSON array). Empty = all allowed |
| `PG_MCP_ALLOWED_TABLES` | `[]` (all) | Table whitelist in `schema.table` format (JSON array). Empty = all allowed |

**Examples:**

```bash
# Only allow public and analytics schemas
PG_MCP_ALLOWED_SCHEMAS='["public", "analytics"]'

# Only allow specific tables
PG_MCP_ALLOWED_TABLES='["public.users", "public.orders", "analytics.events"]'
```

### Query History

| Variable | Default | Description |
|----------|---------|-------------|
| `PG_MCP_QUERY_HISTORY_TABLE` | `None` | Table name for history (e.g. `public.mcp_query_history`). Set to enable. |
| `PG_MCP_QUERY_HISTORY_DB` | `None` | Separate DSN for history storage. Falls back to main `DATABASE_URL`. |

When `QUERY_HISTORY_TABLE` is set, the server auto-creates the table on startup and logs every tool invocation with query text, parameters, timing, and success/failure status.

### SSL/TLS

| Variable | Default | Description |
|----------|---------|-------------|
| `PG_MCP_SSL_ENABLED` | `false` | Enable SSL/TLS |
| `PG_MCP_SSL_CA_FILE` | `None` | CA certificate path |
| `PG_MCP_SSL_CERT_FILE` | `None` | Client certificate path |
| `PG_MCP_SSL_KEY_FILE` | `None` | Client private key path |
| `PG_MCP_SSL_REQUIRE` | `true` | Require SSL (vs. prefer) |

### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `PG_MCP_LOG_QUERIES` | `true` | Log every executed query |
| `PG_MCP_LOG_LEVEL` | `INFO` | Logging level |

---

## Available Tools

### Schema Discovery

| Tool | Description |
|------|-------------|
| `list_schemas` | List all non-system schemas |
| `list_tables` | List tables/views with row estimates |
| `describe_table` | Full table structure (columns, PK, FK, indexes) |
| `get_table_columns` | Lightweight column listing |
| `get_indexes` | Index details |
| `get_foreign_keys` | Foreign key relationships |
| `get_constraints` | All constraints (PK, FK, UNIQUE, CHECK) |

### Query Execution

| Tool | Description |
|------|-------------|
| `execute_select` | Run SELECT queries (auto-limited, timed) |
| `execute_dml` | Run INSERT/UPDATE/DELETE (blocked in read-only) |
| `execute_transaction` | Atomic multi-statement transaction |

### Database Information

| Tool | Description |
|------|-------------|
| `connection_status` | Pool stats + server version + health check |
| `list_databases` | All databases with owner/size |
| `get_database_size` | Current database size |
| `get_table_sizes` | Table sizes (data + index) |

### Admin & Performance

| Tool | Description |
|------|-------------|
| `explain_query` | EXPLAIN ANALYZE execution plan |
| `get_running_queries` | Active queries from pg_stat_activity |
| `get_locks` | Current locks from pg_locks |
| `get_table_stats` | Table statistics (scans, tuples, vacuum) |

---

## Security Model

1. **Parameterized queries** — asyncpg uses native PostgreSQL protocol-level parameterization (not string interpolation)
2. **Dangerous operation blocking** — `DROP DATABASE`, `ALTER SYSTEM`, `COPY TO PROGRAM`, `pg_read_file`, `lo_import/export`, `CREATE EXTENSION` are always blocked
3. **Read-only mode** — when enabled, all DML/DDL statements are rejected
4. **Statement timeout** — prevents runaway queries (default: 30s)
5. **Row limiting** — results capped at configurable maximum (default: 500 rows)
6. **Schema/table whitelists** — restrict which schemas and tables are visible/accessible
7. **Identifier sanitization** — dynamic SQL identifiers are validated against strict patterns
8. **Query logging** — full audit trail of all executed queries with timing

---

## Development

```bash
# Install dev dependencies
uv pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/ tests/

# Type check
mypy src/
```

### Local PostgreSQL for testing

```bash
docker compose up -d    # Start PostgreSQL on port 5432
docker compose down     # Stop
```

---

## License

MIT
