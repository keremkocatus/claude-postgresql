from __future__ import annotations

from claude_postgresql.database import DatabaseManager
from claude_postgresql.formatters import format_as_markdown_table, serialize_rows
from claude_postgresql.security import QueryValidator


async def list_schemas(db: DatabaseManager, validator: QueryValidator) -> str:
    """List all non-system schemas in the database."""
    query = """
        SELECT schema_name, catalog_name
        FROM information_schema.schemata
        WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        ORDER BY schema_name
    """
    result = await db.fetch(query)
    rows = result.data

    # Filter by whitelist if configured
    allowed = validator._config.allowed_schemas
    if allowed:
        rows = [r for r in rows if r["schema_name"] in allowed]

    return format_as_markdown_table(rows)


async def list_tables(db: DatabaseManager, validator: QueryValidator, schema: str = "public") -> str:
    """List all tables and views in *schema* with row-count estimates."""
    access = validator.check_schema_access(schema)
    if not access.valid:
        return f"❌ {access.error}"

    schema_safe = QueryValidator.sanitize_identifier(schema)

    query = """
        SELECT
            t.table_name,
            t.table_type,
            COALESCE(s.n_live_tup, 0) AS estimated_rows
        FROM information_schema.tables t
        LEFT JOIN pg_stat_user_tables s
            ON s.schemaname = t.table_schema AND s.relname = t.table_name
        WHERE t.table_schema = $1
        ORDER BY t.table_name
    """
    result = await db.fetch(query, schema_safe)
    rows = result.data

    # Filter by table whitelist if configured
    allowed_tables = validator._config.allowed_tables
    if allowed_tables:
        rows = [r for r in rows if f"{schema}.{r['table_name']}" in allowed_tables]

    if not rows:
        return f"_No tables found in schema `{schema_safe}`._"

    return format_as_markdown_table(rows)


async def describe_table(
    db: DatabaseManager, validator: QueryValidator, table: str, schema: str = "public"
) -> str:
    """Return full structural information for a table: columns, PK, FKs, indexes, constraints."""
    access = validator.check_table_access(schema, table)
    if not access.valid:
        return f"❌ {access.error}"

    schema_safe = QueryValidator.sanitize_identifier(schema)
    table_safe = QueryValidator.sanitize_identifier(table)

    # ── Columns ───────────────────────────────────────────────────────
    col_query = """
        SELECT
            column_name,
            data_type,
            character_maximum_length,
            is_nullable,
            column_default
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        ORDER BY ordinal_position
    """

    # ── Primary key ───────────────────────────────────────────────────
    pk_query = """
        SELECT kcu.column_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
        WHERE tc.table_schema = $1
          AND tc.table_name = $2
          AND tc.constraint_type = 'PRIMARY KEY'
        ORDER BY kcu.ordinal_position
    """

    # ── Foreign keys ──────────────────────────────────────────────────
    fk_query = """
        SELECT
            kcu.column_name    AS from_column,
            ccu.table_schema   AS to_schema,
            ccu.table_name     AS to_table,
            ccu.column_name    AS to_column,
            tc.constraint_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage ccu
            ON tc.constraint_name = ccu.constraint_name
            AND tc.table_schema = ccu.table_schema
        WHERE tc.table_schema = $1
          AND tc.table_name = $2
          AND tc.constraint_type = 'FOREIGN KEY'
    """

    # ── Indexes ───────────────────────────────────────────────────────
    idx_query = """
        SELECT
            i.relname AS index_name,
            ix.indisunique AS is_unique,
            ix.indisprimary AS is_primary,
            am.amname AS index_type,
            ARRAY_AGG(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns
        FROM pg_index ix
        JOIN pg_class t ON t.oid = ix.indrelid
        JOIN pg_class i ON i.oid = ix.indexrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_am am ON am.oid = i.relam
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
        WHERE n.nspname = $1 AND t.relname = $2
        GROUP BY i.relname, ix.indisunique, ix.indisprimary, am.amname
        ORDER BY i.relname
    """

    cols_result = await db.fetch(col_query, schema_safe, table_safe)
    pk_result = await db.fetch(pk_query, schema_safe, table_safe)
    fk_result = await db.fetch(fk_query, schema_safe, table_safe)
    idx_result = await db.fetch(idx_query, schema_safe, table_safe)

    parts: list[str] = [f"## Table: `{schema_safe}.{table_safe}`\n"]

    # Columns
    parts.append("### Columns\n")
    parts.append(format_as_markdown_table(cols_result.data))

    # Primary key
    pk_cols = [r["column_name"] for r in pk_result.data]
    if pk_cols:
        parts.append(f"\n### Primary Key\n`({', '.join(pk_cols)})`")

    # Foreign keys
    if fk_result.data:
        parts.append("\n### Foreign Keys\n")
        parts.append(format_as_markdown_table(fk_result.data))

    # Indexes
    if idx_result.data:
        parts.append("\n### Indexes\n")
        idx_rows = serialize_rows(idx_result.data)
        parts.append(format_as_markdown_table(idx_rows))

    return "\n".join(parts)


async def get_table_columns(
    db: DatabaseManager, validator: QueryValidator, table: str, schema: str = "public"
) -> str:
    """Light-weight column listing for a table."""
    access = validator.check_table_access(schema, table)
    if not access.valid:
        return f"❌ {access.error}"

    schema_safe = QueryValidator.sanitize_identifier(schema)
    table_safe = QueryValidator.sanitize_identifier(table)

    query = """
        SELECT column_name, data_type, is_nullable, column_default
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        ORDER BY ordinal_position
    """
    result = await db.fetch(query, schema_safe, table_safe)
    return format_as_markdown_table(result.data)


async def get_indexes(
    db: DatabaseManager, validator: QueryValidator, table: str, schema: str = "public"
) -> str:
    """List indexes on a table."""
    access = validator.check_table_access(schema, table)
    if not access.valid:
        return f"❌ {access.error}"

    schema_safe = QueryValidator.sanitize_identifier(schema)
    table_safe = QueryValidator.sanitize_identifier(table)

    query = """
        SELECT
            i.relname AS index_name,
            ix.indisunique AS is_unique,
            ix.indisprimary AS is_primary,
            am.amname AS index_type,
            ARRAY_AGG(a.attname ORDER BY array_position(ix.indkey, a.attnum)) AS columns
        FROM pg_index ix
        JOIN pg_class t ON t.oid = ix.indrelid
        JOIN pg_class i ON i.oid = ix.indexrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        JOIN pg_am am ON am.oid = i.relam
        JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
        WHERE n.nspname = $1 AND t.relname = $2
        GROUP BY i.relname, ix.indisunique, ix.indisprimary, am.amname
        ORDER BY i.relname
    """
    result = await db.fetch(query, schema_safe, table_safe)
    return format_as_markdown_table(serialize_rows(result.data))


async def get_foreign_keys(
    db: DatabaseManager, validator: QueryValidator, table: str, schema: str = "public"
) -> str:
    """List foreign key relationships for a table."""
    access = validator.check_table_access(schema, table)
    if not access.valid:
        return f"❌ {access.error}"

    schema_safe = QueryValidator.sanitize_identifier(schema)
    table_safe = QueryValidator.sanitize_identifier(table)

    query = """
        SELECT
            kcu.column_name    AS from_column,
            ccu.table_schema   AS to_schema,
            ccu.table_name     AS to_table,
            ccu.column_name    AS to_column,
            tc.constraint_name
        FROM information_schema.table_constraints tc
        JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
        JOIN information_schema.constraint_column_usage ccu
            ON tc.constraint_name = ccu.constraint_name
            AND tc.table_schema = ccu.table_schema
        WHERE tc.table_schema = $1
          AND tc.table_name = $2
          AND tc.constraint_type = 'FOREIGN KEY'
    """
    result = await db.fetch(query, schema_safe, table_safe)
    return format_as_markdown_table(result.data)


async def get_constraints(
    db: DatabaseManager, validator: QueryValidator, table: str, schema: str = "public"
) -> str:
    """List all constraints (PK, FK, UNIQUE, CHECK) on a table."""
    access = validator.check_table_access(schema, table)
    if not access.valid:
        return f"❌ {access.error}"

    schema_safe = QueryValidator.sanitize_identifier(schema)
    table_safe = QueryValidator.sanitize_identifier(table)

    query = """
        SELECT
            tc.constraint_name,
            tc.constraint_type,
            STRING_AGG(kcu.column_name, ', ' ORDER BY kcu.ordinal_position) AS columns
        FROM information_schema.table_constraints tc
        LEFT JOIN information_schema.key_column_usage kcu
            ON tc.constraint_name = kcu.constraint_name
            AND tc.table_schema = kcu.table_schema
        WHERE tc.table_schema = $1
          AND tc.table_name = $2
        GROUP BY tc.constraint_name, tc.constraint_type
        ORDER BY tc.constraint_type, tc.constraint_name
    """
    result = await db.fetch(query, schema_safe, table_safe)
    return format_as_markdown_table(result.data)
