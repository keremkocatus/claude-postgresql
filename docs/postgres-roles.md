# PostgreSQL roles for Ratatoskr

Ratatoskr keeps reads read-only in several layers (read-only sessions and transactions that are always rolled back,
the extended protocol, a session reset; see [the security model](security-model.md)), but **the database role in each
DSN is the real boundary**. Those layers cannot take away a privilege the role has, and they do not stop extensions
that open their own connections (`dblink`, `postgres_fdw`). Give every connection a dedicated role with only the
grants it needs; never a superuser or the owner of the tables.

The recipes below assume a database `app` whose tables belong to `app_owner` and live in schema `public`. Replace
the three names and the passwords. They work on PostgreSQL 12 and newer; run them as a superuser or as a role that
may create roles and grant on those objects. `tests/integration/test_postgres_roles_doc.py` runs the two SQL blocks
of this page against a real PostgreSQL and checks what each role can and cannot do; the dev stack
(`dev/postgres/initdb/02-ratatoskr-roles.sql`) uses the same grants.

## 1. Read role (`dsn`)

Every read logs in with `dsn`: `pg_query`, the discovery tools, `pg_explain`, `pg_activity`, `pg_table_stats`,
`pg_server_info` and `connection_health`.

```sql
CREATE ROLE ratatoskr_read LOGIN PASSWORD 'change-me'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
-- Another layer for anything else that logs in with this role; Ratatoskr's read sessions are read-only anyway.
ALTER ROLE ratatoskr_read SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE app TO ratatoskr_read;
GRANT USAGE ON SCHEMA public TO ratatoskr_read;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ratatoskr_read;
-- Tables app_owner creates later:
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT SELECT ON TABLES TO ratatoskr_read;
-- PostgreSQL 14 and older let every role create objects in public; 15 and newer do not.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

**`REVOKE CREATE ON SCHEMA public FROM PUBLIC` applies to the whole database**, not only to `ratatoskr_read`: on
PostgreSQL 14 and older, every other role that creates tables, views or functions in `public` without its own
`CREATE` grant loses that right too (migrations and application roles break). Before running it there, grant
`CREATE ON SCHEMA public` to the roles that need it (for example `app_owner`), or leave the line out.

Repeat the `USAGE`, `SELECT` and `ALTER DEFAULT PRIVILEGES` lines for every other schema the connection should
see, and leave out tables it should not read: `allowed_schemas` in the config only filters the discovery tools, it
does not restrict SQL.

Optional: `GRANT pg_read_all_stats TO ratatoskr_read;` lets `pg_activity` show the queries of other users'
sessions. Those query texts can contain values your users may not otherwise see (literals, sometimes secrets), so
grant it only where that is acceptable. Without it `pg_activity` lists other users' sessions without their query
text.

## 2. Write role (`write_dsn`)

For a connection with `mode: write`, give the write pool its own login with `write_dsn`. Only `pg_execute` and
write-level `pg_explain(analyze=true)` use it; reads keep using `dsn`. Grant only what `pg_execute` should change.

```sql
CREATE ROLE ratatoskr_write LOGIN PASSWORD 'change-me-too'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE app TO ratatoskr_write;
GRANT USAGE ON SCHEMA public TO ratatoskr_write;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ratatoskr_write;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ratatoskr_write;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ratatoskr_write;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT USAGE ON SEQUENCES TO ratatoskr_write;
```

This role cannot create, alter, drop or truncate tables. Grant `TRUNCATE` or DDL rights only if `pg_execute` is
meant to do that.

Why a separate role: without `write_dsn` both pools log in as the same user, and PostgreSQL lets a session cancel
or end any other session of its own user, so a caller with read access could end in-flight writes with
`pg_terminate_backend`. The same holds for two Ratatoskr connections that point at one server with one user.

## 3. Configuration

```yaml
connections:
  app-db:
    kind: postgres
    mode: write                     # leave out (read) for a read-only connection, and then omit write_dsn
    dsn: ${APP_DB_READ_DSN}         # postgresql://ratatoskr_read:...@db.internal:5432/app
    write_dsn: ${APP_DB_WRITE_DSN}  # postgresql://ratatoskr_write:...@db.internal:5432/app
```

`check-config` shows `separate write role: yes` for a write connection with `write_dsn`.

## 4. Do not grant

- Superuser, `CREATEROLE`, `BYPASSRLS`, or membership in the table owner's role.
- `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program` (server files and programs).
- `EXECUTE` on `dblink*` functions or `USAGE` on a `postgres_fdw` server: they open connections Ratatoskr does not
  control.
- `pg_signal_backend` (cancel or end other users' sessions).

## 5. Check it

Connect as each role (`psql "postgresql://ratatoskr_read:...@db.internal/app"`) and expect:

| Statement | `ratatoskr_read` | `ratatoskr_write` |
|---|---|---|
| `SELECT ... FROM <table>` | works | works |
| `INSERT` / `UPDATE` / `DELETE` | `permission denied` or `cannot execute ... in a read-only transaction` | works |
| `CREATE TABLE x (id int)` | refused | `permission denied for schema public` |
| `TRUNCATE <table>` | refused | `permission denied` |
