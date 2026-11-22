-- The read and write roles of docs/postgres-roles.md, for the dev connection "shop" (dsn and write_dsn).
-- Dev-only passwords: compose.dev.yml publishes this database on 127.0.0.1 only.
CREATE ROLE ratatoskr_read LOGIN PASSWORD 'dev-read'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE shop TO ratatoskr_read;
GRANT USAGE ON SCHEMA public TO ratatoskr_read;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ratatoskr_read;
ALTER DEFAULT PRIVILEGES FOR ROLE shop_owner IN SCHEMA public GRANT SELECT ON TABLES TO ratatoskr_read;
GRANT pg_read_all_stats TO ratatoskr_read;

CREATE ROLE ratatoskr_write LOGIN PASSWORD 'dev-write'
  NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT ON DATABASE shop TO ratatoskr_write;
GRANT USAGE ON SCHEMA public TO ratatoskr_write;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ratatoskr_write;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ratatoskr_write;
ALTER DEFAULT PRIVILEGES FOR ROLE shop_owner IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ratatoskr_write;
ALTER DEFAULT PRIVILEGES FOR ROLE shop_owner IN SCHEMA public GRANT USAGE ON SEQUENCES TO ratatoskr_write;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
