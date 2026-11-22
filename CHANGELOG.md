# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### 1.0.0 (to be released)

Ratatoskr 1.0.0 replaces `claude-postgresql` 0.1. It is not backward compatible: see [`MIGRATION.md`](MIGRATION.md).

#### Added

- Any number of named PostgreSQL, Prometheus and Loki connections in one server, with one tool set of 19 tools
  (`list_connections`, `connection_health`, nine `pg_*`, five `prom_*`, three `loki_*`).
- One YAML config file with `${ENV}` and `${file:...}` secret references and `ratatoskr check-config`.
- Groups and roles: effective access per connection is the highest grant of your groups, capped by the connection's
  `mode`; unknown and forbidden connections look the same.
- Streamable HTTP transport with Ratatoskr as OAuth 2.1 authorization server (dynamic client registration, PKCE,
  rotating refresh tokens with reuse detection, revocation), local argon2id users (`ratatoskr hash-password`) or
  OIDC sign-in (Authentik guide), rate-limited sign-in, and SQLite state in `/data`.
- Audit trail of every tool call and authentication event, in the JSON log and (over HTTP) in SQLite.
- Separate write role per PostgreSQL connection (`write_dsn`).
- Prometheus metrics on a separate listener (`server.metrics_port`): tool calls, latency, backend reachability,
  authentication events.
- `compose.yml` with Caddy (Let's Encrypt), `compose.dev.yml` with sample PostgreSQL, Prometheus and Loki data.
- Container image: non-root (uid 10001), read-only root file system, health check. The release workflow publishes
  it on version tags to `ghcr.io/keremkocatus/ratatoskr` for linux/amd64 and linux/arm64 with SBOM and provenance.
- CI: lint, types, unit and integration tests, image build and Trivy scan; Dependabot.
- Documentation: configuration reference, connectors, PostgreSQL roles, security model, security policy.

#### Changed

- Name: package `ratatoskr-mcp`, command `ratatoskr`, module `ratatoskr` (was `claude-postgresql`).
- PostgreSQL tools renamed and merged (`execute_select` is now `pg_query`, and so on; see `MIGRATION.md`).
- Read-only enforcement by PostgreSQL (read-only sessions and transactions that are always rolled back, extended
  protocol) instead of SQL pattern matching.

#### Removed

- `PG_MCP_*` environment variables and `.env` loading.
- The `sse` transport, the shared admin password and in-memory tokens.
- `allowed_tables`, the query history table, Railway support (`railway.json`) and the old `docker-compose.yml`.
