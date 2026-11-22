# Security policy

Ratatoskr sits between Claude and your databases, metrics and logs, so security reports are welcome and taken
seriously.

## Reporting a vulnerability

Report it privately through GitHub: open
[a new security advisory](https://github.com/keremkocatus/claude-postgresql/security/advisories/new) (the
repository's *Security* tab → *Report a vulnerability*). Please do not open a public issue, pull request or
discussion for a vulnerability.

Include what you can of:

- the version (`ratatoskr --version`, image tag or commit) and the transport (stdio or streamable HTTP);
- the affected part (OAuth/sign-in, policy, PostgreSQL read path, Prometheus or Loki backends, metrics, image);
- steps to reproduce, or a proof of concept, and the impact you see;
- the relevant config with every secret removed.

The maintainer replies in the advisory, keeps you informed while a fix is prepared and credits you in the advisory
and the changelog unless you prefer otherwise. This is a volunteer project: there is no bug bounty and no fixed
response time.

## Supported versions

Fixes go into the latest release only (the newest `1.x`). `claude-postgresql` 0.1 is no longer maintained.

## Scope

In scope: anything that lets a caller do more than their groups allow, read data of a connection they cannot see,
bypass read-only enforcement on a `mode: read` connection, obtain or replay tokens, sign in without valid
credentials, or makes Ratatoskr leak secrets (DSNs, passwords, tokens, tenants) into tool output, error texts or
logs.

Out of scope: what a database role, Prometheus or Loki credential is itself allowed to do (see
[PostgreSQL roles](docs/postgres-roles.md)), expensive but permitted queries, a reachable metrics port you chose to
expose, and deployments that ignore [the security model](docs/security-model.md) (for example no TLS proxy, or
`--insecure-dev` beyond loopback).
