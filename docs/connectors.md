# Connecting Claude

Ratatoskr speaks MCP in two ways: **streamable HTTP** at `<public_url>/mcp` with OAuth (a team server, for example
[`compose.yml`](../compose.yml)), and **stdio** (a local process the client starts). Every client sees the same 19
tools; what a person can use depends on their groups (`roles:` in the config).

Each section says what the test suite checks against Ratatoskr itself and what you have to check by hand: the
client applications are not part of the tests, and their menus change.

## claude.ai (custom connector)

Needs a team server with an https `public_url` that claude.ai can reach from the internet.

1. In claude.ai open the connector settings and add a custom connector with the URL `https://<your domain>/mcp`.
   Leave the OAuth client ID and secret empty: claude.ai registers itself.
2. claude.ai opens Ratatoskr's sign-in page (local users) or sends you to your identity provider (OIDC); afterwards
   the connector shows as connected.
3. Ask Claude to run `list_connections`: it lists exactly the connections your groups grant.

What Ratatoskr does here, covered by tests (`tests/unit/secure_http/e2e/`): dynamic client registration for
redirect URIs on `server.allowed_redirect_hosts` (default `claude.ai`, `claude.com`, `localhost`, `127.0.0.1`),
authorization code with PKCE S256, rotating refresh tokens, revocation; scopes a client asks for (claude.ai sends
`claudeai`) are replaced by Ratatoskr's only scope, `mcp`.

Check by hand:

- [ ] Where the custom connector setting is in your plan (on Team and Enterprise plans an owner may have to add the
      connector for the organization first) and that the flow above completes.
- [ ] Your proxy lets claude.ai's servers reach `/mcp`, `/register`, `/authorize`, `/token` and
      `/.well-known/oauth-authorization-server` (and nothing blocks `/login` or `/oauth/callback` for browsers).
- [ ] A tool call shows up in the audit trail with your user as `subject`.

## Claude Desktop

**Remote (team server):** Claude Desktop uses the connectors of your claude.ai account; add the server as above.

**Local (stdio):** add Ratatoskr to `claude_desktop_config.json` (*Settings → Developer → Edit Config* in recent
versions); Claude Desktop starts the process and talks to it over stdin/stdout:

```json
{
  "mcpServers": {
    "ratatoskr": {
      "command": "ratatoskr",
      "args": ["serve", "--config", "/absolute/path/to/config.yaml"],
      "env": { "APP_DB_DSN": "postgresql://ratatoskr_read:password@localhost:5432/app" }
    }
  }
}
```

If `ratatoskr` is not on Claude Desktop's `PATH`, use the absolute path of the executable (for a virtualenv:
`.venv/bin/ratatoskr`, on Windows `.venv\Scripts\ratatoskr.exe`). Over stdio there is no sign-in: you act as a
member of `server.stdio_role`.

Covered by tests: `tests/unit/test_cli.py` starts `ratatoskr serve` as a real process and speaks JSON-RPC over stdio
with it (initialize, tool list, a tool call) without anything but protocol messages on stdout.

Check by hand:

- [ ] A connector added in claude.ai shows up in Claude Desktop signed in with the same account.
- [ ] After a restart of Claude Desktop the local server shows as running and `list_connections` answers.
- [ ] Its log (stderr) is in Claude Desktop's MCP log files, as JSON lines with secrets masked.

## Claude Code

**Remote (team server):**

```bash
claude mcp add --transport http ratatoskr https://<your domain>/mcp
```

Then run `/mcp` in Claude Code and choose the server to sign in in the browser. Claude Code registers as a public
client (no client secret, PKCE only); sign-in, refresh and `/revoke` for public clients are covered by
`tests/unit/secure_http/e2e/test_http_client_compat.py`. For a server on this machine started with
`serve --insecure-dev`, use `http://127.0.0.1:8000/mcp`.

**Local (stdio):**

```bash
claude mcp add ratatoskr -e APP_DB_DSN='postgresql://ratatoskr_read:password@localhost:5432/app' \
  -- ratatoskr serve --config /absolute/path/to/config.yaml
```

**Dev stack:** with `docker compose -f compose.dev.yml up -d` running, Claude Code can start Ratatoskr inside the
stack, with the sample connections `shop`, `metrics` and `logs`:

```bash
claude mcp add ratatoskr-dev -- docker compose -f /absolute/path/to/compose.dev.yml run --rm -T --use-aliases ratatoskr
```

`-T` keeps a terminal out of the MCP channel; `--use-aliases` lets the dev Prometheus scrape this run's metrics as
`ratatoskr:9100`.

Check by hand:

- [ ] `claude mcp list` shows the server as connected, and `/mcp` shows its tools.
- [ ] For the remote server: sign-in in the browser returns to Claude Code, and the session survives an access token
      lifetime (`auth.access_token_ttl`, default 1 hour) through a refresh.

## Several stdio clients

Each stdio client starts its own process. They share nothing but the config file; with `server.metrics_port` set
only the first can listen on that port, so leave metrics off in configs used by several clients (see
[Metrics](configuration.md#metrics)).
