# Authentik as the identity provider

Ratatoskr is an OAuth 2.1 authorization server towards MCP clients (claude.ai, Claude Desktop, Claude Code) and an
OpenID Connect relying party towards Authentik. People sign in at Authentik; Ratatoskr reads their groups from the
ID token and maps them to connections through `roles:` in `config.yaml`.

Throughout this page `https://mcp.example.com` is Ratatoskr's `server.public_url` and `https://auth.example.com` is
Authentik. Replace both. Ratatoskr itself serves plain HTTP on port 8000; a reverse proxy (Caddy in the examples)
terminates TLS in front of it.

## 1. Groups scope mapping

Authentik's default `profile` scope already carries a `groups` claim, but a dedicated scope keeps the claim explicit
and lets you shape it.

1. *Customization → Property Mappings → Create → Scope Mapping*.
2. Name `ratatoskr groups`, **Scope name** `groups`, description `Group membership for Ratatoskr`.
3. Expression:

   ```python
   return {"groups": [group.name for group in request.user.ak_groups.all()]}
   ```

The group names are matched exactly against the keys under `roles:`.

## 2. OAuth2/OpenID provider

*Applications → Providers → Create → OAuth2/OpenID Provider*:

| Field | Value |
|---|---|
| Name | `ratatoskr` |
| Authorization flow | **`default-provider-authorization-explicit-consent`** (recommended, see below) |
| Client type | **Confidential** |
| Client ID / Client Secret | generated; copy both into the environment as `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` |
| Redirect URIs/Origins | **Strict**, exactly `https://mcp.example.com/oauth/callback` |
| Signing Key | a certificate, e.g. `authentik Self-signed Certificate`. **Required**: without it Authentik signs ID tokens with HS256 and publishes an empty JWKS, which Ratatoskr rejects (only RS/PS/ES algorithms are accepted) |
| Scopes (advanced) | `authentik default OAuth Mapping: OpenID 'openid'`, `… 'email'`, `… 'profile'`, `… 'offline_access'`, `ratatoskr groups` |
| Include claims in id_token | **on** (the default). Ratatoskr reads `email` and `groups` from the ID token only |
| Subject mode | any; Ratatoskr uses the claim named by `subject_claim` (default `email`), see below |
| Access code validity | `minutes=1` (default) |
| Refresh token validity | at least `auth.refresh_token_ttl` (default 30 days) |

**Explicit consent.** In OIDC mode Ratatoskr shows no consent page of its own: `/login` sends the browser straight
to Authentik, and if Authentik also consents implicitly, a user who is already signed in there is sent back with a
code without seeing anything. Any MCP client that registered itself (dynamic registration is open by design) could
then start a sign-in in that user's browser and obtain a session for them, as long as its redirect URI is on
`server.allowed_redirect_hosts` (a confused deputy). Two things limit that: keep `allowed_redirect_hosts` to the
hosts of the clients you actually use (the default is claude.ai, claude.com and loopback), and use Authentik's
explicit-consent flow so that every new sign-in stops at a page where the user confirms it. Authentik remembers the
consent per user and application, so this costs one click per user, not one per sign-in.

`offline_access` is mandatory: Ratatoskr re-validates every user at Authentik on each of its own refreshes (at most
`auth.access_token_ttl`, default 1 hour, apart). Without an Authentik refresh token that check is impossible, so
the user would have to sign in again every hour.

**Subject claim.** `subject_claim` is the identity written to the audit trail and used for sessions. Ratatoskr does
not check `email_verified`. With the default `subject_claim: email`, make sure users cannot change their own e-mail
address in Authentik (remove the e-mail field from the user settings flow / prompt stage), or use
`subject_claim: sub`, which never changes.

**Key rotation.** Ratatoskr caches the JWKS for an hour and refetches it when an ID token names an unknown `kid`
(at most once a minute). If the JWKS lists the same `kid` twice, the first key is used: give every certificate its
own key.

## 3. Application

*Applications → Applications → Create*: name `Ratatoskr`, slug `mcp`, provider `ratatoskr`. Bind a policy or group
under *Policy / Group / User Bindings* if only some people may use it at all. The issuer is then
`https://auth.example.com/application/o/mcp/` (with the trailing slash).

## 4. Ratatoskr configuration

```yaml
server:
  transport: streamable-http
  public_url: https://mcp.example.com
  host: 0.0.0.0
  port: 8000
  secret_key: ${SERVER_SECRET_KEY}          # >= 32 random characters: python -c "import secrets; print(secrets.token_urlsafe(48))"
  trusted_proxies: [172.18.0.0/16]          # the reverse proxy's address or network (see below)
auth:
  mode: oidc
  access_token_ttl: 1h
  refresh_token_ttl: 30d
  session_max_age: 30d                      # absolute: sign in again after this, whatever the refreshes
  oidc:
    issuer: https://auth.example.com/application/o/mcp/
    client_id: ${OIDC_CLIENT_ID}
    client_secret: ${OIDC_CLIENT_SECRET}
    scopes: [openid, email, profile, groups, offline_access]
    groups_claim: groups
    subject_claim: email
roles:
  admins: { "*": write }
  devops: { prod-pg: read }
connections:
  prod-pg:
    kind: postgres
    dsn: ${PROD_PG_DSN}
```

Run it with the image (state lives in `/data`, the config is read from `/config/config.yaml`):

```bash
docker run -d --name ratatoskr --read-only --restart unless-stopped \
  -v ratatoskr-data:/data -v "$PWD/config.yaml:/config/config.yaml:ro" \
  -e SERVER_SECRET_KEY -e OIDC_CLIENT_ID -e OIDC_CLIENT_SECRET -e PROD_PG_DSN \
  --network proxy ratatoskr:latest
```

Keep the container's stop grace period at 10 s or more (Docker's default): on SIGTERM Ratatoskr finishes in-flight
requests and writes queued audit events before it exits.

`server.secret_key` protects the sealed Authentik refresh tokens, the registered client secrets and the signed
cookies. Changing it is the emergency switch: every stored Authentik refresh token and client secret becomes
unreadable, every session ends and all users must reconnect.

## 5. Reverse proxy (Caddy)

```caddyfile
mcp.example.com {
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    @probes path /healthz /readyz
    respond @probes 404
    reverse_proxy ratatoskr:8000
}
```

- **HSTS** is set here, at the proxy that terminates TLS; Ratatoskr does not send it.
- **`trusted_proxies` must be Caddy's IP or network.** Ratatoskr only honours `X-Forwarded-For` from those
  addresses. If the list is empty (or wrong), every request seems to come from Caddy: all clients share one
  rate-limit bucket, five wrong logins lock everyone out and the `/authorize` budget becomes global. Do not list
  `0.0.0.0/0` (Ratatoskr warns): then any client can choose its own IP.
- **Do not expose `/healthz` and `/readyz` publicly.** They are for the container health check and your monitoring
  on the internal network; the snippet above hides them.
- **Volumetric DoS** is the proxy's job. Ratatoskr limits sign-in, `/register` and `/authorize` per client IP and
  caps auth request bodies at 64 KiB, but `/token`, `/revoke` and `/mcp` have no per-IP limit; add `rate_limit`
  (a Caddy plugin) or your edge's limits if they are reachable from the internet.

## 6. Behaviour worth knowing

- **Group changes** reach Ratatoskr at the next refresh of the MCP client's token (at most `access_token_ttl`).
  A user Authentik refuses (deactivated, removed from the application binding) loses the whole session at that
  refresh; an Authentik outage keeps existing tokens until they expire and is retried.
- **`auth.session_max_age`** (default 30 days, at least 1 day, never shorter than `refresh_token_ttl`) is an absolute
  limit: after it the user signs in again even if the client kept refreshing.
- **Refresh token rotation.** Every refresh returns a new refresh token. Presenting a used refresh token again
  revokes the whole session (`token_reuse_detected` in the audit trail), except within 5 seconds of its use: such a
  retry is refused but leaves the session alive (`refresh_retry_within_grace`). Consequence: calling `/revoke` with
  the *old* refresh token within those 5 seconds does not end the session; revoke with the current one.

## 7. Verification checklist

Run these after every Authentik or Ratatoskr upgrade.

- [ ] `curl -s https://auth.example.com/application/o/mcp/.well-known/openid-configuration` returns JSON whose
      `issuer` is exactly the configured issuer and whose `id_token_signing_alg_values_supported` contains `RS256`
      (or another RS/PS/ES algorithm).
- [ ] `curl -s https://auth.example.com/application/o/mcp/jwks/` lists at least one key (an empty `keys` list means
      no signing key is selected on the provider).
- [ ] `docker exec ratatoskr ratatoskr check-config` succeeds, prints no secret and no warning you did not expect.
- [ ] From the internal network: `docker exec ratatoskr python -c "import urllib.request as u;
      print(u.urlopen('http://127.0.0.1:8000/readyz').read().decode())"` prints `{"status":"ready"}`; `docker ps`
      shows `(healthy)`. From outside, `https://mcp.example.com/healthz` answers 404 (hidden by the proxy).
- [ ] `curl -sI https://mcp.example.com/.well-known/oauth-authorization-server` (headers only) shows a
      `Strict-Transport-Security` header, and `curl -s https://mcp.example.com/.well-known/oauth-authorization-server`
      (the JSON document) lists `/authorize`, `/token`, `/register` and `/revoke` under `https://mcp.example.com`
      and `"scopes_supported": ["mcp"]`.
- [ ] In claude.ai: *Settings → Connectors → Add custom connector*, URL `https://mcp.example.com/mcp`. The browser
      goes to Authentik (the consent page names the `Ratatoskr` application), then back to claude.ai; the connector
      shows as connected.
- [ ] Ask Claude to run `list_connections`: exactly the connections your groups grant are listed.
- [ ] Remove yourself from a group in Authentik. Within one access-token lifetime (default 1 hour) the connection
      disappears from `list_connections` without reconnecting.
- [ ] Deactivate a test user in Authentik. Their next refresh fails (`upstream_refresh_failed` in the audit trail)
      and claude.ai asks them to reconnect; reconnecting is refused by Authentik.
- [ ] Audit trail (the image has no `sqlite3` binary, Python's module works):
      `docker exec ratatoskr python -c "import sqlite3; [print(r) for r in sqlite3.connect('/data/state.db').execute(\"SELECT datetime(ts, 'unixepoch'), tool, subject, result FROM audit_events ORDER BY id DESC LIMIT 20\")]"`
      shows `login_succeeded` and tool calls with the expected subject.
- [ ] `server.trusted_proxies` holds the address Caddy connects from (`docker network inspect proxy` shows the
      subnet), so rate limits see real client IPs.
- [ ] Logs (`docker logs ratatoskr`) contain no access token, refresh token, client secret or Authentik code.

## Troubleshooting

Sign-in errors are shown to the user as a short generic page; the reason is in Ratatoskr's log.

| Symptom (Ratatoskr log) | Cause |
|---|---|
| `issuer JWKS contains no usable RSA or EC signing key` (user sees "Sign-in is unavailable") | No signing key selected on the provider: Authentik signs with HS256 and publishes an empty JWKS |
| `ID token signature rejected: …` | Token signed with an algorithm Ratatoskr does not accept, or with a key not in the JWKS |
| `OIDC discovery issuer does not match the configured issuer` | `auth.oidc.issuer` differs from Authentik's issuer (check the trailing slash and slug) |
| `claim 'email' is missing from the identity` | `email` scope not selected, "Include claims in id_token" off, or the user has no e-mail; or set `subject_claim: sub` |
| `OIDC sign-in failed, issuer unavailable: …` (user sees "Sign-in is unavailable"; audit `login_failed`, result `error`, `upstream_unavailable`) | Authentik unreachable or answering 5xx from Ratatoskr's network; not a refused user |
| User sees no connections | `groups` scope missing, "Include claims in id_token" off, or group names differ from the keys under `roles:` |
| Users must sign in every hour | `offline_access` scope missing on the provider |
| "Sign-in could not be verified" page after Authentik | The browser dropped the `__Host-ratatoskr-oidc` flow cookie: start from the same browser, and do not open the callback URL in another profile |
| Everyone is locked out after a few wrong attempts | `server.trusted_proxies` does not contain the proxy's address, so all clients share its IP |
