# haproxy-github-oauth

A lightweight Go service that provides GitHub OAuth authentication for HAProxy,
using GitHub Teams as ACL signals. Runs on the HAProxy host; issues signed JWT
cookies validated by a HAProxy Lua script on every request.

## Architecture

```
Internet
  │
  ▼
HAProxy (port 443, TLS termination)
  │  Lua script validates _auth JWT cookie on every request
  │  Extracts `teams` claim → sets txn.teams variable
  │
  ├── JWT missing/invalid → redirect to /login?rd=<original-url>
  ├── JWT valid, team matches backend ACL → proxy to Docker host (VPN)
  └── JWT valid, team does not match → 403

This service (port 4180, localhost only)
  ├── GET /login        → redirect to GitHub OAuth
  ├── GET /callback     → exchange code, fetch teams, issue JWT, redirect
  ├── GET /auth/verify  → 200 (JSON claims) or 401 (for debugging)
  └── GET /healthz      → 200 {"status":"ok"}
```

## Prerequisites

- Go 1.25+
- A GitHub OAuth App ([create one here](https://github.com/settings/developers))
- HAProxy 2.6+ with Lua support

## GitHub OAuth App Setup

1. Go to **Settings → Developer settings → OAuth Apps → New OAuth App**
2. Set **Homepage URL** to your service base URL, e.g. `https://auth.example.com`
3. Set **Authorization callback URL** to `https://auth.example.com/callback`
4. Copy the **Client ID** and generate a **Client secret**

## Installation

```bash
git clone https://github.com/yourusername/haproxy-github-oauth
cd haproxy-github-oauth
make build
# Binary is at ./bin/haproxy-github-oauth
```

## Configuration

All configuration is via environment variables. Copy `.env.example` and fill in values:

```bash
cp .env.example .env
$EDITOR .env
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITHUB_CLIENT_ID` | yes | — | GitHub OAuth App client ID |
| `GITHUB_CLIENT_SECRET` | yes | — | GitHub OAuth App client secret |
| `GITHUB_ORG` | yes | — | GitHub org slug to check membership in |
| `JWT_SECRET` | yes | — | Min 32-character secret for HMAC-SHA256 |
| `BASE_URL` | yes | — | Public URL of this service, e.g. `https://auth.example.com` |
| `COOKIE_DOMAIN` | yes | — | Cookie domain, e.g. `.example.com` |
| `LISTEN_ADDR` | no | `:4180` | Listen address |
| `SESSION_DURATION` | no | `8h` | JWT session lifetime |
| `ALLOWED_TEAMS` | no | _(any org member)_ | Comma-separated `org/team-slug` allow list |

Generate a JWT secret:

```bash
openssl rand -hex 32
```

## Running

```bash
source .env
./bin/haproxy-github-oauth
# or with Docker:
docker compose -f docker/compose.yaml up -d
```

As a systemd service:

```bash
sudo cp docker/d-haproxy-oauth.service /etc/systemd/system/
sudo systemctl enable --now d-haproxy-oauth
```

## HAProxy Configuration

See `haproxy/haproxy.cfg.example` for a complete annotated example. Key steps:

**1. Install the Lua script:**

```bash
cp haproxy/lua/jwt_auth.lua /etc/haproxy/lua/
```

**2. Load the Lua script in `haproxy.cfg`:**

```haproxy
global
    lua-load /etc/haproxy/lua/jwt_auth.lua
```

**3. Wire authentication in your frontend:**

```haproxy
frontend https_in
    bind *:443 ssl crt /etc/haproxy/certs/combined.pem
    http-request lua.check_jwt
    acl has_jwt var(txn.jwt_valid) -m bool
    http-request redirect location /login?rd=%[capture.req.hdr(0)] if !has_jwt
```

**4. Enforce team ACLs per backend:**

```haproxy
backend myapp
    acl allowed_team var(txn.teams) -m sub myorg/backend
    http-request deny status 403 if !allowed_team
    server dockerhost 10.8.0.2:8080 check
```

The Lua script sets `txn.teams` to the comma-separated team list from the JWT
(e.g. `myorg/backend,myorg/staff`). The `-m sub` ACL matches any substring, so
a user in multiple teams passes if any of their teams matches.

## TLS Certificate Sync (Mail-in-a-Box)

`scripts/cert-sync.sh` downloads TLS certificates from a MIAB instance and
reloads HAProxy. Requires `openssl` and `curl`.

**Environment variables:**

| Variable | Description |
|---|---|
| `MIAB_HOST` | MIAB hostname, e.g. `box.example.com` |
| `MIAB_USER` | MIAB admin email |
| `MIAB_PASSWORD` | MIAB admin password |
| `DOMAIN` | Domain to sync cert for |
| `HAPROXY_CERT_DIR` | Directory to write combined PEM, e.g. `/etc/haproxy/certs` |

**Cron setup (run as root):**

```cron
0 3 * * * /opt/haproxy-github-oauth/scripts/cert-sync.sh >> /var/log/cert-sync.log 2>&1
```

**MIAB post-renewal hook:** add the script invocation (via SSH or shared mount)
to `/usr/local/lib/mailinabox/ssl/renew-certs.sh` on the MIAB box, or call it
remotely from MIAB's renewal hook.

The script is idempotent: it compares SHA256 of the existing and new combined
PEM and skips the reload if unchanged.

## VPN / MTU

If Docker services are accessible on LAN but time out over OpenVPN, see
[docs/vpn-mtu.md](docs/vpn-mtu.md) for diagnosis and fix options.

Quick diagnosis:

```bash
./scripts/vpn-debug.sh <vpn_peer_ip>
```

Quick fix (Docker-wide):

```bash
sudo ./scripts/apply-mtu-fix.sh
```

## Development

```bash
# Run all quality gates
make check

# Unit tests only
make test

# Lint only
make lint

# Integration tests (starts a mock GitHub server, exercises full OAuth flow)
make integration-test

# Lua tests
make lua-test

# Build Docker image
make docker-build
```

### Adding a backend

1. Issue or note the team slug: `myorg/myteam`
2. Add an HAProxy backend with the team ACL (see HAProxy config section above)
3. If using `ALLOWED_TEAMS`, add `myorg/myteam` to that env var

## Security Notes

- The JWT secret (`JWT_SECRET`) must be at least 32 characters. Generate with
  `openssl rand -hex 32`.
- The `_auth` cookie is `HttpOnly`, `Secure`, and `SameSite=Lax`.
- The `rd` redirect parameter in `/callback` is validated against `BASE_URL` to
  prevent open-redirect attacks.
- CSRF is protected by a signed `oauth_state` cookie (HMAC-SHA256 of the state
  token using `JWT_SECRET`).
