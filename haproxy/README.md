# HAProxy Integration

## Requirements

- HAProxy 2.6 or later
- Lua 5.3+ with `cjson` module (usually bundled with HAProxy)
- OpenSSL Lua bindings or HAProxy's built-in `core.openssl` (HAProxy 2.7+)

## Installation

### 1. Install the Lua script

```bash
sudo mkdir -p /etc/haproxy/lua
sudo cp haproxy/lua/jwt_auth.lua /etc/haproxy/lua/jwt_auth.lua
```

### 2. Install the HAProxy config

`haproxy/haproxy.cfg` is not tracked in version control (it contains real IPs,
hostnames, and org names). Use the example as your starting point:

```bash
cp haproxy/haproxy.cfg.example haproxy/haproxy.cfg
# Edit all PLACEHOLDER_ values, then deploy:
sudo cp haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg
sudo nano /etc/haproxy/haproxy.cfg
```

### 3. Set JWT_SECRET in HAProxy's environment

The Lua script reads `JWT_SECRET` from the environment. The cleanest way is via
the systemd unit's `EnvironmentFile`:

```ini
# /etc/systemd/system/haproxy.service.d/override.conf
[Service]
EnvironmentFile=/etc/haproxy/haproxy.env
```

```bash
# /etc/haproxy/haproxy.env
JWT_SECRET=the-same-secret-as-in-oauth-app-dot-env
```

```bash
sudo chmod 600 /etc/haproxy/haproxy.env
sudo systemctl daemon-reload
```

### 4. Install TLS certificates

```bash
# Set env vars then run cert-sync
sudo MIAB_HOST=box.yourdomain.tld \
     MIAB_USER=admin@yourdomain.tld \
     MIAB_PASSWORD=yourpassword \
     DOMAIN=yourdomain.tld \
     HAPROXY_CERT_DIR=/etc/haproxy/certs \
     bash scripts/cert-sync.sh
```

### 5. Test and reload

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl reload haproxy
```

## Cert Sync Cron

Add to `/etc/cron.d/cert-sync`:

```cron
0 3 * * * root MIAB_HOST=box.yourdomain.tld MIAB_USER=admin@yourdomain.tld MIAB_PASSWORD=secret DOMAIN=yourdomain.tld HAPROXY_CERT_DIR=/etc/haproxy/certs /opt/haproxy-github-oauth/scripts/cert-sync.sh >> /var/log/cert-sync.log 2>&1
```

## Team ACL Reference

In `haproxy.cfg`, backend ACLs use:

```haproxy
acl allowed var(txn.teams) -m sub ORGNAME/TEAMSLUG
http-request deny status 403 if !allowed
```

`txn.teams` is a comma-separated string of `org/team-slug` values set by the Lua script.
The `-m sub` matcher checks if the substring appears anywhere in the string.

Multiple teams (OR logic):
```haproxy
acl team_a var(txn.teams) -m sub myorg/team-a
acl team_b var(txn.teams) -m sub myorg/team-b
acl allowed_teams team_a or team_b
http-request deny status 403 if !allowed_teams
```

## Troubleshooting

**"Bad gateway" errors from Docker services over VPN:**
Run `scripts/vpn-debug.sh <vpn_peer_ip>` — almost certainly an MTU mismatch.

**403 on every request despite correct GitHub team:**
1. Check that `JWT_SECRET` in HAProxy env matches the OAuth app's `JWT_SECRET`
2. Check that `_auth` cookie domain matches `COOKIE_DOMAIN` in the OAuth app
3. Test the JWT directly: `GET /auth/verify` on the OAuth app should return your teams

**HAProxy Lua errors in log:**
```bash
journalctl -u haproxy -f | grep -i lua
```
