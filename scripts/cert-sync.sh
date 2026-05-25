#!/usr/bin/env bash
# cert-sync.sh — Sync TLS certificates from Mail-in-a-Box to HAProxy.
#
# USAGE:
#   MIAB_HOST=box.example.com MIAB_USER=admin@example.com MIAB_PASSWORD=secret \
#   DOMAIN=example.com HAPROXY_CERT_DIR=/etc/haproxy/certs ./cert-sync.sh
#
# CRON (run as root, daily at 03:00):
#   0 3 * * * /opt/haproxy-github-oauth/scripts/cert-sync.sh >> /var/log/cert-sync.log 2>&1
#
# MIAB POST-RENEWAL HOOK (on the MIAB box):
#   Add this script's invocation to /usr/local/lib/mailinabox/ssl/renew-certs.sh post-hook,
#   or call it via SSH from MIAB's renewal hook.

set -euo pipefail

: "${MIAB_HOST:?MIAB_HOST is required}"
: "${MIAB_USER:?MIAB_USER is required}"
: "${MIAB_PASSWORD:?MIAB_PASSWORD is required}"
: "${DOMAIN:?DOMAIN is required}"
: "${HAPROXY_CERT_DIR:?HAPROXY_CERT_DIR is required}"

HAPROXY_CFG="${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}"
MIAB_SCHEME="${MIAB_SCHEME:-https}"
CERT_OUT="${HAPROXY_CERT_DIR}/${DOMAIN}.pem"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

log() { echo "[$(date -Iseconds)] $*"; }
die() { log "ERROR: $*" >&2; exit 1; }

# ── Fetch certs from MIAB REST API ───────────────────────────────────────────

log "Fetching certificate list from MIAB at ${MIAB_HOST}"
CERT_LIST=$(curl -fsSL --user "${MIAB_USER}:${MIAB_PASSWORD}" \
  "${MIAB_SCHEME}://${MIAB_HOST}/admin/ssl/certs") || die "Failed to fetch cert list from MIAB"

# MIAB returns JSON array: [{"domain":"...","certificate":"...","private-key":"..."}]
CERT_JSON=$(echo "$CERT_LIST" | python3 -c "
import json, sys
certs = json.load(sys.stdin)
for c in certs:
    if c.get('domain') == '${DOMAIN}':
        print(json.dumps(c))
        break
" 2>/dev/null) || die "Failed to parse MIAB cert list"

[ -n "$CERT_JSON" ] || die "No certificate found for domain ${DOMAIN} in MIAB"

CERT_BODY=$(echo "$CERT_JSON" | python3 -c "import json,sys; c=json.load(sys.stdin); print(c['certificate'])" 2>/dev/null) \
  || die "Could not extract certificate"
KEY_BODY=$(echo "$CERT_JSON"  | python3 -c "import json,sys; c=json.load(sys.stdin); print(c['private-key'])" 2>/dev/null) \
  || die "Could not extract private key"

CERT_TMP="${TMPDIR}/cert.pem"
KEY_TMP="${TMPDIR}/key.pem"
printf '%s\n' "$CERT_BODY" > "$CERT_TMP"
printf '%s\n' "$KEY_BODY"  > "$KEY_TMP"

# ── Verify certificate ────────────────────────────────────────────────────────

log "Verifying certificate for ${DOMAIN}"
openssl x509 -noout -subject -enddate -in "$CERT_TMP" || die "Certificate verification failed"
openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt "$CERT_TMP" 2>/dev/null \
  || log "WARN: openssl verify failed (may be ok for Let's Encrypt chain)"

# ── Check if cert changed ─────────────────────────────────────────────────────

NEW_PEM="${TMPDIR}/combined.pem"
cat "$CERT_TMP" "$KEY_TMP" > "$NEW_PEM"

if [ -f "$CERT_OUT" ]; then
  OLD_SHA=$(sha256sum "$CERT_OUT" | awk '{print $1}')
  NEW_SHA=$(sha256sum "$NEW_PEM"  | awk '{print $1}')
  if [ "$OLD_SHA" = "$NEW_SHA" ]; then
    log "Certificate unchanged, skipping reload"
    exit 0
  fi
fi

# ── Install cert ──────────────────────────────────────────────────────────────

mkdir -p "$HAPROXY_CERT_DIR"
chmod 750 "$HAPROXY_CERT_DIR"

cp "$NEW_PEM" "$CERT_OUT"
chmod 640 "$CERT_OUT"
log "Installed new certificate to ${CERT_OUT}"

# ── Reload HAProxy ────────────────────────────────────────────────────────────

log "Testing HAProxy config"
haproxy -c -f "$HAPROXY_CFG" || die "HAProxy config test failed — NOT reloading"

log "Reloading HAProxy"
systemctl reload haproxy || die "HAProxy reload failed"

log "Done — certificate updated and HAProxy reloaded"
