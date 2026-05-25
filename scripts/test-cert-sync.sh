#!/usr/bin/env bash
# test-cert-sync.sh — Integration test harness for cert-sync.sh.
#
# Starts a minimal mock MIAB API server using Python's http.server,
# then runs cert-sync.sh against it and validates:
#   1. Cert installed to HAPROXY_CERT_DIR/DOMAIN.pem
#   2. Idempotent re-run skips reload (SHA256 unchanged)
#   3. Changed cert triggers install + reload

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_SYNC="${SCRIPT_DIR}/cert-sync.sh"
TMPDIR_ROOT="$(mktemp -d)"
MOCK_PORT=18443
MOCK_PID=""

cleanup() {
  [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
  rm -rf "$TMPDIR_ROOT"
}
trap cleanup EXIT

pass() { echo "  [PASS] $*"; }
fail() { echo "  [FAIL] $*" >&2; exit 1; }

# ── Generate a self-signed test cert + key ────────────────────────────────────

CERT_DIR="${TMPDIR_ROOT}/certs"
mkdir -p "$CERT_DIR"
openssl req -x509 -newkey rsa:2048 -keyout "${CERT_DIR}/key.pem" \
  -out "${CERT_DIR}/cert.pem" -days 1 -nodes \
  -subj "/CN=test.example.com" 2>/dev/null
# ── Start mock MIAB server ────────────────────────────────────────────────────

MOCK_RESPONSE_FILE="${TMPDIR_ROOT}/response.json"
python3 - "$MOCK_PORT" "$MOCK_RESPONSE_FILE" <<'PYEOF' &
import sys, json, http.server, base64

port = int(sys.argv[1])
response_file = sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args): pass  # silence access log

    def do_GET(self):
        if self.path != "/admin/ssl/certs":
            self.send_error(404)
            return
        # Basic-auth is not enforced in the mock — just return the payload.
        try:
            with open(response_file) as f:
                body = f.read().encode()
        except FileNotFoundError:
            self.send_error(503, "response not ready")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
PYEOF
MOCK_PID=$!

# Wait for mock server to start
for _ in $(seq 1 20); do
  curl -s "http://127.0.0.1:${MOCK_PORT}/admin/ssl/certs" >/dev/null 2>&1 && break
  sleep 0.1
done

# ── Shared env for cert-sync.sh ───────────────────────────────────────────────

HAPROXY_OUT_DIR="${TMPDIR_ROOT}/haproxy-certs"
mkdir -p "$HAPROXY_OUT_DIR"
EXPECTED_PEM="${HAPROXY_OUT_DIR}/test.example.com.pem"

export MIAB_HOST="127.0.0.1:${MOCK_PORT}"
export MIAB_SCHEME="http"
export MIAB_USER="admin@example.com"
export MIAB_PASSWORD="secret"
export DOMAIN="test.example.com"
export HAPROXY_CERT_DIR="$HAPROXY_OUT_DIR"
# Override HAProxy commands — not a real HAProxy host in this test.
export HAPROXY_CFG="/dev/null"

# Stub out haproxy and systemctl so the test doesn't need them installed.
STUB_BIN="${TMPDIR_ROOT}/stub-bin"
mkdir -p "$STUB_BIN"
printf '#!/bin/sh\necho "[STUB] haproxy $*"\nexit 0\n' > "${STUB_BIN}/haproxy"
printf '#!/bin/sh\necho "[STUB] systemctl $*"\nexit 0\n' > "${STUB_BIN}/systemctl"
chmod +x "${STUB_BIN}/haproxy" "${STUB_BIN}/systemctl"
export PATH="${STUB_BIN}:${PATH}"

# ── Test 1: fresh install ─────────────────────────────────────────────────────

echo ""
echo "Test 1: fresh cert install"

python3 -c "
import json
print(json.dumps([{'domain':'test.example.com','certificate':open('${CERT_DIR}/cert.pem').read(),'private-key':open('${CERT_DIR}/key.pem').read()}]))
" > "$MOCK_RESPONSE_FILE"

"$CERT_SYNC" 2>&1 | grep -v "^\[" || true

[ -f "$EXPECTED_PEM" ] || fail "Expected PEM not installed at ${EXPECTED_PEM}"
pass "PEM installed at ${EXPECTED_PEM}"

# ── Test 2: idempotent re-run ─────────────────────────────────────────────────

echo ""
echo "Test 2: idempotent re-run (cert unchanged)"

OUTPUT="$("$CERT_SYNC" 2>&1)"
echo "$OUTPUT" | grep -q "unchanged" || fail "Expected 'unchanged' message on re-run"
pass "Idempotent skip confirmed"

# ── Test 3: changed cert triggers reinstall ───────────────────────────────────

echo ""
echo "Test 3: changed cert triggers reinstall"

# Generate a new cert
openssl req -x509 -newkey rsa:2048 -keyout "${CERT_DIR}/key2.pem" \
  -out "${CERT_DIR}/cert2.pem" -days 1 -nodes \
  -subj "/CN=test.example.com" 2>/dev/null

python3 -c "
import json
print(json.dumps([{'domain':'test.example.com','certificate':open('${CERT_DIR}/cert2.pem').read(),'private-key':open('${CERT_DIR}/key2.pem').read()}]))
" > "$MOCK_RESPONSE_FILE"

OUTPUT="$("$CERT_SYNC" 2>&1)"
echo "$OUTPUT" | grep -q "Installed new certificate" || fail "Expected 'Installed new certificate' message"
pass "New cert installed on change"

echo ""
echo "All cert-sync tests passed."
