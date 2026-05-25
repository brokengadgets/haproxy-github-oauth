#!/usr/bin/env bash
# apply-mtu-fix.sh — Apply the MTU fix for Docker services running over OpenVPN.
#
# Run on the Docker host (NOT the HAProxy host).
#
# USAGE:
#   # Global daemon fix (recommended):
#   sudo ./apply-mtu-fix.sh
#
#   # Print per-compose instructions only (no changes made):
#   ./apply-mtu-fix.sh --print-only

set -euo pipefail

TARGET_MTU=1400
DAEMON_JSON="/etc/docker/daemon.json"
BACKUP_SUFFIX=".bak.$(date +%Y%m%d-%H%M%S)"
PRINT_ONLY=false

if [ "${1:-}" = "--print-only" ]; then
  PRINT_ONLY=true
fi

log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*" >&2; }

# ── Print per-compose instructions ───────────────────────────────────────────

echo ""
echo "Option B — Per-compose-network (no daemon restart needed):"
echo "  Add to each affected compose.yaml:"
echo ""
echo "    networks:"
echo "      default:"
echo "        driver_opts:"
echo "          com.docker.network.driver.mtu: \"${TARGET_MTU}\""
echo ""
echo "  Then restart the affected stacks:"
echo "    docker compose down && docker compose up -d"
echo ""

if [ "$PRINT_ONLY" = "true" ]; then
  log "Printed per-compose instructions. Exiting (--print-only)."
  exit 0
fi

# ── Require root ─────────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: This script must be run as root to modify ${DAEMON_JSON}" >&2
  echo "       Run: sudo $0" >&2
  exit 1
fi

# ── Check current Docker daemon MTU ──────────────────────────────────────────

CURRENT_MTU="unset"
if [ -f "$DAEMON_JSON" ]; then
  CURRENT_MTU=$(python3 -c \
    "import json; d=json.load(open('${DAEMON_JSON}')); print(d.get('mtu','unset'))" 2>/dev/null \
    || echo "unset")
fi

if [ "$CURRENT_MTU" = "$TARGET_MTU" ]; then
  log "Docker daemon MTU is already set to ${TARGET_MTU}. Nothing to do."
  exit 0
fi

log "Current Docker daemon MTU: ${CURRENT_MTU}"
log "Target MTU: ${TARGET_MTU}"
echo ""
echo "This will:"
echo "  1. Back up ${DAEMON_JSON} to ${DAEMON_JSON}${BACKUP_SUFFIX}"
echo "  2. Set \"mtu\": ${TARGET_MTU} in ${DAEMON_JSON}"
echo "  3. Restart the Docker daemon (all containers will be briefly unavailable)"
echo ""
read -r -p "Proceed? [y/N] " answer
case "$answer" in
  [yY][eE][sS]|[yY]) ;;
  *)
    echo "Aborted."
    exit 0
    ;;
esac

# ── Back up daemon.json ───────────────────────────────────────────────────────

if [ -f "$DAEMON_JSON" ]; then
  cp "$DAEMON_JSON" "${DAEMON_JSON}${BACKUP_SUFFIX}"
  log "Backed up ${DAEMON_JSON} → ${DAEMON_JSON}${BACKUP_SUFFIX}"
fi

# ── Apply MTU setting ─────────────────────────────────────────────────────────

python3 - <<PYEOF
import json, os

path = "${DAEMON_JSON}"
try:
    with open(path) as f:
        cfg = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    cfg = {}

cfg["mtu"] = ${TARGET_MTU}

os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
with open(path, "w") as f:
    json.dump(cfg, f, indent=2)
    f.write("\n")
print(f"Updated {path}")
PYEOF

log "Restarting Docker daemon..."
systemctl restart docker

log "Done. Docker daemon MTU is now ${TARGET_MTU}."
log ""
log "Existing containers use the old network MTU until recreated. Restart affected stacks:"
log "  docker compose down && docker compose up -d"
