#!/usr/bin/env bash
# vpn-debug.sh — Diagnose OpenVPN + Docker MTU mismatches causing service timeouts.
#
# USAGE (run on the Docker host):
#   ./vpn-debug.sh [VPN_PEER_IP]
#
# The most common cause of Docker services timing out over OpenVPN but not on LAN:
#   Docker bridge MTU = 1500, OpenVPN effective MTU ≈ 1400-1450.
#   Large TCP segments (HTTP responses, file transfers) are fragmented or
#   silently dropped because ICMP fragmentation-needed messages don't get through.
#
# FIX (choose one):
#   A) Set Docker daemon MTU globally:  /etc/docker/daemon.json → "mtu": 1400
#   B) Set per-compose network:        driver_opts: {com.docker.network.driver.mtu: "1400"}
#   C) Set on OpenVPN server:          push "mssfix 1400" + push "tun-mtu 1400"

set -uo pipefail

VPN_PEER="${1:-}"
SIZES="1500 1450 1400 1350 1300"

log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*" >&2; }
ok()   { echo "[OK]    $*"; }
bad()  { echo "[FAIL]  $*" >&2; }

echo "═══════════════════════════════════════════════════"
echo " haproxy-github-oauth VPN/MTU Diagnostics"
echo "═══════════════════════════════════════════════════"
echo ""

# ── 1. Network interface MTUs ─────────────────────────────────────────────────

log "Network interface MTUs:"
ip link show | awk '/^[0-9]+:/ {iface=$2} /mtu/ {match($0, /mtu ([0-9]+)/, m); printf "  %-20s MTU=%s\n", iface, m[1]}'
echo ""

# ── 2. Docker daemon MTU ──────────────────────────────────────────────────────

log "Docker daemon MTU configuration:"
if command -v docker >/dev/null 2>&1; then
  DOCKER_MTU=$(docker info 2>/dev/null | grep -i "mtu\|network" | head -5 || true)
  if [ -n "$DOCKER_MTU" ]; then
    awk '{print "  " $0}' <<< "$DOCKER_MTU"
  fi
  if [ -f /etc/docker/daemon.json ]; then
    log "/etc/docker/daemon.json:"
    cat /etc/docker/daemon.json | sed 's/^/  /'
    MTU_SET=$(python3 -c "import json; d=json.load(open('/etc/docker/daemon.json')); print(d.get('mtu','NOT SET'))" 2>/dev/null || echo "NOT SET")
    if [ "$MTU_SET" = "NOT SET" ] || [ "$MTU_SET" = "1500" ]; then
      warn "Docker daemon MTU is not set (defaults to 1500) — likely cause of VPN timeouts"
    else
      ok "Docker daemon MTU = ${MTU_SET}"
    fi
  else
    warn "/etc/docker/daemon.json not found — Docker using default MTU 1500"
  fi
else
  warn "docker not found"
fi
echo ""

# ── 3. OpenVPN interface ──────────────────────────────────────────────────────

log "OpenVPN TUN/TAP interfaces:"
ip link show | grep -E "^[0-9]+:.*tun|^[0-9]+:.*tap" | sed 's/^/  /' || echo "  (none found)"
echo ""

# ── 4. Ping test with DF bit set ─────────────────────────────────────────────

if [ -n "$VPN_PEER" ]; then
  log "Path MTU discovery to VPN peer ${VPN_PEER}:"
  echo "  (Using ping -M do -s SIZE — these probe actual path MTU)"
  for size in $SIZES; do
    # ping payload = size; actual IP packet = size + 28 bytes (IP+ICMP headers)
    result=$(ping -M "do" -s "$size" -c 1 -W 2 "$VPN_PEER" 2>&1 || true)
    if echo "$result" | grep -q "1 received\|1 packets received"; then
      ok "  size ${size}: reachable"
    elif echo "$result" | grep -q "Frag needed\|Message too long\|mtu"; then
      warn "  size ${size}: fragmentation needed (MTU limit here)"
      break
    else
      bad "  size ${size}: packet lost or host unreachable"
      break
    fi
  done
  echo ""

  # ── 5. TCP port tests to Docker services via VPN ─────────────────────────

  log "TCP connectivity tests to Docker host (${VPN_PEER}) via VPN:"
  PORTS="3000:Gitea 5006:Actual 8080:Pihole 8096:Jellyfin 8112:Deluge 8443:Nextcloud 11434:Ollama"
  for entry in $PORTS; do
    port="${entry%%:*}"
    name="${entry##*:}"
    if timeout 3 bash -c ">/dev/tcp/${VPN_PEER}/${port}" 2>/dev/null; then
      ok "  ${name} (port ${port}): reachable"
    else
      bad "  ${name} (port ${port}): connection refused or timed out"
    fi
  done
  echo ""
else
  warn "No VPN_PEER_IP provided — skipping ping/port tests"
  warn "Rerun as: $0 <vpn_peer_ip>"
  echo ""
fi

# ── 6. Recommendations ───────────────────────────────────────────────────────

echo "═══════════════════════════════════════════════════"
echo " Recommendations"
echo "═══════════════════════════════════════════════════"
echo ""
echo "If services time out over VPN but work on LAN, apply MTU fix:"
echo ""
echo "  Option A — Docker-wide (recommended, requires daemon restart):"
echo "    sudo python3 -c \\"
echo "      \"import json; d=json.load(open('/etc/docker/daemon.json')) if open('/etc/docker/daemon.json') else {}; d['mtu']=1400; open('/etc/docker/daemon.json','w').write(json.dumps(d,indent=2))\""
echo "    sudo systemctl restart docker"
echo "    # Then restart all docker-compose stacks"
echo ""
echo "  Option B — Per-compose-network (no daemon restart, edit each compose.yaml):"
echo "    networks:"
echo "      default:"
echo "        driver_opts:"
echo "          com.docker.network.driver.mtu: \"1400\""
echo ""
echo "  Option C — OpenVPN server config (add to server.conf):"
echo "    push \"mssfix 1400\""
echo "    push \"tun-mtu 1400\""
echo "    (requires OpenVPN server restart + client reconnect)"
echo ""
echo "After applying fix, rerun this script to verify."
