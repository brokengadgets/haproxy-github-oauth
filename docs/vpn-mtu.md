# Diagnosing & Fixing Docker over OpenVPN MTU Issues

When HAProxy runs on a public cloud edge node and forwards authenticated requests over an OpenVPN tunnel to a remote Docker host, HTTP requests with small payloads (`GET /healthz`, small JSON responses) may succeed while larger responses (HTML bundles, container assets, media streams) stall and time out with `504 Gateway Time-out` or `502 Bad Gateway`.

## Root Cause

1. **OpenVPN Tunnel Overhead:** OpenVPN encapsulates packets inside an outer UDP/TCP datagram, reducing the effective tunnel MTU (typically ~1400–1420 bytes instead of 1500 bytes).
2. **Docker Bridge Default MTU:** By default, Docker's `bridge` network (`docker0` and custom Compose bridges) uses an MTU of **1500 bytes**.
3. **Dropped ICMP Fragmentation Needed:** When a container on the 1500-byte Docker bridge sends a 1500-byte TCP segment with the `DF` (Don't Fragment) bit set back across the 1400-byte OpenVPN `tun0` interface, Path MTU Discovery (PMTUD) relies on ICMP Type 3 Code 4 (`Fragmentation Needed`) packets reaching the container. If iptables/ufw rules or intermediate NAT layers drop those ICMP packets, large TCP segments silently blackhole.

## Quick Diagnosis

Run the diagnostic script from the HAProxy host against the Docker host's VPN IP:

```bash
./scripts/vpn-debug.sh <vpn_peer_ip>
```

The script checks:
- Local `tun0` interface state and configured MTU
- Path MTU via `ping -M do -s <size>` sweeps (`1472`, `1400`, `1350`, `1200`)
- TCP handshake vs. full HTTP response transfer over the tunnel

## Permanent Fixes

### Option 1: TCP MSS Clamping + Docker Daemon MTU (Recommended)

Run the automated remediation script on the Docker host (and/or HAProxy VPN gateway):

```bash
sudo ./scripts/apply-mtu-fix.sh
```

This script:
1. Configures `iptables` `TCPMSS --clamp-mss-to-pmtu` on `FORWARD` traffic entering/leaving `tun+` so TCP handshakes automatically negotiate a segment size that fits inside the tunnel MTU.
2. Sets `"mtu": 1400` in `/etc/docker/daemon.json` so newly created Docker bridge networks match the OpenVPN tunnel MTU.

### Option 2: Per-Compose Network MTU

In `docker/compose.yaml`, the bridge network explicitly sets the MTU to `1400`:

```yaml
networks:
  default:
    driver: bridge
    driver_opts:
      com.docker.network.driver.mtu: "1400"
```
