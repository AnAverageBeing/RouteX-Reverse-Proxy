# RouteX — Fast Reverse Proxy

<div align="center">

![RouteX](https://img.shields.io/badge/RouteX-Reverse%20Proxy-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Tests](https://img.shields.io/badge/tests-69%20passing-brightgreen?style=flat-square)

**Production-grade L3/L4/L7 reverse proxy in Go.**
Purpose-built for game server infrastructure — DDoS protection, protocol validation, bandwidth quotas, and a full REST API.

[Documentation](https://anaveragebeing.github.io/pingless-studios-docs/routex/) · [Issues](https://github.com/AnAverageBeing/RouteX-Reverse-Proxy/issues)

</div>

---

## Table of Contents

- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Global Configuration](#global-configuration)
- [Per-Proxy Configuration](#per-proxy-configuration)
- [Core Routing](#core-routing)
- [Port Mapping](#port-mapping)
- [Load Balancing](#load-balancing)
- [Health Checks](#health-checks)
- [iptables Rate Limiting](#iptables-rate-limiting)
- [L7 Protection Engine](#l7-protection-engine)
- [ACL System](#acl-system)
- [Bandwidth Management](#bandwidth-management)
- [Metrics & Monitoring](#metrics--monitoring)
- [REST API](#rest-api)
- [Connection Draining](#connection-draining)
- [Access Logging](#access-logging)
- [Timezone](#timezone)
- [TLS Passthrough](#tls-passthrough)
- [Hot Reload](#hot-reload)
- [Installation](#installation)
- [Testing](#testing)
- [Project Structure](#project-structure)

---

## Quick Start

```bash
git clone https://github.com/AnAverageBeing/RouteX-Reverse-Proxy.git
cd RouteX-Reverse-Proxy
make build
make run
```

Verify:
```bash
curl http://localhost:9000/api/health
curl -H "X-API-Key: pk_admin_xxxxxxxxxxxx" http://localhost:9000/api/proxies
```

---

## Architecture

```
Clients ──► RouteX Listeners ──► Load Balancer ──► Upstream Servers
                │                      │
          ┌─────┴──────┐        ┌──────┴──────┐
          │ iptables    │        │ Health Check │
          │ Rate Limits │        │ (active TCP) │
          └─────────────┘        └──────────────┘
                │
          ┌─────┴──────┐        ┌──────────────┐
          │ ACL Engine  │        │ Connection   │
          │ (global+px) │        │ Tracker      │
          └─────────────┘        └──────────────┘
                │
          ┌─────┴──────┐        ┌──────────────┐
          │ L7 Engine   │        │ Bandwidth    │
          │ (in-process)│        │ Manager      │
          └─────────────┘        └──────────────┘
                │
          ┌─────┴──────┐
          │ REST API    │
          │ + Metrics   │
          └─────────────┘
```

**Defense layers in order**: Global ACL → Per-Proxy ACL → iptables Rate Limits → L7 Engine → Bandwidth Quota

Every layer is optional and independently configurable. Disable what you don't need.

---

## Global Configuration

`configs/global.yaml` — applies to ALL proxy instances.

```yaml
api:
  enabled: true
  bind: "0.0.0.0:9000"         # REST API listen address
  api_keys:                     # Auth credentials with scoped permissions
    - key: "your-secret-key"
      label: "admin"
      permissions: ["*"]        # Wildcard = full access
    - key: "readonly-key"
      label: "grafana"
      permissions: ["metrics:read", "proxies:read"]
  tls:
    enabled: false              # Enable HTTPS on the API server
    cert: "/path/to/cert.pem"
    key: "/path/to/key.pem"

timezone: "UTC"                 # Used for bandwidth quota resets. Change to your local TZ.
                                # Examples: "America/New_York", "Europe/London", "Asia/Tokyo"

metrics:
  enabled: true
  retention_hours: 168          # Keep data for 7 days
  flush_interval_seconds: 10    # Write in-memory counters to SQLite every 10s
  sqlite_path: "./routex_metrics.db"
  formats: ["json", "prometheus", "influx", "csv"]  # All 4 available at /metrics?format=X

network:
  socket_buffer_size: 65536     # SO_RCVBUF per listening socket
  tcp_keepalive_enabled: true   # TCP keepalive probes
  tcp_keepalive_interval: 30   # Keepalive interval in seconds
  tcp_nodelay: true             # Disable Nagle's algorithm (lower latency, higher throughput)
  udp_read_buffer: 4194304      # 4 MB receive buffer for UDP sockets
  udp_write_buffer: 4194304     # 4 MB send buffer for UDP sockets

defaults:                       # Global overridable per-proxy via `timeouts:` and `health_check:`
  upstream_connect_timeout: 5s  # Max time to dial an upstream
  upstream_read_timeout: 30s    # Read deadline on upstream connection
  upstream_write_timeout: 30s   # Write deadline on upstream connection
  client_read_timeout: 30s     # Read deadline on client connection
  client_write_timeout: 30s    # Write deadline on client connection
  health_check_interval: 10s   # How often to probe upstreams
  health_check_timeout: 3s     # Probe dial timeout
  health_check_failures_before_eject: 3   # Consecutive failures → mark unhealthy
  health_check_passes_before_readmit: 2   # Consecutive successes → mark healthy
  udp_session_timeout: 60s     # Idle UDP session before cleanup

iptables:
  enabled: true
  chain_prefix: "ROUTEX"        # All iptables chains use this prefix
  comment_prefix: "RouteX"      # Rule comments: "RouteX-Rate-Limit-25565"
  auto_create_chains: true
  flush_on_start: false         # If true, wipes all RouteX rules on startup
  ipv6_enabled: false           # Also manage ip6tables

acl:
  enabled: false                # Global ACL — checked before per-proxy ACLs
  default_action: "allow"       # What happens when no rule matches
  rules:
    - action: "deny"
      cidr: "192.168.0.0/16"
      comment: "block entire private LAN"

logging:
  level: "info"                 # debug | info | warn | error
  format: "json"                # json (structured) | text (console)
  output: "stdout"              # stdout | file
  file_path: "./routex.log"
  max_size_mb: 100
  max_backups: 5
```

---

## Per-Proxy Configuration

Each `.yaml` file in `configs/proxies/` is a **fully isolated** proxy instance. One config failing never affects others. Every field below is explained with *when* and *why* you'd use it.

### Full Reference with Explanations

```yaml
# ── IDENTITY ──────────────────────────────────────────────────────────
name: "minecraft-main"          # Unique ID. Appears in logs, metrics, and API responses.
enabled: true                   # false = skip on startup (can be toggled via API)
description: "Minecraft Java proxy"  # Human-readable, shown in API responses
metadata:                       # Tags for dashboard filtering and ownership tracking
  tags: ["game", "minecraft", "production"]
  owner: "infra-team"

# ── ORIGIN (where clients connect) ────────────────────────────────────
origin-ip: "0.0.0.0"           # Listen address. "0.0.0.0" = all interfaces.
                                # Use specific IPs to bind to one NIC: "192.168.1.10"
                                # Multiple IPs: "192.168.1.10, 10.0.0.5"
origin-port: "25565:25575"     # Single port: "25565"  /  Range: "25565:25575"
                                # Each port in the range gets its own listener

# ── DESTINATION (where traffic goes) ──────────────────────────────────
dest-ip: "10.0.0.1, 10.0.0.2"  # Comma-separated upstream IPs
dest-port: "35565:35575"       # Single port or range

# ── PROTOCOL ──────────────────────────────────────────────────────────
protocol: "tcp-udp"             # tcp = TCP only | udp = UDP only | tcp-udp = both
                                # When tcp-udp: creates TCP + UDP listeners on every port
```

### Core Routing Explained

**origin-ip / dest-ip**: Comma-separated IPs create **multiple listeners** or **multiple upstream targets**. Each origin IP × origin port combination gets its own listener. Each dest IP × dest port combination becomes a load balancer target.

**origin-port / dest-port**: Single ports (`25565`) or ranges (`25565:25575`). Ranges must be `low:high` with `low < high`. Each port in the range gets its own listener.

**UDP Session Model**: Each client (src IP:port) gets a persistent upstream session. All datagrams from that client go to the same upstream for the session lifetime. Sessions expire after `udp_session_timeout` of inactivity.

---

### Port Mapping

Controls how origin ports map to destination ports.

| Mode | Config | Behavior | Use Case |
|------|--------|----------|----------|
| **One-to-One** | `one-to-one: true` | Origin port N maps to dest port N (positional pairing). Ranges must be equal size. | Fixed port translation (public 25565 → internal 35565) |
| **Fan-Out** | `one-to-one: false` | Any origin port connects to any dest port. Load balancer picks per connection. | Multiple origins feeding into a single upstream port pool |

```yaml
# One-to-One example: public ports map 1:1 to internal ports
one-to-one: true
origin-port: "25565:25567"   # 3 ports: [25565, 25566, 25567]
dest-port: "35565:35567"     # 3 ports: [35565, 35566, 35567]
# Result: 25565→35565, 25566→35566, 25567→35567

# Fan-Out example: all origin ports share the same upstream pool
one-to-one: false
origin-port: "25565:25567"   # 3 ports
dest-port: "35565:35567"     # 3 ports (can be any size)
# Result: any origin port → any dest port (6 possible target combinations)
```

---

### Load Balancing

5 algorithms — all goroutine-safe, health-aware, and tested for fairness.

| Algorithm | How It Works | Best For |
|-----------|-------------|----------|
| `round-robin` | Rotates through targets in order, skipping unhealthy | Simple, predictable distribution |
| `least-conn` | Picks target with fewest active connections | Long-lived connections (game servers) |
| `ip-hash` | FNV-32 hash of client IP → stable target | Session affinity without sticky overhead |
| `weighted` | Random weighted by configured weight values | Heterogeneous backends (beefy vs small) |
| `random` | Uniform random among healthy targets | Basic load spreading |

```yaml
load_balancing:
  algorithm: "least-conn"
  sticky_sessions: false       # Source-IP session affinity with TTL
  sticky_ttl: 3600             # How long to remember the mapping (seconds)
  upstream_weights:            # Only used with "weighted" algorithm
    "10.0.0.1": 3              # This upstream gets 3x traffic vs weight 1
    "10.0.0.2": 1
  health_check:                # Override global health check defaults
    interval: 10s
    timeout: 3s
    failures_before_eject: 3   # 3 consecutive fails → mark unhealthy
    passes_before_readmit: 2   # 2 consecutive passes → mark healthy again
```

**Sticky sessions**: When enabled, the first connection from an IP picks normally. All subsequent connections from that IP within `sticky_ttl` seconds go to the **same** upstream. Mapping is in-memory, not persisted.

**Weighted distribution**: Verified at 10:1 ratio — heavy target gets ~91% of traffic (1,100-sample test).

**Health-aware picking**: Unhealthy targets are skipped. When all targets are unhealthy, connections are rejected with `ErrNoHealthyTargets`.

---

### Health Checks

Active TCP probes run per upstream target. Each target gets its own probe goroutine with staggered start to avoid thundering-herd dial storms.

- **Probe**: TCP dial to `upstream_ip:port` with configured timeout
- **Eject**: After N consecutive failures (`failures_before_eject`), target marked unhealthy
- **Readmit**: After N consecutive successes (`passes_before_readmit`), target marked healthy
- **Initial state**: All targets start healthy (optimistic) — first probe determines actual state

---

### Timeouts

Override global defaults per-proxy. Every field uses Go's duration format (`5s`, `1m`, `1h30m`). Zero values inherit the global default.

```yaml
timeouts:
  upstream_connect: 5s         # Max time to establish TCP to upstream
  upstream_read: 30s           # Read timeout on upstream (0 = no timeout)
  upstream_write: 30s          # Write timeout on upstream
  client_read: 30s             # Read timeout on client side
  client_write: 30s            # Write timeout on client side
  udp_session_timeout: 60s     # Idle UDP session expiry
```

---

### Connection Draining

On reload or stop: existing connections continue until they naturally close or the drain timeout hits — whichever comes first. New connections are rejected immediately (listener closes).

```yaml
connection_draining:
  enabled: true
  timeout: 30s                 # Max wait for active connections to finish
```

**How it works**: A `Drainer` tracks active copy goroutines via `sync.WaitGroup`. On stop, it waits up to `timeout` for all goroutines to call `Done()`. If timeout elapses, remaining connections are abandoned and logged.

---

### Access Logging

Log every connection accept and close with structured metadata. Useful for audit trails and debugging.

```yaml
logging:
  level: "debug"               # Override global log level for this proxy
  log_connections: true        # Log: "connection accepted", "connection denied by ACL", "connection closed"
  log_bytes: false             # Log per-connection byte counts (noisy — only for debugging)
```

**Connection closed log includes**: source IP, bytes in, bytes out, duration.

---

### TLS Passthrough

RouteX does NOT terminate TLS. It forwards raw encrypted bytes to the upstream. The upstream handles decryption.

```yaml
tls:
  passthrough: true            # Forward TLS without inspection
  sni_routing: false           # Route by SNI hostname (planned, not yet implemented)
```

---

---

### iptables Rate Limiting

Kernel-level rate limiting applied BEFORE traffic reaches the Go proxy. Rules are created with `RouteX-*` comments for lifecycle management. Each rule type is explained below.

```yaml
rate_limits:
  # ── Packet Rate Limiting ────────────────────────────────────────
  tcp_pps_per_ip: 500           # Max TCP packets/sec per source IP. 0 = disabled.
                                # USE WHEN: volumetric TCP flood (bots send valid packets at high rate)
  udp_pps_per_ip: 1000          # Max UDP packets/sec per source IP.
                                # USE WHEN: UDP amplification or flood attacks

  # ── Connection Rate Limiting ─────────────────────────────────────
  new_conns_per_sec_per_ip: 20  # Max new TCP connections/sec per source IP.
                                # USE WHEN: SYN flood or connection exhaustion from single IP
  new_conns_per_sec_global: 500 # Max new TCP connections/sec across ALL IPs.
                                # USE WHEN: distributed connection flooding (many IPs, few conns each)
  tcp_syn_rate_per_ip: 10      # Max SYN packets/sec per source IP (stricter than conns).
                                # USE WHEN: pure SYN flood (no full handshake completion)

  # ── Connection Limits ────────────────────────────────────────────
  max_simultaneous_conns_per_ip: 10  # Max concurrent connections from one source IP.
                                      # USE WHEN: single IP hogging all backend slots
  max_total_conns: 500              # Max concurrent connections across ALL IPs.
                                    # USE WHEN: overall backend capacity limits

  # ── Packet Filtering ─────────────────────────────────────────────
  drop_fragmented_packets: true     # Drop all fragmented IP packets.
                                    # USE WHEN: teardrop/fragmentation attacks
  tcp_invalid_state_drop: true      # Drop TCP packets not matching valid state.
                                    # USE WHEN: blind spoofed attacks, invalid flag combinations

  # ── TTL Filtering ────────────────────────────────────────────────
  min_ttl: 10                      # Drop packets with TTL below this. 0 = disabled.
  max_ttl: 255                     # Drop packets with TTL above this.
                                    # USE WHEN: detecting packet manipulation or routing anomalies

  # ── Packet Size Filtering ────────────────────────────────────────
  min_packet_size: 20              # Drop packets smaller than this (bytes). 0 = disabled.
  max_packet_size: 65535           # Drop packets larger than this.
                                    # USE WHEN: protocol-specific size constraints

  # ── RST Rate Limiting ────────────────────────────────────────────
  tcp_rst_rate_per_ip: 20          # Max RST packets/sec per IP.
                                    # USE WHEN: RST flood attacks after connection close

  # ── UDP Payload Filtering ────────────────────────────────────────
  udp_max_payload: 4096            # Max UDP payload size (bytes)
  udp_min_payload: 1               # Min UDP payload size. 0 = disabled.
                                    # USE WHEN: game protocol has known payload size ranges
```

**Rule Lifecycle**:
1. **Validate** — check config ranges, kernel module availability (`xt_hashlimit`, `xt_connlimit`, `xt_recent`, `xt_state`), and iptables binary
2. **Scan** — find existing rules with `RouteX-*` comment for this proxy's ports
3. **Delete** — remove all old rules (full flush, no orphans)
4. **Create** — insert fresh rules from validated config
5. **Log** — structured log with rule count and proxy name

If validation fails → proxy starts WITHOUT iptables rules (graceful degradation). Rules are per-port, using either `--dport 25565` for single ports or `--dport 25565:25575` for contiguous ranges.

**Orphan prevention**: On `POST /api/iptables/orphan-sweep`, RouteX scans ALL iptables rules with `RouteX-*` comments. Any rule for a port not owned by an active proxy is removed immediately.

---

### L7 Protection Engine

Runs inside Go goroutines — **zero iptables dependency**. Wraps every accepted `net.Conn` with inspection, rate limiting, and behavioral analysis. When disabled (`enabled: false`), the engine is never created — zero overhead.

```yaml
l7_protection:
  enabled: false                # Set to true to activate. DISABLED BY DEFAULT.

  # ── Slow Connection Attack Detection ───────────────────────────
  slow_connection:
    enabled: true
    min_bytes_in_first: 8      # Client must send at least N bytes within handshake_timeout
    handshake_timeout: 5s      # Max time to wait for first payload
    min_recv_rate_bps: 64      # Minimum sustained receive rate (bytes/sec). 0 = disabled.
    # CATCHES: Slowloris, R.U.D.Y., slow read attacks. Attacker opens connection then dribbles data.

  # ── Payload Rate Limiting (Token Bucket) ────────────────────────
  payload_rate_limit:
    enabled: true
    max_bytes_per_sec_per_ip: 5242880    # 5 MB/s per source IP (all conns from that IP combined)
    max_bytes_per_sec_per_conn: 1048576  # 1 MB/s per individual connection
    burst_multiplier: 2.0                # Allow 2x rate for short bursts before enforcing
    # CATCHES: Application-layer floods after connection is accepted (bypasses L3/L4 rules)

  # ── Connection Cycling Detection ────────────────────────────────
  connection_cycling:
    enabled: true
    window: 10s                 # Lookback period
    max_conns_in_window: 30     # Max connections from one IP in the window
    ban_duration: 60s           # How long to ban the IP after triggering
    # CATCHES: IP opens/closes connections rapidly to exhaust resources or evade per-conn limits

  # ── Payload Inspection ──────────────────────────────────────────
  payload_inspection:
    enabled: true
    mode: "minecraft-java"     # Built-in protocol detectors:
                               #   minecraft-java    - Validates VarInt handshake (packet ID 0x00/0xFE)
                               #   minecraft-bedrock - RAKNET packet ID check (0x01 magic, 0x05, 0x07, 0x80-0x8F)
                               #   fivem             - HTTP/1.x handshake detection (GET/POST/HEAD + info\n)
                               #   gmod              - Source Engine query prefix (0xFF 0xFF 0xFF 0xFF + type)
                               #   none              - Passthrough, only rate limiting active
                               #   custom            - User-defined byte rules (see below)
    custom_rules:              # Only used when mode: custom
      - name: "valid-handshake"
        match_offset: 0        # Byte position to start comparison
        match_bytes: "0x0F,0x10"  # Comma-separated hex bytes
        action: "allow"        # Short-circuit — pass immediately
      - name: "junk-payload"
        match_offset: 0
        match_bytes: "0x00,0x00,0x00"
        action: "drop"         # Short-circuit — block immediately
    # HOW IT WORKS: First N bytes of the connection are buffered and checked.
    # Rules evaluated in order. First match wins. No match → default allow.
    # Subsequent reads have ZERO inspection overhead.

  # ── Amplification Detection ─────────────────────────────────────
  amplification:
    enabled: true
    max_response_to_request_ratio: 10.0   # If upstream response is 10x request size → flag
    window: 5s                             # Measurement window
    # CATCHES: DNS/NTP/memcached amplification where a small query yields a huge response

  # ── Behavioral Scoring & Auto-Ban ───────────────────────────────
  behavioral_scoring:
    enabled: true
    score_window: 30s           # Scoring lookback window
    ban_threshold: 100          # Cumulative score ≥ this → automatic ban
    ban_duration: 120s          # Ban duration after threshold hit
    score_rules:                # Map of event → score points (fully customizable)
      - event: "payload_too_small"
        score: 5
      - event: "payload_too_large"
        score: 10
      - event: "handshake_timeout"
        score: 20
      - event: "invalid_protocol"       # Triggered by payload_inspection failures
        score: 30
      - event: "connection_cycling"     # Triggered by connection_cycling detection
        score: 25
      - event: "amplification_detected"
        score: 40
    # HOW IT WORKS: Each offense adds score points to the source IP.
    # When cumulative score ≥ ban_threshold → ALL connections from that IP closed immediately.
    # IP added to ban list with TTL. Score resets after ban.
    # Ban list is in-memory (not persisted).
```

---

### ACL System

Two-layer access control with live management via API. Rules are CIDR-based and evaluated in order — first match wins.

```yaml
acl:
  default_action: "allow"      # What happens when no rule matches
  rules:
    - action: "deny"
      cidr: "10.0.0.0/8"      # Block this entire range
      comment: "internal network block"
    - action: "allow"
      cidr: "1.2.3.4/32"      # Allow this specific IP
      comment: "trusted monitoring host"
    - action: "deny"
      cidr: "5.6.7.0/24"      # Block this subnet
      comment: "known abusive range"
```

**Whitelist mode**: Set `default_action: deny` and add specific `allow` rules for trusted IPs.
**Blacklist mode**: Set `default_action: allow` and add specific `deny` rules for bad IPs.

**Evaluation order**:
1. **Global ACL** checked first (from `global.yaml`). If denied → connection dropped.
2. **Per-Proxy ACL** checked second. If denied → connection dropped.
3. If both pass → connection accepted.

**Live management** — 8 API endpoints for add/remove/replace rules without restart:
```bash
# View global ACL rules + stats
curl -H "X-API-Key: admin" http://localhost:9000/api/acl/global

# Add a rule
curl -X POST -H "X-API-Key: admin" -H "Content-Type: application/json" \
  -d '{"action":"deny","cidr":"9.9.9.0/24","comment":"bad subnet"}' \
  http://localhost:9000/api/acl/global/rules

# Remove a rule
curl -X DELETE -H "X-API-Key: admin" \
  "http://localhost:9000/api/acl/global/rules?cidr=9.9.9.0/24"
```

---

### Bandwidth Management

Track and limit bandwidth per-proxy. Hourly buckets with configurable quotas.

```yaml
bandwidth:
  enabled: true
  hourly_limit: 10737418240     # 10 GB/hour. Bytes, not bits! 0 = unlimited.
  daily_limit: 107374182400     # 100 GB/day
  weekly_limit: 0               # Unlimited
  monthly_limit: 2147483648000  # 2 TB/month
  suspend_on_limit: true        # Auto-suspend the proxy when quota exceeded
```

**How it works**:
- Byte counters updated from proxy copy goroutines (hot path, atomic operations)
- Hourly buckets with 31-day retention (auto-pruned)
- Quota checked every hour + on every bandwidth API call
- When `suspend_on_limit: true` and quota exceeded → proxy stops accepting new connections
- Quota resets at the **top of the boundary in the configured timezone**: hourly = top of hour, daily = midnight, weekly = Monday 00:00, monthly = 1st 00:00

**API**:
```bash
# View current usage
curl -H "X-API-Key: admin" http://localhost:9000/api/bandwidth/proxy/minecraft-main

# Reset counters to zero
curl -X POST -H "X-API-Key: admin" http://localhost:9000/api/bandwidth/proxy/minecraft-main/reset
```

**Sample response**:
```json
{
  "name": "minecraft-main",
  "inbound_bytes": 524288000,
  "outbound_bytes": 1073741824,
  "hourly_used": 524288000,
  "daily_used": 1598029824,
  "hourly_percent": 4.88,
  "daily_percent": 1.48,
  "suspended": false
}
```

---

### Metrics & Monitoring

One endpoint, four output formats. SQLite-backed with configurable retention.

```
GET /metrics?format=json         → {"active_connections": ..., "bytes_in": ...}
GET /metrics?format=prometheus   → # TYPE routex_active_connections gauge\nroutex_active_connections 42
GET /metrics?format=influx       → routex active_connections=42 1719000000000000000
GET /metrics?format=csv          → metric,value\nactive_connections,42
GET /metrics/proxy/{name}        → Per-proxy metrics
```

**Prometheus metrics exposed**:
```
routex_active_connections{proxy="mc"} 42
routex_total_connections{proxy="mc"} 15000
routex_bytes_in{proxy="mc"} 1073741824
routex_bytes_out{proxy="mc"} 2147483648
routex_l7_blocked{proxy="mc"} 127
routex_upstream_active_conns{proxy="mc",upstream="10.0.0.1:35565"} 15
routex_upstream_healthy{proxy="mc",upstream="10.0.0.1:35565"} 1
```

**Grafana integration**: Point at `http://routex:9000/metrics?format=prometheus` with `X-API-Key` header.

---

### REST API

36 endpoints. All protected except `/api/health` and `/api/version`.

| Category | Endpoints | Permission |
|----------|-----------|------------|
| Health | `GET /api/health`, `GET /api/version` | None |
| Proxies | List, get, enable, disable, reload, connections, kill, upstreams, eject, readmit | `proxies:read` / `*` |
| Metrics | Global + per-proxy in 4 formats | `metrics:read` |
| iptables | Rules list, validate, flush, orphan sweep | `*` |
| L7 | Banned list, unban, manual ban, events | `*` |
| ACL | Global + per-proxy: get, add, remove, replace (8 endpoints) | `*` |
| Bandwidth | Usage snapshot, reset counters | `metrics:read` |
| System | Reload all configs | `*` |

---

### Hot Reload

RouteX watches `configs/proxies/` with inotify (fsnotify). When a `.yaml` file changes:

1. **Debounce** — 200ms quiet window to collapse rapid saves (vim, `sed -i`)
2. **Validate** — new config validated in isolation. If it fails, old proxy keeps running.
3. **Reload** — old proxy stops with draining, new proxy starts with fresh config
4. **iptables** — old rules flushed, new rules created from validated config

Only the changed proxy is reloaded. All other proxies continue without interruption.

---

### Timezone

Set in `global.yaml` under `timezone:`. Used for:
- **Bandwidth quota resets** (hourly/daily/weekly/monthly boundaries)
- All future time-based features

Invalid timezone names fall back to UTC. Valid examples: `America/New_York`, `Europe/London`, `Asia/Tokyo`, `Australia/Sydney`.

---

### Installation

```bash
sudo bash install.sh /opt/routex
```

**Supported**: Debian/Ubuntu, RHEL/CentOS/Rocky/Alma/Fedora/Amazon Linux, Arch/Manjaro, Alpine Linux.

The installer: detects OS → installs system deps → installs Go → checks iptables kernel modules → builds RouteX → installs systemd service → verifies firewall.

---

### Testing

```bash
go test -short ./...       # 69 tests, all passing
go test -cover ./...       # Coverage report
```

**69 tests across 6 packages**: config validation (10), load balancer algorithms (9), port mapping (4), E2E TCP proxy (4), L7 protocol detection (6), rate limiters (8), L7 engine (9), iptables (10), API middleware (8). Includes 50 concurrent connections and 64KB throughput verification.

---

### Project Structure

```
RouteX/
├── cmd/routex/main.go                 # Entry point, signal handling
├── configs/
│   ├── global.yaml                    # Cross-cutting settings
│   └── proxies/                       # One YAML file per proxy instance
├── internal/
│   ├── acl/                           # IP whitelist/blacklist engine
│   ├── api/                           # REST API (Chi router, 36 endpoints)
│   ├── bandwidth/                     # Per-proxy tracking + quota management
│   ├── config/                        # YAML loading, validation, file watcher
│   ├── health/                        # Active TCP health probes
│   ├── iptables/                      # Rule builder, validator, lifecycle manager
│   ├── l7/                            # Protocol detectors, token bucket, scoring engine
│   ├── lb/                            # 5 load balancing algorithms
│   ├── metrics/                       # SQLite store, collector, multi-format API
│   └── proxy/                         # TCP/UDP engines, port mapping, draining
├── install.sh                         # Universal installer
├── Makefile
└── README.md
```
