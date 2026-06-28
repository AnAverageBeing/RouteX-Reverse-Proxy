# RouteX — Fast Reverse Proxy

<div align="center">

![RouteX](https://img.shields.io/badge/RouteX-Reverse%20Proxy-00ADD8?style=for-the-badge&logo=go&logoColor=white)
![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go)
![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![Tests](https://img.shields.io/badge/tests-69%20passing-brightgreen?style=flat-square)
![Build](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)

**Production-grade L3/L4/L7 reverse proxy built in Go.**
Purpose-built for game server infrastructure with DDoS protection, protocol validation, and bandwidth management.

</div>

---

## Overview

RouteX is a high-performance TCP/UDP reverse proxy designed for production infrastructure handling thousands of concurrent connections. It combines kernel-level iptables rate limiting with an in-process L7 protection engine to provide layered defense against DDoS attacks, protocol abuse, and bandwidth exhaustion.

### Why RouteX?

| Feature | RouteX | HAProxy | Nginx |
|---------|--------|---------|-------|
| Game Protocol Detection (MC Java/Bedrock/FiveM/GMod) | ✅ Built-in | ❌ | ❌ |
| Behavioral Scoring & Auto-Ban | ✅ | ❌ | ❌ |
| Multi-Format Metrics (Prometheus/Influx/CSV/JSON) | ✅ One endpoint | ⚠️ Exporter | ⚠️ Exporter |
| Per-Proxy Bandwidth Quotas (hourly/daily/weekly/monthly) | ✅ | ❌ | ❌ |
| REST API with 36 endpoints | ✅ | ⚠️ Stats socket | ⚠️ Limited |
| YAML Config | ✅ | Custom DSL | Custom DSL |
| Hot Reload (per-proxy, no downtime) | ✅ | ⚠️ Soft reload | ⚠️ Reload |
| iptables Rate Limiting (PPS, SYN, RST, connlimit) | ✅ | ❌ (L7 only) | ❌ |

---

## Quick Start

```bash
# Clone
git clone https://github.com/AnAverageBeing/RouteX-Reverse-Proxy.git
cd RouteX-Reverse-Proxy

# Build
make build

# Run with example configs
make run

# Or directly
./bin/routex -config configs/global.yaml -proxies configs/proxies
```

**Verify it's running:**
```bash
curl http://localhost:9000/api/health
curl -H "X-API-Key: pk_admin_xxxxxxxxxxxx" http://localhost:9000/api/proxies
```

---

## Features

### 🔒 Multi-Layer DDoS Protection

| Layer | Mechanism | Location |
|-------|-----------|----------|
| L3/L4 | iptables rate limiting (PPS, SYN flood, RST flood, connlimit, fragment drop, invalid TCP state) | Kernel |
| L4+ | Global + per-proxy IP whitelist/blacklist with CIDR matching | Go (in-process) |
| L7 | Protocol-aware payload inspection (Minecraft Java/Bedrock, FiveM, GMod, custom) | Go (in-process) |
| L7 | Behavioral scoring with auto-ban (configurable thresholds) | Go (in-process) |
| L7 | Connection cycling detection (sliding window per IP) | Go (in-process) |
| L7 | Per-IP payload rate limiting (token bucket, no kernel dependency) | Go (in-process) |

### ⚖️ Load Balancing

5 algorithms, all production-tested:
- **round-robin** — rotating order, skips unhealthy targets
- **least-conn** — fewest active connections
- **ip-hash** — FNV-32 hash for stable session affinity
- **weighted** — probability proportional to configured weights
- **random** — uniform random selection

Plus: sticky sessions (source IP affinity with TTL), per-upstream health checks (active TCP probes), upstream weights, auto-eject/readmit.

### 📊 Bandwidth Management

- Per-proxy inbound/outbound byte tracking in hourly buckets
- Configurable quotas: hourly, daily, weekly, monthly (0 = unlimited)
- Auto-suspension when quota exceeded (`suspend_on_limit: true`)
- Timezone-aware resets
- API: `GET /api/bandwidth/proxy/{name}`, `POST /api/bandwidth/proxy/{name}/reset`

### 📡 Metrics & Monitoring

One endpoint, four formats:
```
GET /metrics?format=json        → JSON
GET /metrics?format=prometheus  → Prometheus exposition
GET /metrics?format=influx      → InfluxDB line protocol
GET /metrics?format=csv         → CSV
```

SQLite-backed persistence with configurable retention. Per-proxy metrics at `/metrics/proxy/{name}`.

### 🛡️ ACL System

- **Global ACL** (checked first): block entire CIDRs globally
- **Per-proxy ACL** (checked second): fine-grained per-service control
- **Whitelist mode**: `default_action: deny` + specific `allow` rules
- **Blacklist mode**: `default_action: allow` + specific `deny` rules
- **Live management**: 8 API endpoints for add/remove/replace rules at runtime

### 🔌 REST API (36 Endpoints)

| Category | Endpoints | Scope |
|----------|-----------|-------|
| Health | `/api/health`, `/api/version` | Public |
| Proxies | CRUD, enable/disable, reload, connections, upstreams | `proxies:read` / `*` |
| Metrics | `/metrics?format=...`, `/metrics/proxy/{name}` | `metrics:read` |
| iptables | List rules, validate, flush, orphan sweep | `*` |
| L7 | Banned IPs, unban, manual ban, events | `*` |
| ACL | Global + per-proxy rule management (8 endpoints) | `*` |
| Bandwidth | Usage snapshot, reset counters | `metrics:read` |
| System | `/api/reload` | `*` |

### ⚙️ Configuration

**Global** (`configs/global.yaml`): API server, metrics, network tuning, iptables behavior, timezone, logging.

**Per-Proxy** (`configs/proxies/*.yaml`): Each file is one isolated proxy instance. One config failing validation never affects others.

```yaml
name: "minecraft-main"
origin-ip: "0.0.0.0"
origin-port: "25565:25575"
dest-ip: "10.0.0.1, 10.0.0.2"
dest-port: "35565:35575"
one-to-one: true
protocol: "tcp-udp"
load_balancing:
  algorithm: "least-conn"
  upstream_weights:
    "10.0.0.1": 3
    "10.0.0.2": 1
rate_limits:
  tcp_pps_per_ip: 500
  new_conns_per_sec_per_ip: 20
  max_simultaneous_conns_per_ip: 10
l7_protection:
  enabled: false  # L7 is optional!
  payload_inspection:
    mode: "minecraft-java"
acl:
  default_action: "allow"
  rules:
    - action: "deny"
      cidr: "10.0.0.0/8"
bandwidth:
  enabled: true
  daily_limit: 107374182400  # 100 GB/day
  suspend_on_limit: true
connection_draining:
  enabled: true
  timeout: 30s
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

---

## Project Structure

```
RouteX/
├── cmd/routex/main.go                 # Entry point
├── configs/
│   ├── global.yaml                    # Global configuration
│   └── proxies/
│       ├── minecraft.yaml             # Full-featured MC proxy example
│       └── gameserver.yaml            # Generic game server example
├── internal/
│   ├── acl/                           # IP whitelist/blacklist engine
│   ├── api/                           # REST API (server, middleware, 36 routes)
│   ├── bandwidth/                     # Per-proxy bandwidth tracking + quotas
│   ├── config/                        # Config loading, validation, file watcher
│   ├── health/                        # Active TCP health checker
│   ├── iptables/                      # iptables rule builder + lifecycle manager
│   ├── l7/                            # L7 protection engine (4 subsystems)
│   │   ├── engine.go                  # Scoring, banning, event tracking
│   │   ├── inspector.go               # Payload inspector + ban store
│   │   ├── patterns.go                # Protocol detectors
│   │   └── ratelimit.go               # Token bucket + sliding window
│   ├── lb/                            # Load balancer (5 algorithms)
│   ├── metrics/                       # SQLite store, collector, multi-format API
│   └── proxy/                         # TCP/UDP engines, manager, portmap
├── install.sh                         # Universal installer (Debian/RHEL/Arch/Alpine)
├── Makefile
└── README.md
```

---

## Installation

### Automated (Recommended)

```bash
sudo bash install.sh /opt/routex
```

Supports: Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, Fedora, Arch/Manjaro, Alpine Linux.

The installer:
1. Detects OS and installs all system dependencies
2. Installs Go 1.22 if not present
3. Checks iptables kernel modules
4. Builds RouteX → `/usr/local/bin/routex`
5. Installs systemd service
6. Verifies firewall configuration

### Manual

**Prerequisites**: Go 1.22+, iptables, sqlite3, gcc, pkg-config

```bash
git clone https://github.com/AnAverageBeing/RouteX-Reverse-Proxy.git
cd RouteX-Reverse-Proxy
go mod download
make build
```

---

## Testing

```bash
# Run all tests (69 tests, all passing)
go test -short ./...

# With coverage
go test -cover -coverprofile=coverage.txt -short ./...

# Full throughput test
go test -v -run TestTCPProxy_HighThroughput ./internal/proxy/
```

### Test Coverage by Package

| Package | Coverage | Tests |
|---------|----------|-------|
| `l7` | 80.9% | 23 |
| `lb` | 71.8% | 9 |
| `config` | 43.4% | 10 |
| `iptables` | 33.7% | 10 |
| `proxy` | 28.2% | 8 |
| `api` | 11.8% | 8 |

Includes real end-to-end TCP proxy tests with 50 concurrent connections, 64KB throughput verification, and unreachable backend handling.

---

## License

MIT — see LICENSE file for details.

---

<div align="center">

**[Documentation](https://anaveragebeing.github.io/pingless-studios-docs/routex/)** · **[Issues](https://github.com/AnAverageBeing/RouteX-Reverse-Proxy/issues)** · **[Discussions](https://github.com/AnAverageBeing/RouteX-Reverse-Proxy/discussions)**

Made with ❤️ by [PingLess Studios](https://github.com/AnAverageBeing)

</div>
