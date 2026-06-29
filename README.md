<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/AnAverageBeing/RouteX-Reverse-Proxy/main/.github/routex-dark.png">
  <img alt="RouteX" src="https://raw.githubusercontent.com/AnAverageBeing/RouteX-Reverse-Proxy/main/.github/routex-light.png" width="600">
</picture>

# RouteX — Fast Reverse Proxy

> **Production-grade L3/L4/L7 reverse proxy in Go.**
> Built for game server infrastructure — DDoS protection, protocol validation, bandwidth quotas, and a full REST API.

<p align="center">
  <a href="https://anaveragebeing.github.io/pingless-studios-docs/routex/"><img src="https://img.shields.io/badge/docs-online-brightgreen?style=flat-square" alt="Docs"></a>
  <a href="https://github.com/AnAverageBeing/RouteX-Reverse-Proxy/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="License"></a>
  <a href="https://github.com/AnAverageBeing/RouteX-Reverse-Proxy/actions"><img src="https://img.shields.io/badge/build-passing-brightgreen?style=flat-square" alt="Build"></a>
  <img src="https://img.shields.io/badge/tests-69%20passing-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-80.9%25%20(l7)-green?style=flat-square" alt="Coverage">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go" alt="Go">
  <img src="https://img.shields.io/badge/endpoints-36-orange?style=flat-square" alt="API Endpoints">
</p>

---

## Why RouteX?

<p align="center">
  <b>RouteX fills the gap between HAProxy's complexity and Nginx's limitations — purpose-built for game servers, DDoS protection, and modern API-driven infrastructure.</b>
</p>

### Comparison: RouteX vs HAProxy vs Traefik vs Caddy

| Feature | RouteX | HAProxy | Traefik | Caddy |
|---------|:------:|:-------:|:-------:|:-----:|
| **Layer** | L3/L4/L7 | L4/L7 | L7 | L7 |
| **UDP Proxying** | ✅ Native | ⚠️ Limited | ✅ | ❌ |
| **Game Protocol Detection** | ✅ MC Java/Bedrock, FiveM, GMod | ❌ | ❌ | ❌ |
| **L7 Behavioral Scoring** | ✅ Auto-ban by threat score | ❌ | ❌ | ❌ |
| **Connection Cycling Detection** | ✅ Sliding window per IP | ❌ | ❌ | ❌ |
| **iptables Rate Limiting** | ✅ Kernel-level PPS/SYN/RST/connlimit | ❌ L7 only | ❌ | ❌ |
| **Bandwidth Quotas** | ✅ Hourly/Daily/Weekly/Monthly | ❌ | ❌ | ❌ |
| **ACL (Whitelist/Blacklist)** | ✅ Global + Per-proxy, live API | ✅ Extensive | ✅ Middleware | ❌ |
| **Load Balancing** | ✅ 5 algorithms | ✅ 10+ algorithms | ✅ Round-robin | ✅ Round-robin |
| **Health Checks** | ✅ Active TCP probes | ✅ Active + Passive | ✅ | ✅ |
| **Metrics Format** | Prometheus + InfluxDB + CSV + JSON | Prometheus (exporter) | Prometheus + OTEL | Prometheus |
| **REST API** | ✅ 36 endpoints, API-key auth | ⚠️ Stats socket (text) | ✅ Dashboard | ✅ Admin API |
| **YAML Config** | ✅ Simple, flat structure | Custom DSL | YAML/TOML/KV | Caddyfile/JSON |
| **Hot Reload** | ✅ Per-proxy, zero downtime | ⚠️ Soft reload | ✅ | ✅ Graceful |
| **TLS Termination** | ⚠️ Passthrough only | ✅ Full | ✅ Auto Let's Encrypt | ✅ Auto Let's Encrypt |
| **HTTP L7 Routing** | ❌ L4 only | ✅ Full | ✅ Full | ✅ Full |
| **PROXY Protocol** | ❌ | ✅ | ✅ | ✅ |
| **DNS-based Discovery** | ❌ | ✅ | ✅ Docker/Swarm/K8s | ❌ |
| **Web UI** | ❌ REST API only | ✅ Stats page | ✅ Dashboard | ❌ |
| **Let's Encrypt** | ❌ | ❌ | ✅ | ✅ Auto |
| **Maturity** | New (2026) | 20+ years | 9 years | 10 years |
| **Best For** | Game servers, DDoS protection, API-driven infra | HTTP-heavy, enterprise | Cloud-native, containers | Simple web servers |

### When to Choose RouteX

✅ **Game server hosting** — built-in Minecraft/FiveM/GMod protocol validation catches bot attacks that generic proxies miss.

✅ **DDoS mitigation** — layered defense: iptables drops volumetrics at kernel level, L7 catches slow/app-layer attacks.

✅ **API-driven infrastructure** — 36 REST endpoints for full programmatic control. No config file editing needed at runtime.

✅ **Bandwidth-constrained environments** — enforce hourly/daily/monthly quotas with auto-suspension. Perfect for metered hosting.

### When to Choose Something Else

❌ **HTTP/HTTPS web servers** — use Caddy (simple) or Nginx. RouteX is L4, it doesn't parse HTTP.

❌ **Kubernetes ingress** — use Traefik. RouteX doesn't have native K8s service discovery.

❌ **Enterprise HTTP routing** — use HAProxy. RouteX doesn't do header rewriting, cookie persistence, or URL-based routing.

---

## Quick Start

```bash
git clone https://github.com/AnAverageBeing/RouteX-Reverse-Proxy.git
cd RouteX-Reverse-Proxy
make build
make run
```

```bash
# Health check (no auth)
curl http://localhost:9000/api/health

# List proxies (needs API key)
curl -H "X-API-Key: pk_admin_xxxxxxxxxxxx" http://localhost:9000/api/proxies

# Prometheus metrics
curl -H "X-API-Key: pk_admin_xxxxxxxxxxxx" "http://localhost:9000/metrics?format=prometheus"
```

---

## Documentation

**Full documentation**: [anaveragebeing.github.io/pingless-studios-docs/routex/](https://anaveragebeing.github.io/pingless-studios-docs/routex/)

| Section | Description |
|---------|-------------|
| [Getting Started](https://anaveragebeing.github.io/pingless-studios-docs/routex/getting-started/overview) | Overview, installation, quick start, FAQ |
| [Global Config](https://anaveragebeing.github.io/pingless-studios-docs/routex/reference/global-config) | Every global setting explained |
| [Proxy Config](https://anaveragebeing.github.io/pingless-studios-docs/routex/reference/proxy-config) | Every per-proxy field with use cases |
| [API Reference](https://anaveragebeing.github.io/pingless-studios-docs/routex/api/endpoints) | All 36 endpoints documented |

---

## Features at a Glance

### 🛡 Defense Layers (in order of evaluation)

```
1. Global ACL ──► 2. Per-Proxy ACL ──► 3. iptables Rate Limits ──► 4. L7 Engine ──► 5. Bandwidth Quota
```

| Layer | Type | Where | What It Catches |
|-------|------|-------|----------------|
| Global ACL | IP allow/deny | Go | Known bad IPs before any proxy |
| Per-Proxy ACL | IP allow/deny | Go | Service-specific access control |
| TCP/UDP PPS | Packet rate | iptables | Volumetric floods |
| SYN Rate | Connection rate | iptables | SYN floods |
| Connlimit | Connection count | iptables | Connection exhaustion |
| Fragment Drop | Packet filter | iptables | Teardrop/fragmentation attacks |
| Invalid TCP State | State filter | iptables | Spoofed/blind attacks |
| TTL/Packet Size | Packet filter | iptables | Anomalous packet detection |
| Slow Connection | Handshake timeout | Go L7 | Slowloris, R.U.D.Y. |
| Payload Rate Limit | Token bucket | Go L7 | App-layer floods after accept |
| Connection Cycling | Sliding window | Go L7 | Rapid open/close abuse |
| Payload Inspection | Byte matching | Go L7 | Invalid game protocol handshakes |
| Amplification | Ratio check | Go L7 | DNS/NTP reflection |
| Behavioral Scoring | Per-IP scoring | Go L7 | Multi-vector coordinated attacks |
| Bandwidth Quota | Byte counting | Go | Usage overage, cost control |

### ⚖️ 5 Load Balancing Algorithms

| Algorithm | Best For |
|-----------|----------|
| Round-Robin | Simple, predictable distribution |
| Least-Conn | Long-lived connections (game servers) |
| IP-Hash | Stable session affinity |
| Weighted | Heterogeneous backends |
| Random | Basic load spreading |

### 📊 Complete Observability

- **Prometheus, InfluxDB, CSV, JSON** — all from one `/metrics` endpoint
- **SQLite persistence** with configurable retention
- **Per-connection access logging** (accept, close, bytes, duration)
- **L7 event stream** — queryable via API with search and limits

### 🔌 36 REST API Endpoints

Full CRUD for proxies, upstreams, ACL rules, iptables rules, L7 bans, bandwidth, and system config. API-key authentication with scoped permissions.

---

## Installation

```bash
# Automated (recommended)
sudo bash install.sh /opt/routex
```

**Supports**: Debian, Ubuntu, RHEL, CentOS, Rocky, Alma, Fedora, Amazon Linux, Arch, Manjaro, Alpine.

**Installs**: System dependencies → Go 1.22+ → Builds binary → systemd service → Firewall check.

---

## Configuration

RouteX uses a simple flat YAML structure. No nested wrappers, no confusing indirection.

### Minimal TCP Proxy

```yaml
# configs/proxies/minimal.yaml
name: "my-tcp-proxy"
enabled: true
origin-ip: "0.0.0.0"
origin-port: "8080"
dest-ip: "10.0.0.1"
dest-port: "9090"
protocol: "tcp"
one-to-one: true
```

### Full Production Config

```yaml
name: "minecraft-main"
enabled: true
origin-ip: "0.0.0.0"
origin-port: "25565:25575"
dest-ip: "10.0.0.1, 10.0.0.2"
dest-port: "35565:35575"
one-to-one: true
protocol: "tcp-udp"

load_balancing:
  algorithm: "least-conn"
  sticky_sessions: true
  sticky_ttl: 3600

rate_limits:
  tcp_pps_per_ip: 500
  new_conns_per_sec_per_ip: 20
  max_simultaneous_conns_per_ip: 10
  drop_fragmented_packets: true
  tcp_syn_rate_per_ip: 10
  tcp_invalid_state_drop: true

l7_protection:
  enabled: true
  payload_inspection:
    enabled: true
    mode: "minecraft-java"
  behavioral_scoring:
    enabled: true
    ban_threshold: 100
    ban_duration: 300s

acl:
  default_action: "allow"
  rules:
    - action: "deny"
      cidr: "10.0.0.0/8"

bandwidth:
  enabled: true
  daily_limit: 107374182400
  suspend_on_limit: true
```

---

## Project Structure

```
RouteX/
├── cmd/routex/main.go              # Entry point
├── configs/
│   ├── global.yaml                 # Cross-cutting settings
│   └── proxies/                    # One file per proxy instance
├── internal/
│   ├── acl/                        # IP whitelist/blacklist engine
│   ├── api/                        # Chi router, middleware, 36 endpoints
│   ├── bandwidth/                  # Tracker + quota management
│   ├── config/                     # YAML loading, validation, file watcher
│   ├── health/                     # Active TCP probes
│   ├── iptables/                   # Rule builder, validator, manager
│   ├── l7/                         # Protocol detection, token bucket, scoring
│   ├── lb/                         # 5 algorithms, sticky sessions
│   ├── metrics/                    # SQLite store, collector, multi-format API
│   └── proxy/                      # TCP/UDP engines, port mapping, draining
├── .github/                        # Issue templates, PR template
├── LICENSE                         # MIT
├── CONTRIBUTING.md                 # Development guide
├── SECURITY.md                     # Vulnerability reporting
├── CODE_OF_CONDUCT.md              # Community standards
├── Makefile
└── README.md
```

---

## Community

- **Documentation**: [pingless-studios-docs/routex](https://anaveragebeing.github.io/pingless-studios-docs/routex/)
- **Issues**: [GitHub Issues](https://github.com/AnAverageBeing/RouteX-Reverse-Proxy/issues)
- **Discussions**: [GitHub Discussions](https://github.com/AnAverageBeing/RouteX-Reverse-Proxy/discussions)
- **Discord**: [PingLess Studios](https://discord.gg/qgBMREWWgp)
- **Security**: See [SECURITY.md](SECURITY.md)

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/AnAverageBeing">PingLess Studios</a>
</p>
