# RouteX REST API Reference

RouteX exposes a complete HTTP control plane designed to be the backend for a
custom dashboard (think TCPShield-style network management). Every runtime
object — proxies, upstreams, connections, ACLs, L7 bans, bandwidth quotas,
rate limits and live/historical metrics — is reachable over JSON.

- **Base URL:** `http://<bind-addr>` (default `http://0.0.0.0:9000`, set via `api.bind` in `global.yaml`)
- **Content type:** all responses are `application/json` unless a metric `format` is requested
- **CORS:** enabled for all origins (`*`) so a browser dashboard can call the API directly

---

## Authentication

All endpoints except `GET /api/health` and `GET /api/version` require an API key.

Provide it either way:

| Method | Example |
| ------ | ------- |
| Header (preferred) | `X-API-Key: pk_live_xxxxxxxx` |
| Query parameter | `?api_key=pk_live_xxxxxxxx` |

Keys are declared in `global.yaml`:

```yaml
api:
  enabled: true
  bind: "0.0.0.0:9000"
  api_keys:
    - key: "pk_admin_xxxxxxxx"
      label: "admin"
      permissions: ["*"]
    - key: "pk_dash_xxxxxxxx"
      label: "grafana-dashboard"
      permissions: ["metrics:read", "proxies:read"]
```

> If `api.enabled` is `false`, RouteX treats the API as a local-only instrument
> and bypasses auth. Keep it enabled in production.

### Permission scopes

| Scope | Grants |
| ----- | ------ |
| `*` | Everything (admin) |
| `proxies:read` | Read proxies, stats, connections, upstreams, config, system, overview |
| `metrics:read` | `/metrics*` and `/api/bandwidth/*` |

Mutating endpoints (create/update/delete/enable/disable/reload, ACL/L7/iptables
changes, key listing) require `*`.

### Auth responses

| Status | Meaning |
| ------ | ------- |
| `401 Unauthorized` | Missing or invalid API key |
| `403 Forbidden` | Key valid but lacks the required scope |

---

## Endpoint index

| Method | Path | Scope | Purpose |
| ------ | ---- | ----- | ------- |
| GET | `/api/health` | none | Liveness probe |
| GET | `/api/version` | none | Version/build info |
| GET | `/api/system` | proxies:read | Server runtime + resource info |
| GET | `/api/overview` | proxies:read | One-shot dashboard payload |
| GET | `/api/stats` | proxies:read | Global aggregate counters |
| GET | `/api/stats/proxy/{name}` | proxies:read | Live per-proxy stats |
| GET | `/api/stats/proxy/{name}/history` | proxies:read | Time-series for graphs |
| GET | `/api/keys` | * | List API keys (masked) |
| GET | `/api/proxies` | proxies:read | List all proxies (running + on-disk) |
| GET | `/api/proxies/{name}` | proxies:read | Single proxy summary |
| GET | `/api/proxies/{name}/config` | proxies:read | Full config (JSON + YAML) |
| POST | `/api/proxies` | * | Create a proxy |
| POST | `/api/proxies/validate` | * | Validate a config without applying |
| PUT | `/api/proxies/{name}` | * | Replace a proxy config |
| DELETE | `/api/proxies/{name}` | * | Stop + delete a proxy |
| POST | `/api/proxies/{name}/enable` | * | Enable + start (persists) |
| POST | `/api/proxies/{name}/disable` | * | Disable + stop (persists) |
| POST | `/api/proxies/{name}/reload` | * | Reload this proxy from disk |
| GET | `/api/proxies/{name}/connections` | proxies:read | Active connections |
| DELETE | `/api/proxies/{name}/connections/{id}` | * | Kill a connection |
| GET | `/api/proxies/{name}/upstreams` | proxies:read | Upstream list + health |
| POST | `/api/proxies/{name}/upstreams/{ip}/eject` | * | Force-eject an upstream |
| POST | `/api/proxies/{name}/upstreams/{ip}/readmit` | * | Force-readmit an upstream |
| GET | `/api/proxies/{name}/l7` | proxies:read | L7 status + counters |
| GET | `/api/proxies/{name}/ratelimits` | proxies:read | Configured rate limits |
| GET | `/api/acl/global` | * | Global ACL + stats |
| POST | `/api/acl/global/rules` | * | Add a global ACL rule |
| DELETE | `/api/acl/global/rules?cidr=` | * | Remove a global ACL rule |
| PUT | `/api/acl/global/rules` | * | Replace global ACL rules |
| GET | `/api/acl/proxy/{name}` | * | Per-proxy ACL + stats |
| POST | `/api/acl/proxy/{name}/rules` | * | Add a per-proxy ACL rule |
| DELETE | `/api/acl/proxy/{name}/rules?cidr=` | * | Remove a per-proxy ACL rule |
| PUT | `/api/acl/proxy/{name}/rules` | * | Replace per-proxy ACL rules |
| GET | `/api/l7/banned` | * | List L7-banned IPs |
| POST | `/api/l7/banned/{ip}?duration=` | * | Manually ban an IP |
| DELETE | `/api/l7/banned/{ip}` | * | Unban an IP |
| GET | `/api/l7/events?limit=` | * | Recent L7 block/ban events |
| GET | `/api/bandwidth/proxy/{name}` | metrics:read | Bandwidth usage + quota |
| POST | `/api/bandwidth/proxy/{name}/reset` | metrics:read | Reset bandwidth counters |
| GET | `/api/iptables/rules` | * | List RouteX-managed iptables rules |
| POST | `/api/iptables/validate` | * | Dry-run validate a rate-limit block |
| POST | `/api/iptables/flush/{proxy}` | * | Flush + recreate a proxy's rules |
| POST | `/api/iptables/orphan-sweep` | * | Remove orphaned RouteX rules |
| POST | `/api/reload` | * | Re-scan the proxies dir (reload all) |
| GET | `/metrics` | metrics:read | Global metrics (multi-format) |
| GET | `/metrics/proxy/{name}` | metrics:read | Per-proxy metrics |

---

## System & overview

### `GET /api/health`
No auth. Liveness probe.
```json
{ "status": "ok" }
```

### `GET /api/version`
```json
{ "project": "RouteX", "version": "0.1.0" }
```

### `GET /api/system`
Server runtime + resource snapshot for a status panel.
```json
{
  "project": "RouteX", "version": "0.1.0",
  "uptime_seconds": 3, "started_at": "2026-06-30T05:53:54Z", "timezone": "UTC",
  "go_version": "go1.23.0", "os": "linux", "arch": "amd64",
  "num_cpu": 12, "goroutines": 52,
  "mem_alloc_bytes": 1599208, "mem_sys_bytes": 11885584,
  "proxies_running": 10, "iptables_enabled": false, "metrics_enabled": true
}
```

### `GET /api/overview`
Everything a dashboard landing page needs in **one call**: totals plus a
per-proxy summary.
```json
{
  "version": "0.1.0", "uptime_seconds": 42,
  "totals": {
    "proxies": 10, "active_connections": 5, "total_connections": 1287,
    "bytes_in": 9123847, "bytes_out": 11238471, "l7_blocked": 3, "l7_banned": 1
  },
  "proxies": [
    { "name": "minecraft-main", "running": true, "active_connections": 5,
      "total_connections": 1287, "bytes_in": 9123847, "bytes_out": 11238471,
      "upstreams_healthy": 2, "upstreams_total": 2, "l7_blocked": 3, "suspended": false }
  ]
}
```

---

## Stats

### `GET /api/stats`
Global aggregate counters across all proxies.
```json
{ "proxies": 10, "active_connections": 5, "total_connections": 1287,
  "bytes_in": 9123847, "bytes_out": 11238471, "l7_blocked": 3, "l7_banned": 1 }
```

### `GET /api/stats/proxy/{name}`
Detailed live stats for one proxy, combining proxy counters, balancer health,
L7 engine, and bandwidth tracker.
```json
{
  "name": "tcp-single", "running": true,
  "active_connections": 0, "total_connections": 1,
  "bytes_in": 10, "bytes_out": 19,
  "upstreams": [
    { "IP": "127.0.0.1", "Port": 28001, "Weight": 1, "Healthy": true,
      "ActiveConns": 0, "TotalConns": 1, "FailCount": 0 }
  ],
  "upstreams_total": 1, "upstreams_healthy": 1,
  "l7_enabled": false, "l7_blocked": 0, "l7_banned": 0,
  "suspended": false
}
```

### `GET /api/stats/proxy/{name}/history?hours=24&limit=1000`
Persisted time-series samples (SQLite-backed, survive restarts) for rendering
connection/bandwidth graphs. `hours` defaults to 24 (max 720); `limit` caps rows.
```json
{
  "proxy": "tcp-single", "hours": 1, "count": 34,
  "points": [
    { "timestamp": 1782798836, "active_connections": 0, "total_connections": 0,
      "bytes_in": 0, "bytes_out": 0, "l7_blocked": 0, "l7_banned": 0, "rate_limited_drops": 0 }
  ]
}
```

---

## API keys

### `GET /api/keys` (scope `*`)
Lists configured keys **without** revealing the secret — only a masked preview.
```json
[
  { "label": "admin", "masked_key": "pk_a…test", "permissions": ["*"] },
  { "label": "grafana-dashboard", "masked_key": "pk_d…test", "permissions": ["metrics:read", "proxies:read"] }
]
```

---

## Proxies

### `GET /api/proxies`
Lists every proxy known to RouteX — both **running** instances and proxies that
exist on disk but are stopped/disabled — so a dashboard can show and re-enable them.
```json
[
  { "name": "minecraft-main", "description": "MC proxy", "running": true,
    "enabled": true, "protocol": "tcp-udp", "origin_port": "25565:25575",
    "active_connections": 5, "config_path": "configs/proxies/minecraft.yaml" }
]
```

### `GET /api/proxies/{name}`
```json
{ "name": "minecraft-main", "running": true, "active_conns": 5 }
```

### `GET /api/proxies/{name}/config`
Full config as structured JSON (YAML field names) **and** raw YAML, so a UI can
render a form or a text editor.
```json
{
  "config": { "name": "tcp-single", "enabled": true, "origin-ip": "127.0.0.1",
              "origin-port": 18001, "dest-ip": "127.0.0.1", "dest-port": 28001,
              "protocol": "tcp", "load_balancing": { "algorithm": "round-robin" } },
  "yaml": "name: tcp-single\nenabled: true\n..."
}
```

### `POST /api/proxies` (scope `*`)
Create a new proxy. The body is a proxy config (YAML **or** JSON — YAML is a JSON
superset, both parse). The config is validated, written to
`{proxies_dir}/{name}.yaml`, and started if `enabled: true`.

Request body (YAML):
```yaml
name: "api-created"
enabled: true
origin-ip: "127.0.0.1"
origin-port: 18060
dest-ip: "10.0.0.1, 10.0.0.2"
dest-port: 28001
protocol: "tcp"
load_balancing:
  algorithm: "least-conn"
```
Response `201`:
```json
{ "status": "created", "name": "api-created", "running": true, "config_path": "configs/proxies/api-created.yaml" }
```
Errors: `400` invalid config (validation message included), `409` name already exists.

### `POST /api/proxies/validate` (scope `*`)
Validate a config body without applying it. Never `400`s on a bad config —
returns the verdict in the body so a UI can show inline errors.
```json
{ "valid": false, "error": "configs/<api>: proxy.origin-port: at least one origin port must be specified" }
```

### `PUT /api/proxies/{name}` (scope `*`)
Replace a proxy's config (body = full config). The `name` in the body must match
the URL. The on-disk file is overwritten and the proxy is restarted (or stopped
if the new config is `enabled: false`).
```json
{ "status": "updated", "name": "api-created", "running": true }
```

### `DELETE /api/proxies/{name}` (scope `*`)
Stops the proxy and removes its config file.
```json
{ "status": "deleted", "name": "api-created" }
```

### Lifecycle: enable / disable / reload (scope `*`)

| Endpoint | Effect |
| -------- | ------ |
| `POST /api/proxies/{name}/enable` | Sets `enabled: true` in the file **and** starts the proxy |
| `POST /api/proxies/{name}/disable` | Sets `enabled: false` in the file **and** stops the proxy (no traffic) |
| `POST /api/proxies/{name}/reload` | Re-reads the config from disk and restarts the proxy |

```json
{ "status": "enabled", "name": "api-created" }
```

> All three persist to disk, so state survives a RouteX restart.

---

## Connections

### `GET /api/proxies/{name}/connections`
Live connection table.
```json
[
  { "id": 42, "src_ip": "1.2.3.4", "src_port": 51234,
    "upstream": "10.0.0.1", "upstream_port": 25565,
    "bytes_in": 1820, "bytes_out": 90233,
    "started_at": "2026-06-30T05:53:54Z", "closed": false }
]
```

### `DELETE /api/proxies/{name}/connections/{id}` (scope `*`)
Force-closes a single connection.
```json
{ "status": "killed" }
```

---

## Upstreams

### `GET /api/proxies/{name}/upstreams`
```json
[
  { "IP": "10.0.0.1", "Port": 25565, "Weight": 3, "Healthy": true,
    "ActiveConns": 4, "TotalConns": 980, "FailCount": 0 }
]
```

### `POST /api/proxies/{name}/upstreams/{ip}/eject` / `.../readmit` (scope `*`)
Force an upstream (all its ports) unhealthy or healthy.
```json
{ "status": "ejected", "targets_affected": 1 }
```

---

## ACL (whitelist / blacklist)

ACLs are CIDR allow/deny lists evaluated in order (first match wins) with a
configurable default action. They apply live — no restart. Global rules compose
with per-proxy rules (a global `deny` always wins).

### `GET /api/acl/global`
```json
{ "enabled": true, "default_action": "allow",
  "rules": [ { "action": "deny", "cidr": "1.2.3.0/24", "comment": "bad net" } ],
  "stats": { "allowed": 9120, "denied": 14 } }
```

### `POST /api/acl/global/rules` (body = rule)
```json
{ "action": "deny", "cidr": "1.2.3.4/32", "comment": "abuse" }
```
→ `{ "status": "added" }`

### `DELETE /api/acl/global/rules?cidr=1.2.3.4/32`
→ `{ "removed": 1 }`

### `PUT /api/acl/global/rules` (body = array of rules)
Atomically replaces the rule set. → `{ "count": 3 }`

### Per-proxy equivalents
`GET/POST/DELETE/PUT /api/acl/proxy/{name}[/rules]` — same shapes, scoped to one proxy.

---

## L7 protection

### `GET /api/proxies/{name}/l7`
L7 config + live counters.
```json
{ "name": "l7-minecraft", "enabled": true,
  "config": { "enabled": true, "payload_inspection": { "enabled": true, "mode": "minecraft-java" } },
  "blocked_connections": 12, "banned_ips": 1 }
```

### `GET /api/l7/banned`
```json
[ { "ip": "1.2.3.4", "reason": "behavioral threshold exceeded" } ]
```

### `POST /api/l7/banned/{ip}?duration=10m`
Manually ban an IP across all L7 engines (default duration 1h). → `{ "status": "banned" }`

### `DELETE /api/l7/banned/{ip}`
→ `{ "status": "unbanned" }`

### `GET /api/l7/events?limit=100`
Recent block/ban events for an attack feed.
```json
[ { "time": "2026-06-30T10:36:44Z", "ip": "1.2.3.4", "event_type": "invalid_protocol",
    "score": 30, "action": "blocked", "reason": "payload failed protocol inspection" } ]
```

---

## Rate limits (L3/L4)

### `GET /api/proxies/{name}/ratelimits`
Returns the configured iptables-backed rate-limit block (YAML field names).
```json
{ "name": "minecraft-main",
  "rate_limits": { "tcp_pps_per_ip": 500, "udp_pps_per_ip": 1000,
                   "new_conns_per_sec_per_ip": 20, "max_simultaneous_conns_per_ip": 10,
                   "tcp_syn_rate_per_ip": 10, "drop_fragmented_packets": true } }
```
> Rate limits are changed by editing the proxy config (`PUT /api/proxies/{name}`)
> and are (re)applied to iptables on start/reload.

---

## Bandwidth

### `GET /api/bandwidth/proxy/{name}` (scope `metrics:read`)
```json
{ "name": "bandwidth-limited", "inbound_bytes": 1200, "outbound_bytes": 1207,
  "total_bytes": 2407, "suspended": true,
  "quota": { "hourly": 1024, "daily": 0, "weekly": 0, "monthly": 0 },
  "hourly_used": 2407, "hourly_percent": 235.05, "daily_used": 2407 }
```
When a quota is exceeded, `suspended` flips to `true` and the proxy refuses all
new traffic until the window resets (or `reset` is called).

### `POST /api/bandwidth/proxy/{name}/reset` (scope `metrics:read`)
Clears counters and the suspended flag. → `{ "status": "reset" }`

---

## iptables (scope `*`)

| Endpoint | Purpose |
| -------- | ------- |
| `GET /api/iptables/rules` | List all `RouteX-Rate-Limit-*` rules |
| `POST /api/iptables/validate` | Dry-run validate a rate-limit block |
| `POST /api/iptables/flush/{proxy}` | Flush + recreate a proxy's rules |
| `POST /api/iptables/orphan-sweep` | Remove rules with no owning proxy |

> Requires RouteX to run with `CAP_NET_ADMIN` and `iptables.enabled: true`.

---

## Metrics (scope `metrics:read`)

`GET /metrics` and `GET /metrics/proxy/{name}` support a `?format=` selector for
plugging into any dashboard/TSDB:

| `format` | Output |
| -------- | ------ |
| `json` (default) | JSON object |
| `prometheus` | Prometheus exposition format (`routex_*`) |
| `influx` | InfluxDB line protocol |
| `csv` | CSV |

Example: `GET /metrics?format=prometheus`
```
# TYPE routex_active_connections gauge
routex_active_connections 5
# TYPE routex_proxy_bytes_in counter
routex_proxy_bytes_in{proxy="minecraft-main"} 9123847
```

---

## Reload all

### `POST /api/reload` (scope `*`)
Re-scans the proxies directory: starts new/enabled proxies, stops disabled ones,
and stops any running proxy whose config file was removed.
```json
{ "status": "reloaded", "started": 10, "stopped": 0, "failed": 0, "errors": null }
```

---

## Hot reload

RouteX watches the global config file and the proxies directory with `fsnotify`
(200 ms debounce). Changes apply **without restarting** RouteX:

| Action on disk | Result |
| -------------- | ------ |
| Add `proxies/foo.yaml` (`enabled: true`) | Proxy `foo` starts automatically |
| Edit `proxies/foo.yaml` | Proxy `foo` is reloaded with the new config |
| Set `enabled: false` in `proxies/foo.yaml` | Proxy `foo` stops |
| Delete `proxies/foo.yaml` | Proxy `foo` stops |

The REST mutation endpoints write the same files, so the API and hand-edits stay
consistent. Editing the **global** config still requires a restart.

> Note: a config change triggers a brief proxy restart, so existing connections
> on that proxy are reset (standard reverse-proxy reload behavior).

---

## Building a dashboard

A typical dashboard polling loop:

1. `GET /api/overview` every few seconds for the landing page (totals + per-proxy cards).
2. `GET /api/stats/proxy/{name}/history?hours=24` to draw traffic/connection graphs.
3. `GET /api/proxies/{name}/connections` for a live connection table.
4. `GET /api/l7/events` for an attack/security feed; `GET /api/l7/banned` for the ban list.
5. `GET /api/proxies/{name}/upstreams` for backend health indicators.
6. Management actions via the `POST`/`PUT`/`DELETE` endpoints (create networks,
   toggle proxies, ban IPs, edit ACLs).

Issue a low-privilege `proxies:read` + `metrics:read` key to the browser/dashboard
and reserve `*` keys for server-side administrative actions.
