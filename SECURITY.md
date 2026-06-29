# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Active development |

## Reporting a Vulnerability

**Do not open a public issue.** Please report security vulnerabilities privately:

1. Email: security@pingless.org (PGP key available on request)
2. Discord: DM `anavgbeing` in the [PingLess Studios Discord](https://discord.gg/qgBMREWWgp)

We aim to respond within 48 hours and provide a fix timeline within 72 hours.

## Security Model

RouteX operates as a reverse proxy with kernel-level (iptables) and application-level (Go) defenses. Security considerations:

- **iptables rules** require `CAP_NET_ADMIN` — the systemd service file grants this automatically
- **API keys** are stored in YAML config files — restrict file permissions appropriately
- **TLS** for the management API is supported via `api.tls` config
- **TLS passthrough** for proxy traffic forwards encrypted bytes without inspection
- **L7 engine** runs in-process with no external dependencies
- **ACL system** supports global + per-proxy whitelist/blacklist

## Best Practices

- Use strong, unique API keys
- Enable TLS on the management API if exposed to networks
- Regularly review iptables orphan rules via `POST /api/iptables/orphan-sweep`
- Monitor L7 events via `/api/l7/events` for attack patterns
- Set bandwidth quotas to prevent unexpected overages
