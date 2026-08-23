# FloppyGuard Roadmap

Last updated: 2026-08-23

This is the public roadmap overview. The maintained technical implementation status and operational backlog are in [docs/TECHNICAL_ROADMAP.md](docs/TECHNICAL_ROADMAP.md).

## Recently shipped

- **v2.0.0 — Controlled application updates.** Administrators see available releases in the dashboard and can deliberately start an update from the approved Git branch. The update path uses only fast-forward merges, never discards local changes, and reports progress in the application.
- **v2.0.0 — Cloudflare DNS synchronization.** Proxy Hosts can manage their A and AAAA records automatically, including the Cloudflare proxy state. Credentials come from the selected Cloudflare DNS certificate or an optional global token. Manually managed and wildcard records are not changed.
- **v2.0.0 — Proxy Host editor improvements.** The Advanced section has clear spacing, and Custom Nginx Configuration reliably displays content, supports line numbers, and can be focused through its label.
- **v1.3.22–v1.3.26 — Security and reliability hardening.** Confirmed injection, privilege, routing, configuration, and endpoint-propagation issues were fixed. Agent and WireGuard regression coverage was expanded.
- **v1.3.21 and earlier — WireGuard platform.** Peer and interface CRUD, hub-to-agent synchronization, routing automation, Agent self-update, network ACLs, configuration export, QR enrollment, platform capabilities, and the audit log are available.

## Next priorities

### Operations and observability

- Monitoring dashboard or metrics endpoint for Prometheus/Grafana
- Alerting for missing agent heartbeats and WireGuard handshakes
- Full database backup before a WireGuard plan apply; metadata backups already exist
- Expand the audit-log UI with WireGuard-specific filters and apply context

### Quality

- Modernize the separate Cypress E2E and lint dependency chain without changing the production toolchain
- Add regression tests for production incidents as they are resolved

### DNS automation

- Cloudflare A/AAAA record synchronization is complete
- IPv64 provider support remains planned
- Optional cleanup of FloppyGuard-managed records on host deletion remains planned

## Planned features

- **Internal DNS aliases:** friendly service names for WireGuard networks
- **Service health checks:** active health and latency reporting for discovered services
- **Long-term bandwidth metrics:** persisted daily and weekly history instead of only the short ring buffer
- **Zero-touch enrollment:** a new peer receives an ID and secret, then securely retrieves its configuration from the hub
- **Docker deployment support:** a supported Compose-based deployment option alongside the host installer
- **Access-list improvements:** richer per-host allow/deny policy and optional WireGuard integration

## Related GitHub issues

- [#1 — DNS Auto-Provisioning](https://github.com/floppy007/floppyguard/issues/1) — Cloudflare is complete; IPv64 remains open
- [#3 — Tunnel Failure Alerting](https://github.com/floppy007/floppyguard/issues/3)
- [#4 — Long-term Bandwidth Metrics](https://github.com/floppy007/floppyguard/issues/4)
- [#5 — Zero-Touch Enrollment](https://github.com/floppy007/floppyguard/issues/5)
- [#6 — Docker Deployment Support](https://github.com/floppy007/floppyguard/issues/6)
