# Changelog

All notable changes to FloppyGuard are documented here.
This project diverges from upstream nginx-proxy-manager starting at v1.0.0.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.2.2] – 2026-05-04

### Added

- **WireGuard routing automation** — `syncHubConf()` rewrites hub `wg0.conf` AllowedIPs and
  PostUp/PostDown ip-route commands from metadata on every UI apply; applies live via `wg set` +
  `ip route add` without restarting wg0
- **Agent config sync** — `syncAgentConfigs()` updates every connected agent's WireGuard peer
  AllowedIPs so all sites can reach each other through the hub; agents pick up changes on their
  next 30 s poll; both syncs fire automatically on `metadata-with-config-intent` apply
- **Agent self-update** — `AGENT_SCRIPT_VERSION` constant tracks the loop-script version; agents
  compare their local version on every config poll and self-update automatically via
  `GET /api/agent/loop-script` + `exec` — no token reset or manual reinstall required
- **`sync_routes()` in agent loop script** — adds missing kernel ip routes after `wg syncconf`
  (which updates WireGuard peer tables but never touches the kernel routing table); runs on every
  config change and once at startup
- **Full multilanguage UI (EN / DE / FR)** — all user-visible strings in WireGuard, Dashboard,
  Platform, Gateway and Fail2Ban sections are now translated; topology labels, badge labels,
  table headers, editors, planners, stat cards, empty states and backend warning codes all go
  through the i18n system
- **Agent duplicate-link guard** — `create` and `update` reject `wg_link_name` when more than one
  link shares that name; `syncAgentConfigs` skips ambiguous agents with a warning; plan preview
  reports a validation error on duplicate link names

### Changed

- WireGuard apply response now includes `hubSync` and `agentSync` result fields
- UI shows live sync feedback after apply: hub peer count updated, agent names synced, or warnings on error
- GitHub Actions CI pipeline added (lint, test, build)
- Install script added (`scripts/install`) for host-based deployment
- Docker dev stack removed (will be rebuilt as a proper feature)
- Remaining NPM leftovers removed, package fully renamed to `floppyguard`

---

## [1.2.1] – 2026-05-03

First public release of FloppyGuard, forked from nginx-proxy-manager v2.14.0.

### Added

- **WireGuard management** — interface, peer and link CRUD with live status polling; visual
  topology map (hub / site / client nodes, link edges); planning layer with discover → shape →
  validate → ready stages; dry-run plan preview; one-step apply and restore
- **Remote agent system** — native Linux agent with curl-based install one-liner and automatic
  token registration; UniFi-compatible mode; service discovery across registered agents
- **Platform dashboard** — combined home page with proxy stats, WireGuard summary, gateway
  overview and Fail2Ban status; Fail2Ban UI with jail list, banned IPs and one-click unban
- **Gateway page** — reachability map, private route inventory, peer network inventory, routing
  hints (missing return routes, NAT candidates, observations)
- **Security hardening** — nftables firewall with strict INPUT policy; fail2ban jails for API
  auth brute-force, admin bot scans and SSH

### Changed

- Merged Platform and Dashboard pages into a single home page (`/`), removed standalone `/platform` route
- WireGuard planner: removed mandatory preview step before saving
- Footer: copyright Florian Hesse | Comnic-IT with version number
- Dark mode: fixed missing `--tblr-bg-surface-rgb` CSS variables
- Package name changed to `floppyguard`, author updated to Florian Hesse

### Base (upstream nginx-proxy-manager v2.14.0)

- Proxy hosts, redirection hosts, streams, 404/dead hosts
- Let's Encrypt certificates via certbot (HTTP and DNS challenge)
- DNS challenge integrations: Cloudflare, dns-multi (ipv64, name.com, etc.)
- Access lists with HTTP Basic Auth
- Multiple users with role-based permissions
- Audit log
- React 19 + Vite frontend, Express.js backend, Objection.js ORM

---

## [1.2.0] – 2026-02-17

### Added

- **WireGuard management page** — visual topology map showing hub, site and client nodes with
  link edges; interface and peer status from live `wg show` output; link metadata editor and
  planner

---

## [1.1.0] – 2025-11-11

### Added

- **Remote agent system** — agent registration with token-based authentication; install
  one-liner generator; token reset and agent management UI

---

## [1.0.0] – 2025-10-14

Initial fork of nginx-proxy-manager v2.14.0.

---

*nginx-proxy-manager v2.14.0 by [Jamie Curnow](https://github.com/jc21) — MIT License*
