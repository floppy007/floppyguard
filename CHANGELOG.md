# Changelog

All notable changes to FloppyGuard are documented here.
This project diverges from upstream nginx-proxy-manager starting at v1.0.0.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.3.1] – 2026-05-09

### Added

- **WireGuard Peer CRUD** — delete button on every link card with confirmation modal; removes peer from live interface, config file and metadata; creates safety backup before deletion; `POST /api/wireguard/update-peer` for live AllowedIPs changes with automatic hub sync
- **WireGuard Interface CRUD** — create new interfaces (wg2, wg3, …) with auto-generated keypair, address and listen port; delete non-hub interfaces with confirmation modal; `wg-quick up/down` and `systemctl enable/disable` handled automatically
- **Interface selector** — tunnel creation form and header now show an interface dropdown when multiple interfaces exist (was hardcoded to wg0)
- **Live-vs-conf drift detection** — `syncHubConf` now compares the running WireGuard interface against the config file and corrects any discrepancies automatically

### Fixed

- **AllowedIPs stripped on sync** — `_buildPeerUpdates` removed non-host networks from peers when `importedNetworks` was empty in metadata; now preserves existing AllowedIPs from the config file when metadata has no override
- **WireGuard nav icon** — replaced wide text logo SVG (1874×333) with shield-only icon; nav item now renders at correct 16×16 size
- **Interface card layout** — consistent vertical layout with fixed button position at bottom, all info rows always visible
- **CI lint errors** — fixed all `useOptionalChain` and `noParameterAssign` errors across backend

---

## [1.3.0] – 2026-05-06

### Added

- **WireGuard tunnel creation** — new "Neuer Tunnel" button on WireGuard page; creates peer with keypair, auto-assigns tunnel IP, generates downloadable client config
- **Tunnel configuration options** — name, type (client/site-to-site/hub-link), DNS servers, platform (desktop/mobile), full tunnel toggle, custom AllowedIPs
- **Platform-aware AllowedIPs** — desktop uses `/1`-split routing (no routing loop), mobile uses `0.0.0.0/0` (OS VPN tunnel flag)
- **DNS/nameserver config** — configurable per interface and per link; falls back to `WG_DNS` env variable; written into `[Interface] DNS =` of generated peer configs
- **DonutGauge component** — SVG ring gauge for stat cards showing ratios (e.g. 10/12 active)
- **PeerSparkline component** — mini bandwidth sparkline chart per peer connection
- **Chart legends** — bandwidth charts show peer name + color + current rate

### Changed

- **Dashboard redesign** — stat cards with donut gauges, peer link preview with sparklines and scroll, higher bandwidth charts
- **Traffic page redesign** — donut stat cards, per-peer sparkline column in link table
- **Header redesign** — compact 56px glassmorphism header, pill-style nav links, Light/Dark pill toggle, avatar with initials
- **CSS simplification** — removed heavy body gradients, grid overlays, pseudo-element decorations; cards use `backdrop-filter: blur` and `color-mix`

### Fixed

- Bandwidth charts starting in the middle when history is incomplete (left-padded with zeros)
- Nav link active state not visible (Tabler CSS specificity override)

---

## [1.2.3] – 2026-05-04

### Fixed

- **Certificate renewal (HTTP challenge)** — `certbot renew` replaced with `certonly --force-renewal`; added missing `--webroot-path` and `--non-interactive` flags; uses virtualenv certbot at `/opt/certbot/bin/certbot` instead of system binary (which lacks DNS plugins)
- **Certificate renewal (DNS challenge)** — fixed "unrecognized arguments" error by switching from `--authenticator dns-cloudflare` to `--dns-cloudflare`; credentials are now fetched directly from the database (bypassing the `omissions()` security filter that strips them from API responses)
- **Certbot versioned lineage** — added `clearCertDirsForRenewal()` helper that removes `archive/`, `live/` and `renewal/` entries for a certificate before `certonly`, preventing certbot from creating suffixed lineages like `npm-116-0001` instead of `npm-116`
- **New certificate request (DNS challenge)** — fixed same `--authenticator` → `--<plugin>` flag for initial issuance
- **Modal header alignment** — fixed tab nav being pushed down in Redirection Host, Proxy Host, Dead Host and Stream modals; adjusted card-header padding and removed double-rendered `<Alert>` (replaced `show={!!errorMsg}` with conditional rendering)

### Changed

- Scripts (`check-production-routes`, `start-production`, `status-production`) — replaced hardcoded external URL default with `http://127.0.0.1:81`

### Added

- `ROADMAP.md` — documents planned DNS auto-provisioning feature (Cloudflare + IPv64)

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
