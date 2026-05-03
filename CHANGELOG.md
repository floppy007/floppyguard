# Changelog

All notable changes to FloppyGuard are documented here.
This project diverges from upstream nginx-proxy-manager starting at v1.2.1.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.2.1] – 2026-05-03

First public release of FloppyGuard, forked from nginx-proxy-manager v2.14.0.

### Added

**WireGuard management**
- Interface, peer and link CRUD with live status polling
- Visual topology map (hub / site / client nodes, link edges)
- Planning layer: links progress through discover → shape → validate → ready stages
- Dry-run plan preview before applying changes
- Plan apply and one-step restore

**Remote agent system**
- Native Linux agent (curl-based install one-liner with automatic token registration)
- UniFi-compatible mode (targets UniFi gateway-style API)
- Service discovery across registered agents

**Platform dashboard**
- Combined home page: proxy stats, WireGuard summary, gateway overview, fail2ban status
- Fail2Ban UI — view jails, banned IPs and unban with one click

**Security hardening**
- nftables firewall: strict INPUT policy, only required ports open (22, 80, 443, 81, 51820/UDP, 3300 from WireGuard only)
- fail2ban jails for API auth brute-force, admin bot scans and SSH

### Changed
- Merged Platform and Dashboard pages into a single home page (`/`)
- Removed standalone `/platform` route
- WireGuard planner: removed mandatory preview step before saving
- Footer: copyright Florian Hesse | Comnic-IT with version number
- Dark mode: fixed missing `--tblr-bg-surface-rgb` CSS variables — all card/panel backgrounds now render correctly in dark mode
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

*nginx-proxy-manager v2.14.0 by [Jamie Curnow](https://github.com/jc21) — MIT License*
