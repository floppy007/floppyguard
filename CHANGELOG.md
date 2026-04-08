# Changelog

All notable changes to FloppyGuard are documented here.

## [1.2.1] – 2026-05-03

### Added
- **WireGuard management** – interface, peer and link CRUD with visual topology map
- **Planning layer** – links progress through discover → shape → validate → ready stages
- **Remote agent system** – native Linux agent and UniFi-compatible mode for applying configs to remote hosts
- **Agent install one-liner** – `curl | bash` install flow with automatic token registration
- **Platform dashboard** – combined home page: proxy stats, WireGuard summary, gateway overview, fail2ban status
- **Fail2Ban UI** – view jails, banned IPs and unban directly from the dashboard
- **nftables firewall** – strict INPUT policy, only required ports open (22, 80, 443, 81, 51821/UDP, 3300 from WireGuard only)
- **fail2ban hardening** – custom jails for API auth, admin bot scans and SSH

### Changed
- Merged Platform and Dashboard pages into a single home page
- Removed standalone `/agents` and `/platform` routes
- WireGuard planner: removed mandatory preview step before saving
- Footer: copyright Florian Hesse | Comnic-IT, version number
- Dark mode: fixed missing `--tblr-bg-surface-rgb` CSS variables (all backgrounds now render correctly)
- Version bumped to 1.2.1 (diverges from upstream nginx-proxy-manager versioning)

### Base
- Forked from **nginx-proxy-manager v2.14.0** by Jamie Curnow
