<p align="center">
  <img src="frontend/public/images/floppyguard-logo.png" alt="FloppyGuard" width="280" />
</p>

# FloppyGuard

> Nginx reverse proxy manager with integrated WireGuard VPN management, a visual topology map, remote agent support and a hardened host-based runtime.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.5.0-blue.svg)](CHANGELOG.md)
[![CI](https://github.com/floppy007/floppyguard/actions/workflows/ci.yml/badge.svg)](https://github.com/floppy007/floppyguard/actions/workflows/ci.yml)

---

## What FloppyGuard is for

FloppyGuard is a self-hosted operations platform for administrators who run web services and WireGuard-connected sites on their own Linux infrastructure. It combines reverse-proxy and certificate management with a central view of VPN links, routes, gateways, and remote agents.

Use it when you want one operational interface to publish services securely, manage a hub-and-spoke or site-to-site WireGuard network, and keep remote gateway configurations synchronized. It is designed for a trusted administrator-operated environment, not as a multi-tenant SaaS product or a replacement for a general-purpose network-management suite.

---

## Features

**Inherited from nginx-proxy-manager**
- Proxy hosts, redirection hosts, streams, 404/dead hosts
- Let's Encrypt certificates (HTTP + DNS challenge)
- Access lists, multiple users, audit log

**Added by FloppyGuard**
- WireGuard interface, peer and link management with visual topology map
- WireGuard tunnel creation from the UI - name, type, DNS, platform (desktop/mobile), full tunnel toggle
- WireGuard peer CRUD - create, update and delete peers live from the UI
- Peer config export with QR code for mobile enrollment
- DNS/nameserver auto-config per interface or link, with platform-aware AllowedIPs
- Road warrior peers auto-inherit all remote site networks in AllowedIPs
- Planning layer: links go through discover -> shape -> validate -> ready stages
- Remote agent system - push WireGuard configs to remote hosts
- Auto-MASQUERADE - cross-site LAN traffic gets NAT rules auto-generated and pushed to agents
- Live bandwidth monitoring with per-peer sparklines and donut gauges
- Platform dashboard - proxy stats, WireGuard summary, gateway overview, fail2ban status in one view
- Fail2Ban UI - view jails and banned IPs, unban with one click
- nftables firewall hardening (strict INPUT policy, only required ports open)
- Strict CIDR/IP validation on all WireGuard network inputs - network values flow into root-executed routing rules, so anything that is not a clean address/CIDR is rejected
- Multilanguage UI - English, German, French
- Dark mode with compact glassmorphism header and theme toggle
- Proxy Host advanced-config editor with visible input, line numbers and accessible label focus
- Optional Cloudflare DNS sync for Proxy Hosts: targeted A/AAAA records, per-host proxy mode, and safe coexistence with manual or wildcard records

---

## Architecture

FloppyGuard runs **host-based** - no Docker container for the application itself.

```
Internet -> nginx (80/443) -> proxy host configs in /data/nginx/
                          -> port 81 (admin UI)

Port 81   nginx serves frontend/dist (SPA) -> /api/ -> backend :3300
Port 3300 FloppyGuard backend (Node.js, systemd unit: floppyguard-backend)
```

- **Backend**: Express.js (`backend/index.js`), managed by systemd
- **Frontend**: React 19 + Vite, built to `frontend/dist`, served by nginx on port 81
- **Database**: MySQL, PostgreSQL or SQLite (configured via environment variables)
- **Nginx configs**: generated and written to `/data/nginx/`, loaded by system nginx
- **Certs**: Let's Encrypt via certbot, stored at `/opt/npm/letsencrypt/`

---

## Installation

### Prerequisites

- Debian 12/13 or Ubuntu 22.04+
- Node.js 22.22.2+ with npm 12.0.2 and Yarn 1.22.22
- nginx (system package)
- WireGuard tools (`wireguard-tools`)
- nftables
- fail2ban (optional but recommended)
- MySQL or PostgreSQL (SQLite for dev/testing)

### Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/floppy007/floppyguard/develop/scripts/install.sh | bash
```

The script will:
1. Check and install missing prerequisites
2. Clone the repository to `/var/www/floppyguard`
3. Install Node.js dependencies and build the frontend
4. Install the controlled application-updater (`scripts/update.sh`)
5. Create the systemd unit `floppyguard-backend`
6. Write an nginx config for the admin UI (port 81)
7. Set up environment variables for DB access

### Manual installation

```bash
# 1. Clone
git clone https://github.com/floppy007/floppyguard.git /var/www/floppyguard
cd /var/www/floppyguard

# 2. Install dependencies
corepack enable
npm install -g yarn@1.22.22
cd backend && yarn install --frozen-lockfile && cd ..
cd frontend && yarn install --frozen-lockfile && yarn build && cd ..

# 3. Create data directory
mkdir -p /data/nginx /opt/npm/letsencrypt

# 4. Install systemd service
cp docs/examples/floppyguard-backend.service /etc/systemd/system/
# Edit the service file - set DB_MYSQL_* environment variables
systemctl daemon-reload
systemctl enable --now floppyguard-backend

# 5. Configure nginx
cp docs/examples/floppyguard-nginx.conf /etc/nginx/conf.d/floppyguard.conf
nginx -t && nginx -s reload
```

### Environment variables

Set these in the systemd unit file (`/etc/systemd/system/floppyguard-backend.service`):

| Variable | Default | Description |
|---|---|---|
| `DB_MYSQL_HOST` | - | MySQL host |
| `DB_MYSQL_PORT` | `3306` | MySQL port |
| `DB_MYSQL_USER` | - | MySQL user |
| `DB_MYSQL_PASSWORD` | - | MySQL password |
| `DB_MYSQL_NAME` | - | MySQL database name |
| `DB_SQLITE_FILE` | - | SQLite file path (alternative to MySQL, for dev/testing) |
| `WG_CONF_DIR` | `/etc/wireguard` | WireGuard config directory |
| `WG_HUB_HOST` | OS hostname | Public domain or IP (IPv4, or bracketed/bare IPv6) for the WireGuard endpoint baked into peer and agent configs. The hub is authoritative: changing it re-propagates the endpoint to every agent on its next poll. |
| `WG_DNS` | - | Default DNS for peer configs (comma-separated) |
| `CLOUDFLARE_API_TOKEN` | - | Optional global Cloudflare token (`Zone:Read` + `DNS:Edit`) for Proxy Host DNS synchronization; a Cloudflare DNS-challenge certificate token takes precedence. |
| `CLOUDFLARE_DNS_IPV4` | detected public IPv4 | Optional explicit A-record target for Proxy Host DNS synchronization. |
| `CLOUDFLARE_DNS_IPV6` | detected public IPv6 | Optional explicit AAAA-record target for Proxy Host DNS synchronization. |
| `PORT` | `3300` | Backend listen port |
| `SITE_ISOLATION_NFT_FILE` | `/etc/nftables.d/floppyguard-sites.nft` | Boot copy of the site isolation table ("Standorte untereinander"), rewritten after every apply |
| `SITE_ISOLATION_BOOT_CONF` | `/etc/nftables.conf` | nftables boot config checked for the include of that file (warning `boot-include-missing`) |
| `SITE_ISOLATION_DISABLED` | - | `true` = the backend never touches the site isolation table |

### Cloudflare DNS synchronization

For a domain-specific Cloudflare token, create a **Let's Encrypt via DNS** certificate in **Certificates**, select **Cloudflare**, and enter the token in **Credentials**:

```ini
dns_cloudflare_api_token = YOUR_CLOUDFLARE_TOKEN
```

Select that certificate in the Proxy Host's **SSL** tab, then enable **Manage DNS records automatically** in its **Advanced** tab. The selected certificate's token is used for that host, so separate DNS certificates provide separate permissions per domain or certificate group. The token needs `Zone:Read` and `DNS:Edit` for the relevant Cloudflare zone. `CLOUDFLARE_API_TOKEN` is only the optional server-wide fallback.

FloppyGuard creates exact A and AAAA records from the host's public addresses (or `CLOUDFLARE_DNS_IPV4` / `CLOUDFLARE_DNS_IPV6`) and never overwrites wildcard or manually managed records. Enable **Proxy through Cloudflare** to use Cloudflare's orange-cloud proxy. In the Proxy Hosts table, a green Cloudflare icon means DNS sync is active without the proxy; an orange icon means the Cloudflare proxy is enabled.

---

## Operations

```bash
# Status
systemctl status floppyguard-backend

# Restart
systemctl restart floppyguard-backend

# Logs (live)
journalctl -u floppyguard-backend -f

# nginx
nginx -t && nginx -s reload

# Check all routes
./scripts/check-production-routes
```

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for the full runbook.

### Site isolation ("Standorte untereinander")

Pairs of sites that must not reach each other are set on the **Freigaben** page and enforced on the hub in a dedicated nftables table `inet floppyguard_sites` (forward hook, priority `filter - 10`, policy accept, only drop rules). The backend replaces that table atomically (`nft -c -f`, then `nft -f`) on start-up, after every change and whenever the WireGuard links or networks change. It never touches any other table.

The table lives in the kernel, so it survives a backend restart. It does **not** survive a reboot or `systemctl restart nftables`, because `/etc/nftables.conf` starts with `flush ruleset`. The backend therefore writes a boot copy to `/etc/nftables.d/floppyguard-sites.nft`; add this line at the **end** of `/etc/nftables.conf`, after the existing tables:

```
include "/etc/nftables.d/floppyguard-sites.nft"
```

The file starts with `table inet floppyguard_sites {}` + `delete table inet floppyguard_sites`, so it is valid right after `flush ruleset`. Create the directory and a valid empty table before adding the include, so the include never fails at boot even if the backend has not written the file yet:

```bash
mkdir -p /etc/nftables.d
[ -f /etc/nftables.d/floppyguard-sites.nft ] || printf 'table inet floppyguard_sites {}\n' > /etc/nftables.d/floppyguard-sites.nft
nft -c -f /etc/nftables.conf   # check only; never `nft -f` it at runtime (flush ruleset drops the WireGuard NAT)
```

Until the include is in place, the Freigaben page shows the warning "Nach einem Neustart des Hubs greift die Trennung erst wieder, wenn FloppyGuard läuft".

**Fail-safe behaviour:** a missing or unreadable view of the links never lifts a separation. Tunnel addresses fall back to the last known ones, a link that disappears keeps its last networks for one more apply, and if stored pairs exist but none of them matches a current site link, the previous table is kept and the page shows an error. IPv6 networks of a site are not covered (the table is IPv4 only) and are listed as a warning.

**Manual drop rules:** drop rules with `ip saddr`/`ip daddr` in *other* forward chains (for example a hand-written `ip saddr @site_x ip daddr @site_y drop` in `inet filter forward`) are detected and shown as "manuell getrennt" with the warning "Am Hub gibt es zusätzliche, manuell gesetzte Sperren außerhalb von FloppyGuard". The Freigaben tester reports them too. FloppyGuard cannot lift them: "Erlauben" only clears its own table.

**Cut-over from manual rules** (one step, in this order):

1. Deploy: run the frontend production build and restart the backend. The migration creates the empty `site_isolation` table, and start-up creates the empty table `inet floppyguard_sites` (policy accept, harmless).
2. On the Freigaben page, use **In FloppyGuard übernehmen** in the warning about manual blocks, or separate the pair in the matrix.
3. Check that the hub has the pair: `nft list table inet floppyguard_sites` shows two `counter drop` rules.
4. Only then remove the manual rules and sets from the live ruleset (`nft delete rule inet filter forward handle <n>`, `nft delete set inet filter <name>`) **and** from `/etc/nftables.conf`, and add the include above.
5. Reload the page: the warning about manual blocks is gone, and the pair shows "getrennt".

### Direct links between sites ("Direktverbindungen")

Two site agents can talk to each other through their own WireGuard tunnel instead of through the hub; the hub stays the configuration source and the automatic fallback. Set them up on the **Freigaben** page: site A listens (fixed public IP, UDP port forward on its router to the agent's LAN address, set up on the router itself), site B dials A's address. Agents from script 1.6.0 on generate the key themselves and report only the public key.

- Interface `fgd<id>`, transfer net = a private /30 of its own.
- The partner's networks go into routing table `52000+id`, looked up by `ip rule pref 31000` before the main table. The agent fills it only while the link is healthy (handshake younger than 180 s and ping to the partner's tunnel address, every 10 s); after 3 failed checks the table is emptied and the hub routes on `wgN` carry the traffic, after 3 successful checks it switches back. The hub routes themselves are never changed.
- Each side routes the networks it reaches through the hub today (same ACL) that the partner exports. NAT stays as on the hub path; tick "maskiert ausgehend" for a site that masquerades into the hub tunnel today.
- The Freigaben (`FG_IN`) cover the direct interfaces too; a restricted gateway keeps a direct interface down while its filter does not cover it. Separated sites ("Standorte untereinander") never get an active direct link.
- Install `conntrack` on the gateways so NATed flows survive a path switch; `ping` is required for the health check.

**Way back:** switch the link off (or delete it): both agents take the tunnel down on their next poll and all traffic goes through the hub again.

### Application updates

Administrators see an available FloppyGuard release on the dashboard and in **Settings → Application update**. Starting an update always requires an explicit confirmation. The updater fetches only the configured branch of the approved `floppy007/floppyguard` repository, performs a fast-forward merge (never a reset), installs both committed Yarn lockfiles, builds the frontend, restarts the backend and verifies its local health endpoint.

The progress is displayed in the Settings page and persisted in `/var/lib/floppyguard/update-status.json`; the detailed log is `/var/lib/floppyguard/update.log`. If local Git changes prevent a safe fast-forward merge, the updater stops without discarding them.

---

## Development

### Prerequisites

- Node.js 22.22.2+ with npm 12.0.2 and Yarn 1.22.22
- MySQL (or SQLite for quick local dev)

### Backend

```bash
cd backend
yarn install
node index.js   # start backend (or use systemd)
npx biome lint .  # Biome linting
node --test internal/*.test.js  # unit tests
```

### Frontend

```bash
cd frontend
yarn install
yarn dev        # Vite dev server -> http://localhost:5173
yarn build      # TypeScript check + production build -> dist/
npx biome lint .  # Biome linting
npx vitest run  # unit tests
```

---

## Project structure

```
backend/          Express.js API (Node 22+, ES modules)
frontend/         React 19 + TypeScript + Vite
scripts/          Operational scripts (install, start, stop, check)
docs/             VitePress documentation + architecture notes
test/             Cypress E2E + Vacuum OpenAPI contract tests
```

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

---

## License

AGPL-3.0 - see [LICENSE](LICENSE).

**Additional Term (§7 AGPL-3.0):** Any deployment of this software over a network must retain a visible "Powered by FloppyGuard" notice with a link to this repository in the UI footer.

FloppyGuard © Florian Hesse, [Comnic-IT](https://comnic-it.de).
Built on top of [nginx-proxy-manager](https://github.com/NginxProxyManager/nginx-proxy-manager) by Jamie Curnow (MIT).
