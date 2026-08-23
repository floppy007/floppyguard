<p align="center">
  <img src="frontend/public/images/floppyguard-logo.png" alt="FloppyGuard" width="280" />
</p>

# FloppyGuard

> Nginx reverse proxy manager with integrated WireGuard VPN management, a visual topology map, remote agent support and a hardened host-based runtime.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.1-blue.svg)](CHANGELOG.md)
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
- Remote agent system - push WireGuard configs to remote hosts (native Linux + UniFi-compatible mode)
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
