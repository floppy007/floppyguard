<p align="center">
  <img src="frontend/public/images/floppyguard-logo.png" alt="FloppyGuard" width="280" />
</p>

# FloppyGuard

> Nginx reverse proxy manager with integrated WireGuard VPN management, a visual topology map, remote agent support and a hardened host-based runtime.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.2.2-blue.svg)](CHANGELOG.md)
[![CI](https://github.com/floppy007/floppyguard/actions/workflows/ci.yml/badge.svg)](https://github.com/floppy007/floppyguard/actions/workflows/ci.yml)

---

## Features

**Inherited from nginx-proxy-manager**
- Proxy hosts, redirection hosts, streams, 404/dead hosts
- Let's Encrypt certificates (HTTP + DNS challenge)
- Access lists, multiple users, audit log

**Added by FloppyGuard**
- WireGuard interface, peer and link management with visual topology map
- Planning layer: links go through discover → shape → validate → ready stages
- Remote agent system — push WireGuard configs to remote hosts (native Linux + UniFi-compatible mode)
- Platform dashboard — proxy stats, WireGuard summary, gateway overview, fail2ban status in one view
- Fail2Ban UI — view jails and banned IPs, unban with one click
- nftables firewall hardening (strict INPUT policy, only required ports open)
- Dark mode with correct CSS variable handling

---

## Architecture

FloppyGuard runs **host-based** — no Docker container for the application itself.

```
Internet → nginx (80/443) → proxy host configs in /data/nginx/
                          → port 81 (admin UI)

Port 81   nginx serves frontend/dist (SPA) → /api/ → backend :3300
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
- Node.js 20+ and Yarn
- nginx (system package)
- WireGuard tools (`wireguard-tools`)
- nftables
- fail2ban (optional but recommended)
- MySQL, PostgreSQL, or SQLite

### Quick install

```bash
curl -fsSL https://raw.githubusercontent.com/floppy007/floppyguard/develop/scripts/install.sh | bash
```

The script will:
1. Check and install missing prerequisites
2. Clone the repository to `/opt/floppyguard`
3. Install Node.js dependencies and build the frontend
4. Create the systemd unit `floppyguard-backend`
5. Write an nginx site config for the admin UI (port 81)
6. Generate an `.env` file for DB configuration

### Manual installation

```bash
# 1. Clone
git clone https://github.com/floppy007/floppyguard.git /opt/floppyguard
cd /opt/floppyguard

# 2. Install dependencies
cd backend && yarn install --frozen-lockfile && cd ..
cd frontend && yarn install --frozen-lockfile && yarn build && cd ..

# 3. Configure environment
cp backend/.env.example backend/.env
# Edit backend/.env — set DB_MYSQL_* or DB_SQLITE_FILE

# 4. Create data directory
mkdir -p /data/nginx /opt/npm/letsencrypt

# 5. Install systemd service
cp docs/examples/floppyguard-backend.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now floppyguard-backend

# 6. Configure nginx
cp docs/examples/floppyguard-nginx.conf /etc/nginx/sites-available/floppyguard
ln -s /etc/nginx/sites-available/floppyguard /etc/nginx/sites-enabled/
nginx -t && nginx -s reload
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `DB_SQLITE_FILE` | `/data/database.sqlite` | SQLite file path (use if not MySQL/PG) |
| `DB_MYSQL_HOST` | — | MySQL host |
| `DB_MYSQL_PORT` | `3306` | MySQL port |
| `DB_MYSQL_USER` | — | MySQL user |
| `DB_MYSQL_PASSWORD` | — | MySQL password |
| `DB_MYSQL_NAME` | — | MySQL database name |
| `DB_POSTGRES_HOST` | — | PostgreSQL host |
| `DB_POSTGRES_PORT` | `5432` | PostgreSQL port |
| `DB_POSTGRES_USER` | — | PostgreSQL user |
| `DB_POSTGRES_PASSWORD` | — | PostgreSQL password |
| `DB_POSTGRES_NAME` | — | PostgreSQL database name |
| `WG_CONF_DIR` | `/etc/wireguard` | WireGuard config directory |
| `PORT` | `3300` | Backend listen port |

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

---

## Development

### Prerequisites

- Node.js 20+ and Yarn
- Docker + Docker Compose (for the full dev stack)

### Backend

```bash
cd backend
yarn install
yarn dev        # nodemon auto-restart
yarn lint       # Biome linting
yarn test       # Node built-in tests
```

### Frontend

```bash
cd frontend
yarn install
yarn dev        # Vite dev server → http://localhost:5173
yarn build      # TypeScript check + production build → dist/
yarn lint       # Biome linting
yarn test       # Vitest
```

### Full dev stack (Docker)

> Docker support is planned but not yet available. FloppyGuard currently runs host-based only.

---

## Project structure

```
backend/          Express.js API (Node 18+, ES modules)
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

MIT — see [LICENSE](LICENSE).

FloppyGuard © Florian Hesse, [Comnic-IT](https://comnic-it.de).
Built on top of [nginx-proxy-manager](https://github.com/NginxProxyManager/nginx-proxy-manager) by Jamie Curnow (MIT).
