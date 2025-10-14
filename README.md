# FloppyGuard

Fork of [nginx-proxy-manager](https://github.com/NginxProxyManager/nginx-proxy-manager) v2.14.0, extended with WireGuard VPN management.

Running host-based (no Docker for the app itself) on this server.

## Architecture

```
https://your-instance-domain  →  nginx (80/443)  →  proxy_host/58.conf
                                                   →  port 81 (admin UI)

Port 81  — nginx serves frontend/dist (SPA)        →  /api/ → backend :3300
Port 3300 — FloppyGuard backend (Node.js, systemd)
Port 8080 — wg-gui (legacy, being replaced)
```

- **Backend**: Express.js, `backend/index.js`, managed by systemd
- **Frontend**: React 19 + Vite, built to `frontend/dist`, served by nginx on port 81
- **Database**: MySQL (`npm`/`npm` @ localhost:3306, same DB as legacy NPM)
- **Nginx configs**: written to `/data/nginx/`, loaded by system nginx
- **Certs**: Let's Encrypt via certbot virtualenv at `/opt/certbot/`, certs at `/opt/npm/letsencrypt/`

## Production Operations

```bash
# Status
systemctl status floppyguard-backend

# Restart
systemctl restart floppyguard-backend

# Logs (live)
journalctl -u floppyguard-backend -f

# nginx
nginx -t && nginx -s reload
```

See [docs/OPERATIONS.md](docs/OPERATIONS.md) for the full runbook.

## Development

### Backend (`cd backend`)
```bash
yarn lint          # Biome linting
yarn prettier      # Biome format --write
yarn test          # Node built-in tests
```

### Frontend (`cd frontend`)
```bash
yarn dev           # Vite dev server (port 5173)
yarn build         # TypeScript check + production build → dist/
yarn lint          # Biome linting
yarn test          # Vitest
```

### Local Preview
```bash
./scripts/start-local-preview   # boots backend + Vite dev server
./scripts/stop-local-preview
```

### Full Dev Stack (Docker)
```bash
./scripts/start-dev    # docker-compose.dev.yml: postgres, mariadb, step-ca, powerdns, authentik
```

## Deploying to Production

After `yarn build` in `frontend/`:

```bash
systemctl restart floppyguard-backend
nginx -s reload
./scripts/check-production-routes
```

The backend regenerates all nginx proxy-host configs from the DB on changes; reload nginx after.

## First-Time Setup (new server)

See [docs/PRODUCTION_ARCHITECTURE.md](docs/PRODUCTION_ARCHITECTURE.md) for the full infrastructure setup including systemd unit, nginx config, certbot virtualenv, and data directory layout.

For migrating from a legacy NPM Docker install: run `./scripts/cutover-production`.

## Features

- Full nginx-proxy-manager v2.14.0 feature set (proxy hosts, redirects, streams, access lists, certificates)
- WireGuard status dashboard, topology map, metadata editor, plan-preview, apply + restore
- Gateway and Platform overview pages
- Let's Encrypt DNS challenge support: Cloudflare, dns-multi (ipv64, name.com, etc.)
