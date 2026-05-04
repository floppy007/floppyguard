# FloppyGuard Production Mode

> **Status: Live seit 2026-05-03.**
> Systemd + nginx verwalten Backend und Frontend vollständig.

## Was läuft wo

| Dienst | Wie gestartet | Port |
|--------|--------------|------|
| Backend | `systemctl start floppyguard-backend` | 3300 (localhost) |
| Admin UI | System nginx, `/etc/nginx/conf.d/floppyguard.conf` | 81 |
| Proxy-Hosts | System nginx, `/data/nginx/proxy_host/*.conf` | 80/443 |

## Schnellstart

```bash
systemctl restart floppyguard-backend
nginx -s reload
```

## Frontend aktualisieren

```bash
cd /var/www/floppyguard/frontend
corepack yarn build
# nginx serviert dist/ sofort — kein Reload nötig
```

## Ports

- `3300` — API, nur localhost
- `81` — Admin UI
- `80`/`443` — Proxy hosts
- `5173` — Dev-only (Vite), läuft nicht in production

## Weiterführend

- Infrastruktur-Details: [PRODUCTION_ARCHITECTURE.md](PRODUCTION_ARCHITECTURE.md)
- Betriebskommandos: [OPERATIONS.md](OPERATIONS.md)
