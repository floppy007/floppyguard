# FloppyGuard Operations Runbook

Stand: 2026-05-03

## Daily Commands

```bash
# Health check
systemctl status floppyguard-backend
./scripts/check-production-routes

# Live logs
journalctl -u floppyguard-backend -f

# nginx status
nginx -t
```

## Restart Backend

```bash
systemctl restart floppyguard-backend
journalctl -u floppyguard-backend -n 20 --no-pager
```

## Reload nginx

```bash
nginx -t && nginx -s reload
```

## View Logs

```bash
# Backend (systemd journal)
journalctl -u floppyguard-backend -f
journalctl -u floppyguard-backend --since "1 hour ago"

# nginx per proxy host
tail -f /data/logs/proxy-host-<id>_access.log
tail -f /data/logs/proxy-host-<id>_error.log

# nginx fallback
tail -f /data/logs/fallback_http_access.log
tail -f /var/log/nginx/error.log
```

## Rebuild Frontend

```bash
cd /var/www/nginx-proxy-manager-fork-base/frontend
corepack yarn build
# nginx serves dist/ immediately — no reload needed
```

## Check Health Manually

```bash
# Backend API
curl -s http://127.0.0.1:3300/ | head -3

# Admin UI
curl -so /dev/null -w "%{http_code}" http://127.0.0.1:81/

# Domain
curl -so /dev/null -w "%{http_code}" https://your-instance-domain/
```

## Agent Management

Agents are managed via `/wireguard` — open a link card and click "Agent".

Agent logs on remote hosts:
```bash
journalctl -u floppyguard-agent -f
systemctl status floppyguard-agent
systemctl restart floppyguard-agent
```

List agents via API:
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:3300/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"identity":"admin@example.com","secret":"..."}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
curl -s http://127.0.0.1:3300/api/agents -H "Authorization: Bearer $TOKEN"
```

## SSL Certificate Renewal

Certificates are renewed automatically by the backend's built-in renewal timer (runs daily).

If certbot plugin is missing:
```bash
. /opt/certbot/bin/activate
pip install certbot-dns-cloudflare certbot-dns-multi~=4.9
deactivate
systemctl restart floppyguard-backend
```

## Proxy Host Config Stuck / Not Regenerating

If a proxy host shows "offline" or its nginx config is missing from `/data/nginx/proxy_host/`:

1. Open the proxy host in the UI and save it (triggers regeneration)
2. Or copy from legacy backup:
   ```bash
   cp /opt/npm/data/nginx/proxy_host/<id>.conf /data/nginx/proxy_host/
   nginx -t && nginx -s reload
   ```

## SPA Routes Return 404

All SPA routes (`/gateway`, `/wireguard`, `/platform`) are handled by nginx `try_files → /index.html`.

```bash
grep -A5 "location /" /etc/nginx/conf.d/floppyguard.conf
nginx -t
```

## Database

```bash
mysql -u npm -pnpm npm
mysqlshow -u npm -pnpm npm
```

## Logrotate

```bash
logrotate -f /etc/logrotate.d/nginx-proxy-manager
```

## Troubleshooting: Backend Won't Start

```bash
journalctl -u floppyguard-backend -n 50 --no-pager
```

Common causes:
- **MySQL not running**: `systemctl start mysql`
- **Port 3300 in use**: `ss -tlnp | grep 3300` → `systemctl restart floppyguard-backend`
- **Migration error**: check DB schema, backup DB before retrying

## Legacy NPM

Cutover already executed. To fully remove:
```bash
cd /opt/npm && docker compose down
# Keep /opt/npm/letsencrypt/ — certs still in use via symlinks
```
