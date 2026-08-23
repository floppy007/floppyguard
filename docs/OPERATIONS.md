# FloppyGuard Operations Runbook

Stand: 2026-08-23

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
cd /var/www/floppyguard/frontend
corepack yarn build
# nginx serves dist/ immediately — no reload needed
```

## Release-Version erhöhen

Bei jedem Versionsbump müssen `backend/package.json`, `frontend/package.json`, das README-Badge und `CHANGELOG.md` dieselbe Version enthalten. Alle Änderungen eines Kalendertags werden in einer gemeinsamen Version und einem gemeinsamen Commit gebündelt. Anschließend den Produktions-Build erzeugen, damit die neue Frontend-Version ausgeliefert wird:

```bash
cd /var/www/floppyguard/frontend
corepack yarn build
```

Die Backend-Version wird beim Start eingelesen. Deshalb danach den Dienst neu starten und den laufenden API-Wert prüfen:

```bash
systemctl restart floppyguard-backend
curl -fsS http://127.0.0.1:3300/api/
```

Erst abschließen, wenn `version.major`, `version.minor` und `version.revision` die erhöhte Version ergeben.

## Installationspfad bei Abhängigkeitsupdates

Bei Änderungen an Abhängigkeiten, Lockfiles, dem Paketmanager oder den Node-Anforderungen muss vor dem Release immer der Installationspfad geprüft werden. Falls nötig, `scripts/install.sh` und die manuellen Schritte im README gemeinsam anpassen. Neue Installationen müssen Node 22.22.2+, npm 12.0.2 und Yarn 1.22.22 verwenden, die committed `yarn.lock`-Dateien mit `yarn install --frozen-lockfile` installieren und anschließend einen frischen Installationslauf sowie den Frontend-Build verifizieren.

## Kontrolliertes Anwendungsupdate

Im Dashboard erscheint für Administratoren ein Hinweis, sobald die Versionsprüfung ein neues GitHub-Release erkennt. Das Update wird anschließend bewusst unter **Settings → Anwendungsupdate** gestartet; es gibt keine automatische Installation.

`POST /api/version/update` ist ausschließlich für Administratoren verfügbar. Es startet `scripts/update.sh` in einer separaten transienten systemd-Unit, damit der Backend-Neustart den laufenden Updateprozess nicht beendet. Das Script akzeptiert nur den fest hinterlegten Upstream `floppy007/floppyguard`, lädt den aktuell ausgecheckten Branch, verwendet ausschließlich einen Fast-Forward-Merge und verwirft daher niemals lokale Änderungen. Danach installiert es beide Lockfiles, baut das Frontend, startet `floppyguard-backend` neu und prüft `http://127.0.0.1:3300/api/`.

Fortschritt: `/var/lib/floppyguard/update-status.json` · Log: `/var/lib/floppyguard/update.log`

Bei einem fehlgeschlagenen Merge zuerst den lokalen Git-Status prüfen und die Änderungen bewusst sichern oder bereinigen. Nicht mit `git reset --hard` im Produktivverzeichnis arbeiten.

## Check Health Manually

```bash
# Backend API
curl -s http://127.0.0.1:3300/ | head -3

# Admin UI
curl -so /dev/null -w "%{http_code}" http://127.0.0.1:81/
```

## Agent Management

Agents are managed via `/wireguard` — open a link card and click "Agent".

**Install on a new host:**
```bash
curl -fsSL "<publicUrl>/api/agent/install?reg_token=TOKEN&public_url=URL&tunnel_url=URL" | bash
```

**Agent logs on remote hosts:**
```bash
journalctl -u floppyguard-agent -f
systemctl status floppyguard-agent
systemctl restart floppyguard-agent
```

**Agent self-update:**
Agents compare their local `SCRIPT_VERSION` against `script_version` in the config response
on every 30s poll. If the version changed, they automatically download the new script from
`GET /api/agent/loop-script` and `exec` it — zero-downtime, no systemd restart required.

To trigger a self-update on all agents: bump `AGENT_SCRIPT_VERSION` in
`backend/internal/agent.js`, rebuild the frontend and restart the backend.

**List agents via API:**
```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:3300/api/tokens \
  -H 'Content-Type: application/json' \
  -d '{"identity":"admin@example.com","secret":"..."}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
curl -s http://127.0.0.1:3300/api/agents -H "Authorization: Bearer $TOKEN"
```

## WireGuard Routing Automation

When you click Apply in the WireGuard planner (scope `metadata-with-config-intent`):

1. **Hub sync** — `wg0.conf` AllowedIPs and ip-route PostUp/PostDown are rewritten from metadata;
   changes go live immediately via `wg set` + `ip route add` (no wg0 restart)
2. **Agent sync** — every connected agent's peer AllowedIPs are updated via the config API;
   agents pick up the new AllowedIPs on their next 30s config poll and run `wg syncconf`
3. **Kernel routes on agents** — after `wg syncconf`, the agent's `sync_routes()` function
   adds missing kernel ip routes, removes stale routes no longer in AllowedIPs, and skips
   networks already routed via physical interfaces (prevents overriding local LAN routes)

The apply result panel in the UI shows which peers were updated and which agents were synced.

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
