# Local Preview

Use the fork locally without Docker while the live NPM stack and live WireGuard stay untouched.

## Start

```bash
cd /var/www/nginx-proxy-manager-fork-base
./scripts/start-local-preview
```

The script starts:

- frontend on `http://127.0.0.1:5173`
- backend on `http://127.0.0.1:3300`
- SQLite data under `.local-data/backend/database.sqlite`

## Import live NPM data into preview

```bash
cd /var/www/nginx-proxy-manager-fork-base
./scripts/import-live-npm-to-preview
```

This clones the current live NPM MariaDB data from `/opt/npm` into the local preview SQLite database and then re-creates the preview login:

- user: `preview@example.com`
- password: `Preview123!`

Remote access uses plain HTTP by default:

- `http://your-instance-domain:5173`

Do not use `https://...:5173` unless you later put the preview behind a TLS proxy.

Preview login:

- user: `preview@example.com`
- password: `Preview123!`

## Stop

```bash
cd /var/www/nginx-proxy-manager-fork-base
./scripts/stop-local-preview
```

## Notes

- This preview reads real host WireGuard status from `/etc/wireguard`, `wg`, and system routes.
- The WireGuard module currently reads live host status and allows metadata-only planning writes via the app API. It does not restart interfaces or rewrite live configs.
- Preview logs are written to `.local-data/logs/backend-preview.log` and `.local-data/logs/frontend-preview.log`.
