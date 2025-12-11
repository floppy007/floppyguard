# FloppyGuard Implementation Status

Stand: 2026-05-03

## Production Infrastructure — DONE

- Host-based production runtime (no Docker for the app)
- systemd unit: `/etc/systemd/system/floppyguard-backend.service`
- nginx config: `/etc/nginx/conf.d/floppyguard.conf` (port 81 admin UI, includes `/data/nginx/`)
- MySQL backend (same DB as legacy NPM)
- certbot virtualenv at `/opt/certbot/` with Cloudflare + dns-multi plugins
- Let's Encrypt certs symlinked from `/opt/npm/letsencrypt/`
- Domain `https://your-instance-domain` live
- NPM Docker container stopped (cutover complete)

## Proxy Management (NPM feature set) — DONE

- Proxy hosts, redirections, dead hosts, streams
- Access lists, custom SSL, Let's Encrypt DNS challenge
- nginx config generation + reload on save
- All existing proxy host configs migrated from NPM

## WireGuard — Read + Metadata Layer — DONE

API endpoints live:
- `GET /api/wireguard/status` — interfaces, peers, links, routes, topology, capabilities, warnings
- `GET/PUT /api/wireguard/metadata` — read and write planning metadata
- `POST /api/wireguard/plan-preview` — dry-run planning (used by Interface editor)
- `POST /api/wireguard/apply-metadata` — apply metadata with auto-backup
- `GET /api/wireguard/apply-state` — last apply status
- `POST /api/wireguard/restore-metadata` — restore from backup

Current capability: `runtime-read + metadata-write + metadata-restore`
Live WireGuard config writes are intentionally not yet implemented.

## WireGuard Agent System — DONE

Remote agent management built and live:

**Admin API (JWT-authenticated):**
- `GET /api/agents` — list all agents (includes `reg_token` for pending agents)
- `POST /api/agents` — create agent
- `PUT /api/agents/:id` — update agent
- `DELETE /api/agents/:id` — delete agent
- `POST /api/agents/:id/reset-token` — generate new reg_token (sets status back to pending)

**Public Agent API (no JWT):**
- `GET /api/agent/install?reg_token=...&public_url=...&tunnel_url=...` — serves install script
- `POST /api/agent/register` — agent exchanges reg_token for permanent agent_token
- `GET /api/agent/config` — agent polls for WireGuard config (Bearer agent_token)
- `POST /api/agent/heartbeat` — agent reports hash + hostname + LAN IP + services

Agent features:
- `native` and `unifi` modes
- `wg_link_name` field reliably links an agent to a WireGuard link by name
- Auto-create agent when opening Agent section for a link
- Service auto-discovery (hub-side scan of agent LAN IP on known ports)
- Heartbeat stores hostname (with LAN IP suffix) + discovered services + last_seen
- Status: `pending` (never connected) → `active` (first heartbeat received)

Install one-liner:
```bash
curl -fsSL "<publicUrl>/api/agent/install?reg_token=TOKEN&public_url=URL&tunnel_url=URL" | bash
```
Installs as `floppyguard-agent` systemd service, polls hub every 30s.

## WireGuard UI — DONE

- Link cards with inline metadata editor and link planner
- Link planner: sets type, exported/imported networks, return path, management mode — saves directly (no preview step)
- After saving plan with `remoteManagementMode: agent` → agent section opens automatically
- Agent section per link: shows host, last seen, discovered app buttons
- Discovered services shown directly on link card (no need to open agent section)
- "Neu installieren": resets token and shows new one-liner immediately
- Metadata editor for interfaces

## WireGuard — Still Missing

- Peer CRUD (add/modify/delete peers)
- Interface CRUD
- Config file generation / QR code / client export
- `wg set` / conf-write / reload (live config writes)
- Restore preview before actual restore
- Guided setup wizard
- Audit history view (beyond last-apply)

## UI Pages

| Page | Status |
|------|--------|
| Login | Live |
| Dashboard | Live |
| Proxy Hosts | Live |
| Redirections | Live |
| Streams | Live |
| Dead Hosts | Live |
| Certificates | Live |
| Access Lists | Live |
| Users | Live |
| Settings | Live |
| Audit Log | Live |
| `/wireguard` | Live (read + metadata + agent management) |
| `/gateway` | Live (status only) |
| `/platform` | Live (status only) |

## Next Priorities

See [TECHNICAL_ROADMAP.md](TECHNICAL_ROADMAP.md).
