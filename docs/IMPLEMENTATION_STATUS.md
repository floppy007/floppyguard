# FloppyGuard Implementation Status

Stand: 2026-05-04

## Production Infrastructure — DONE

- Host-based production runtime (no Docker for the app)
- systemd unit: `/etc/systemd/system/floppyguard-backend.service`
- nginx config: `/etc/nginx/conf.d/floppyguard.conf` (port 81 admin UI, includes `/data/nginx/`)
- MySQL backend (same DB as legacy NPM)
- certbot virtualenv at `/opt/certbot/` with Cloudflare + dns-multi plugins
- Let's Encrypt certs symlinked from `/opt/npm/letsencrypt/`
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

## WireGuard — Routing Automation — DONE (v1.2.2)

Hub-and-spoke routing wired up end-to-end on every apply:

- `syncHubConf()` — rewrites hub `wg0.conf` AllowedIPs and PostUp/PostDown ip-route commands
  from link metadata; applies live via `wg set` + `ip route add` without restarting wg0
- `syncAgentConfigs()` — updates every connected agent's WireGuard peer AllowedIPs so all sites
  can reach each other through the hub; agents pick up changes on their next 30 s poll
- Both syncs fire automatically when apply scope is `metadata-with-config-intent`
- Apply response includes `hubSync` and `agentSync` result fields
- UI shows live sync feedback (peer count, agent names, or warnings) after apply

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
- `GET /api/agent/loop-script` — serves current loop script for self-update (Bearer agent_token)
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

## Agent Self-Update — DONE (v1.2.2)

Agents self-update automatically when the server script version changes:

- `AGENT_SCRIPT_VERSION` constant in `backend/internal/agent.js` tracks the loop script version
- Config response includes `script_version`; agent compares on every 30s poll
- On version change: downloads new script from `GET /api/agent/loop-script`, atomically replaces
  `/usr/local/sbin/floppyguard-agent`, then `exec`s it — zero-downtime, no systemd restart
- `sync_routes()` bash function added to loop script: adds missing kernel ip routes after
  `wg syncconf` (which updates WireGuard peer tables but never touches the kernel routing table)

**Rule:** Any edit to `buildLoopScript()` in `agent.js` that affects the generated bash script
**requires a `AGENT_SCRIPT_VERSION` bump** — otherwise running agents never pick up the change.

## WireGuard UI — DONE

- Link cards with inline metadata editor and link planner
- Link planner: sets type, exported/imported networks, return path, management mode — saves directly (no preview step)
- After saving plan with `remoteManagementMode: agent` → agent section opens automatically
- Agent section per link: shows host, last seen, discovered app buttons
- Discovered services shown directly on link card (no need to open agent section)
- "Neu installieren": resets token and shows new one-liner immediately
- Metadata editor for interfaces
- Apply result shows hubSync / agentSync feedback inline

## WireGuard — Still Missing

- ~~Interface CRUD~~ ✔ v1.3.1 — `createInterface` + `deleteInterface` with wg-quick up/down, systemctl enable/disable, metadata cleanup
- Restore preview before actual restore
- Guided setup wizard
- Audit history view (beyond last-apply)

## WireGuard — Recently Completed

- ~~Peer CRUD (add/modify/delete peers)~~ ✔ v1.3.1 — `createPeer`, `deletePeer`, `updatePeer` with live `wg set`, conf rewrite, metadata cleanup
- ~~Config file generation / QR code / client export~~ ✔ v1.2.4
- ~~`wg set` / conf-write / reload (live config writes)~~ ✔ v1.3.1 — live AllowedIPs sync + drift detection

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
| `/wireguard` | Live (read + metadata + routing automation + agent management) |
| `/gateway` | Live (status only) |
| `/platform` | Live (status only) |

## Next Priorities

See [TECHNICAL_ROADMAP.md](TECHNICAL_ROADMAP.md).
