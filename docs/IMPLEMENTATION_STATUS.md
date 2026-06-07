# FloppyGuard Implementation Status

Stand: 2026-05-27

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
- `GET /api/wireguard/status` — interfaces, peers, links, routes, topology, capabilities, warnings (admin)
- `GET/PUT /api/wireguard/metadata` — read and write planning metadata (admin)
- `POST /api/wireguard/plan-preview` — dry-run planning (admin)
- `POST /api/wireguard/apply-metadata` — apply metadata with auto-backup (admin)
- `GET /api/wireguard/apply-state` — last apply status (admin)
- `POST /api/wireguard/restore-metadata` — restore from backup (admin)
- `GET /api/wireguard/bandwidth` — per-interface transfer counters (admin)
- `GET /api/wireguard/link-config` — download peer config file (admin)
- `GET /api/wireguard/link-config-qr` — download peer config QR code (admin)
- `POST /api/wireguard/create-peer` — create WireGuard peer with keypair (admin)
- `POST /api/wireguard/update-peer` — update peer AllowedIPs live (admin)
- `POST /api/wireguard/delete-peer` — remove peer from interface + config + metadata (admin)
- `POST /api/wireguard/create-interface` — create new WireGuard interface (admin)
- `POST /api/wireguard/delete-interface` — remove non-hub interface (admin)
- `POST /api/wireguard/peers` — RESTful alias for create-peer (admin)
- `PUT/DELETE /api/wireguard/peers/:linkId` — RESTful alias for update/delete peer (admin)
- `POST /api/wireguard/interfaces` — RESTful alias for create-interface (admin)
- `DELETE /api/wireguard/interfaces/:name` — RESTful alias for delete-interface (admin)

Current capability: `runtime-read + metadata-write + config-write + metadata-restore`

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
  `wg syncconf` (which updates WireGuard peer tables but never touches the kernel routing table);
  also removes stale routes no longer in AllowedIPs and skips physically-connected networks

**Rule:** Any edit to `buildLoopScript()` in `agent.js` that affects the generated bash script
**requires a `AGENT_SCRIPT_VERSION` bump** — otherwise running agents never pick up the change.

## Agent Version Tracking — DONE (v1.3.4)

Agents report their script version to the hub on every heartbeat:

- Heartbeat payload includes `script_version` field
- Stored in `agent_version` column (migration `20260509160000_agent_version.js`)
- `GET /api/agents` returns `agent_version` for each agent
- UI shows `Agent v{version}` badge directly on link cards (no panel open needed)
- Also visible in the Agent panel next to "Host" and "Last seen"

## Agent Script Signing — DONE (v1.3.2)

Agent self-update is now cryptographically verified:

- Server computes HMAC-SHA256 of the loop script using the agent's `agent_token` as key
- Signature is sent in `X-Script-Signature` response header on `GET /api/agent/loop-script`
- Agent computes local HMAC using `openssl dgst -sha256 -hmac "$FGTOKEN"` and compares
- Script replacement is rejected if signatures don't match
- Prevents server-compromise-to-RCE escalation on agent hosts

## Security Hardening — DONE (v1.3.2)

Full security audit performed and all findings remediated:

**Access control:**
- All admin endpoints (`/api/agents/*`, `/api/wireguard/*` reads, `GET /api/users`,
  `GET /api/security/fail2ban`) now require `requireAdmin()` middleware
- `POST /api/design/screenshot` requires JWT + admin + magic-bytes file validation
- `DELETE /api/users` (bulk delete) permanently disabled (always returns 404)
- `GET /api/wireguard/link-config` and `/link-config-qr` require admin (expose private keys)

**Authentication:**
- JWT token expiry capped at 30 days maximum
- Rate limiter upgraded from in-memory Map to SQLite-backed persistent storage

**Infrastructure:**
- GitHub Actions SHA-pinned (immutable commit references)
- `.github/CODEOWNERS` protects workflow files
- CSP header added to all responses
- CORS returns 403 for disallowed origins (was silently passing)
- `.env` and `.gstack/` added to `.gitignore`
- Cypress Dockerfile explicitly sets `USER 1000`
- `utils.exec()` shell calls replaced with `utils.execFile()` where possible

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

- Restore preview before actual restore
- Guided setup wizard
- Audit history view (beyond last-apply)

## WireGuard — Completed

- Hub→Agent sync hardening ✔ v1.3.21 — REMOVE/DELETE/RENAME propagate reliably: `deletePeer`/`deleteInterface`/link-rename/`createPeer`/`wg_link_name`-rebind now trigger `syncAgentConfigs`, plus a 5-min reconciler (defense-in-depth); every metadata-store mutation + the reconciler run under `withWriteLock` (no lost-write resurrect); hub authoritative for hub-peer AllowedIPs; per-agent error isolation in the sync loop; `%i`→`$iface` before `eval` (MASQUERADE/FORWARD); site networks strictly IPv4 + canonical (IPv6 rejected, host bits masked); install-script root command-injection closed; `last_server_url` recorded on heartbeat. Consolidates same-day releases v1.3.17–v1.3.20.
- Central hub-URL setting ✔ v1.3.16 — the per-agent hub-URL editor from v1.3.15 is now a single page-level control in the WireGuard "Overview" tab (UI-only, behavior unchanged)
- Hub-URL propagation + agent ACL editor ✔ v1.3.15 — `GET /api/agent/config` serves hub URLs from the `agent-hub-url` setting; the agent adopts them into `config.env` only after a `reach` check (a typo can't brick it); `allowed_networks` editable per agent in the UI (triggers `syncAgentConfigs`); strict ACL CIDR validation (every `/0` rejected); `sanitizeHubUrl`
- WireGuard network-field validation ✔ v1.3.14 — `importedNetworks`/`exportedNetworks`/`routeTargets` strictly validated as IPv4/IPv6 CIDRs at input AND at the sink (`syncHubConf`), closing a root command-injection via `ip route add`; rate-limit added to `GET /api/agent/install`
- Road warrior AllowedIPs ✔ v1.3.13 — `generatePeerConfig` und `createPeer` sammeln automatisch alle exportedNetworks anderer Peers fuer Road Warriors; `resolveHubHost()` nutzt Domain statt IP; Key-Rotation Metadata-Migration nur bei tatsaechlichem Erfolg
- Stale route cleanup ✔ v1.3.12 — `sync_routes()` entfernt veraltete wg0-Routen und ueberspringt physisch angeschlossene Netze
- AllowedIPs conflict blocking ✔ v1.3.12 — `applyMetadata` und `PUT /wireguard/metadata` pruefen auf doppelte Subnet-Zuweisungen
- Metadata live-sync ✔ v1.3.12 — `PUT /wireguard/metadata` loest sofort `syncHubConf` + `syncAgentConfigs` aus
- Multi-interface sync ✔ v1.3.12 — `syncHubConf` synct alle WG-Interfaces, nicht nur wg0
- Hub-LAN MASQUERADE ✔ v1.3.11 — zwei MASQUERADE-Regeln pro physischem Interface (lokal + Tunnel-Subnet)
- Agent PostUp route generation ✔ v1.3.10 — `buildHubPostUp` generiert `ip route add` fuer alle Peer-AllowedIPs
- Client-peer route clash fix ✔ v1.3.9 — Client-Peers bekommen keine importedNetworks als Hub-AllowedIPs
- AllowedIPs conflict detection ✔ v1.3.3 — warns when multiple peers claim the same subnet; shown as alert in UI
- Auto-MASQUERADE ✔ v1.3.3 — `syncHubConf` discovers non-WG interfaces and adds NAT rules for cross-interface routing
- Peer CRUD ✔ v1.3.1 — `createPeer`, `deletePeer`, `updatePeer` with live `wg set`, conf rewrite, metadata cleanup
- Interface CRUD ✔ v1.3.1 — `createInterface`, `deleteInterface` with wg-quick up/down, systemctl enable/disable
- Interface selector ✔ v1.3.1 — tunnel creation supports all interfaces, not just wg0
- Live-vs-conf drift detection ✔ v1.3.1 — `syncHubConf` auto-corrects discrepancies
- Config file generation / QR code / client export ✔ v1.2.4
- Live config writes (`wg set` + conf-write) ✔ v1.3.1

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
| `/wireguard` | Live (full CRUD + routing automation + agent management) |
| `/gateway` | Live (WireGuard gateway status + link warnings) |
| `/platform` | Alias for Dashboard (`/`) |

## Next Priorities

See [TECHNICAL_ROADMAP.md](TECHNICAL_ROADMAP.md).
