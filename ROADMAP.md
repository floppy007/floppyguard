# FloppyGuard Roadmap

This document tracks planned features and improvements. Items are not in strict priority order — implementation depends on available time and community interest.

---

## Planned Features

### DNS Auto-Provisioning (Cloudflare & IPv64)

**Goal:** When a Proxy Host (or Redirection Host) is created or updated, FloppyGuard automatically creates or updates the corresponding DNS record (A/CNAME) via the provider's API — no manual DNS management needed.

**Scope:**
- Supported providers: **Cloudflare** (via API token + Zones API), **IPv64** (via API key)
- Records created: A record pointing to the server's public IP, or CNAME to a base domain
- Optional per-host toggle: "Auto-provision DNS" in the Proxy Host form
- Provider credentials stored per-zone in the Settings page
- Cleanup option: delete DNS record when host is deleted

**Backend:**
- New `dns-provisioning` module in `backend/internal/`
- Cloudflare: `POST /zones/{zone_id}/dns_records`, `PUT` for updates, `DELETE` for cleanup
- IPv64: IPv64 REST API for subdomain management
- Triggered as a post-save hook in `proxy-host.js` / `redirection-host.js`

**Frontend:**
- Optional "Auto DNS" toggle in Proxy Host / Redirection Host form
- DNS provider selection (Cloudflare / IPv64)
- Zone / base domain selector (loaded from provider API)
- Record type selection (A / CNAME)
- Settings page: manage provider API credentials

**Related issue:** [#1 — DNS Auto-Provisioning](https://github.com/floppy007/floppyguard/issues/1)

---

### Grafische Netz-Zuordnung (Network ACL Editor)

**Goal:** Visueller Editor im WireGuard-Bereich, in dem man pro Agent/Site grafisch festlegt, welche Netze und VLANs erreichbar sein sollen. Ersetzt manuelle DB-Eintraege fuer `allowed_sites` und `allowed_networks`.

**Scope:**
- Drag & Drop oder Checkbox-Matrix: Agent links, Netze rechts
- Pro Agent: welche Subnetze (192.168.10.0/24, 192.168.111.0/24, ...) sollen geroutet werden
- MASQUERADE pro Agent ein/ausschaltbar (Toggle)
- Aenderungen generieren automatisch neue PostUp/PostDown via `normalizeAgentConfig()`
- Live-Preview: zeigt die resultierenden AllowedIPs und Firewall-Regeln bevor man applied
- Apply pusht die Config an alle betroffenen Agents (naechster Poll-Zyklus)

**Backend:**
- `PUT /api/agents/:id` akzeptiert bereits `allowed_sites` und `allowed_networks` (v1.3.6)
- Neuer Endpoint: `POST /api/wireguard/apply-acls` — setzt allowed_networks fuer alle Agents und triggert `syncAgentConfigs()`
- `normalizeAgentConfig()` erhaelt optionalen Parameter `masquerade: boolean`
- `GET /api/wireguard/acl-matrix` — liefert die aktuelle Zuordnung aller Agents zu allen Netzen

**Frontend:**
- Neuer Tab "Netzwerk-Zuordnung" / "Network ACLs" im WireGuard-Bereich
- Matrix-View: Zeilen = Agents/Sites, Spalten = verfuegbare Subnetze
- Checkbox oder Toggle pro Zelle (Agent darf Netz sehen: ja/nein)
- MASQUERADE-Toggle pro Agent-Zeile
- Apply-Button mit Diff-Preview (vorher/nachher AllowedIPs)

**Abhaengigkeit:** Baut auf `allowed_sites`, `allowed_networks` und `normalizeAgentConfig()` aus v1.3.6 auf.

---

### Internal DNS Aliase

**Goal:** Friendly Names fuer Services im WireGuard-Netz statt roher IPs. `cts.internal` statt `10.10.10.101`, `pbs.internal` statt `192.168.10.50`.

**Scope:**
- DNS-Zone (z.B. `.internal` oder `.wg`) automatisch aus WireGuard-Metadata generieren
- Jeder Link/Peer kann einen oder mehrere DNS-Namen bekommen (Feld im Metadata-Editor)
- dnsmasq oder CoreDNS auf dem Hub generiert Zone-File aus Metadata
- Zone wird bei jedem `apply-metadata` neu geschrieben
- Peers erhalten den Hub als DNS-Server (schon via `WG_DNS` env var moeglich)

**Backend:**
- Neues Feld `dnsNames: string[]` in Link-Metadata
- `syncDnsZone()` in `wireguard.js` — generiert dnsmasq-Config aus Metadata
- Hook in `applyMetadata` — ruft `syncDnsZone()` nach erfolgreichem Apply auf
- `GET /api/wireguard/dns` — aktuelle DNS-Eintraege als JSON

**Frontend:**
- DNS-Name-Feld im Link-Metadata-Editor (Chips/Tags Input)
- DNS-Tabelle im Routing-Tab (Name -> IP -> Peer)

---

### Notification System / Tunnel Failure Alerting

- Webhook support (Discord, Slack, generic HTTP)
- Alerts for: certificate expiry, WireGuard peer disconnect, Fail2Ban ban events
- Configurable thresholds (z.B. Peer offline > 5 Minuten)

**Related issue:** [#3 — Tunnel Failure Alerting](https://github.com/floppy007/floppyguard/issues/3)

---

### Service Health Checks

**Goal:** Aktiver Health-Status pro entdecktem Service. Nicht nur "Agent zuletzt gesehen", sondern "Service antwortet auf Port 443: ja/nein, Latenz 12ms".

**Scope:**
- Agent prueft discovered Services per TCP-Connect oder HTTP-GET alle 30s
- Health-Status (`healthy`, `degraded`, `down`) + Latenz im Heartbeat mitgesendet
- UI zeigt gruen/gelb/rot Badge pro Service auf der Link-Card
- History: letzte 24h Health-Daten fuer Mini-Uptime-Chart

**Backend:**
- Agent loop script: `check_services()` Funktion, TCP-Connect mit 3s Timeout
- Heartbeat-Payload erweitern: `services: [{ name, port, status, latency_ms }]`
- `GET /api/agents/:id/health` — Health-History pro Agent/Service

**Frontend:**
- Health-Badge (gruen/gelb/rot) auf der Link-Card neben discovered Services
- Tooltip mit Latenz und letztem Check-Zeitpunkt
- Optional: Mini-Uptime-Bar (24h, 1px pro Minute)

---

### Long-term Bandwidth Metrics

**Goal:** Bandwidth-History ueber Tage/Wochen statt nur 10-Minuten Ring-Buffer. Trends erkennen, Kapazitaet planen.

**Scope:**
- Aggregierte Bandwidth-Daten (stuendlich/taeglich) in DB persistieren
- History-Charts auf Dashboard und Traffic-Seite
- Per-Peer und per-Interface Trends

**Related issue:** [#4 — Long-term Bandwidth Metrics](https://github.com/floppy007/floppyguard/issues/4)

---

### Zero-Touch Enrollment

**Goal:** Neue Peers/Sites automatisch onboarden. Peer bekommt nur eine ID und ein Secret, zieht den Rest (Keys, Config, Firewall-Regeln) automatisch vom Hub.

**Scope:**
- Enrollment-Token mit begrenzter Gueltigkeit
- Peer generiert Keypair lokal, sendet Public Key an Hub
- Hub erstellt Peer-Eintrag, generiert Config, pusht via Agent
- Kein manuelles Kopieren von Configs oder Keys noetig

**Related issue:** [#5 — Zero-Touch Enrollment](https://github.com/floppy007/floppyguard/issues/5)

---

### Docker Support

Docker Compose stack for FloppyGuard (backend + frontend + nginx), usable as a self-contained alternative to the host-based install.

**Related issue:** [#6 — Docker Deployment Support](https://github.com/floppy007/floppyguard/issues/6)

---

### Access List Improvements

- Per-host IP allowlist/denylist beyond what nginx `allow`/`deny` provides
- Sync access lists to WireGuard peer filter rules

---

## Recently Shipped (v1.3.6)

### Hub-Managed Firewall Rules ✓

- All agent PostUp/PostDown rules generated centrally by the hub via `normalizeAgentConfig()`
- No local firewall configuration needed on VPN gateways
- Tunnel subnet derived automatically from Address field (no hardcoded subnets)
- Agent applies PostUp/PostDown changes live without tunnel restart
- Agent preserves local PrivateKey when hub sends `(hidden)` placeholder

### Per-Agent Network Access Control ✓

- `allowed_networks`: explicit CIDRs per agent (most granular, deny-by-default)
- `allowed_sites`: link-name whitelist per agent (site-level)
- `null` = full-mesh (backwards compatible)
- `syncAgentConfigs` respects priority: allowed_networks > allowed_sites > full-mesh
- New DB columns + migration: `allowed_sites`, `allowed_networks`

### Agent Config Auto-Upload ✓

- Agents upload their local WG config (with masked PrivateKey) to the hub when the server has no config stored
- `POST /api/agent/upload-config` (rate-limited)
- Enables `syncAgentConfigs` for agents registered without providing their config (e.g. existing WireGuard setups)

### Reboot Resilience ✓

- Backend startup: max 30 retries with exponential backoff, clear "Database unreachable" error message, exits on failure so systemd marks it failed
- WireGuard: `Table = off` in `createInterface()` prevents wg-quick auto-route collisions with existing kernel routes
- Install script: detects MariaDB/MySQL, adds systemd dependency, installs `mariadb-rundir.service` for LXC containers where `systemd-tmpfiles` fails

---

## All Shipped Versions

| Version | Highlights |
|---------|-----------|
| v1.3.6  | Hub-managed firewall rules, per-agent network ACLs, agent config auto-upload, reboot resilience, PrivateKey preservation |
| v1.3.4  | Agent version display, WCAG focus-visible, responsive layout, 7 backend bug fixes, design + QA audit fixes |
| v1.3.3  | AllowedIPs conflict detection, auto-MASQUERADE, full i18n, error handling fixes |
| v1.3.2  | Security hardening: access control, JWT cap, rate limiter, HMAC agent signing, CSP, CORS |
| v1.3.1  | WireGuard peer + interface CRUD, live-vs-conf drift fix, AllowedIPs sync bugfix, CI fix |
| v1.3.0  | UI redesign, WireGuard tunnel creation, DNS config, platform-aware AllowedIPs |
| v1.2.4  | Peer config export, QR code modal, routing matrix, active peer names |
| v1.2.3  | Certificate renewal fixes (HTTP + DNS challenge), modal alignment fix |
| v1.2.2  | i18n (DE/FR/EN), WireGuard routing automation, agent self-update, Fail2Ban dashboard, CI workflow |
| v1.2.1  | Install script, German translations, compiled locales |
| v1.2.0  | WireGuard hub/spoke topology, link management, route planning |
| v1.1.0  | Remote agent system: registration, token management, install one-liner |
| v1.0.0  | Fork of nginx-proxy-manager v2.14.0, FloppyGuard rebranding |
