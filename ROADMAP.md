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

### Docker Support

Docker Compose stack for FloppyGuard (backend + frontend + nginx), usable as a self-contained alternative to the host-based install.

---

### Access List Improvements

- Per-host IP allowlist/denylist beyond what nginx `allow`/`deny` provides
- Sync access lists to WireGuard peer filter rules

---

### Notification System

- Webhook support (Discord, Slack, generic HTTP)
- Alerts for: certificate expiry, WireGuard peer disconnect, Fail2Ban ban events

---

### Internal DNS Aliase

**Goal:** Friendly Names fur Services im WireGuard-Netz statt roher IPs. `cts.internal` statt `10.10.10.101`, `pbs.internal` statt `192.168.10.50`.

**Scope:**
- DNS-Zone (z.B. `.internal` oder `.wg`) automatisch aus WireGuard-Metadata generieren
- Jeder Link/Peer kann einen oder mehrere DNS-Namen bekommen (Feld im Metadata-Editor)
- dnsmasq oder CoreDNS auf dem Hub generiert Zone-File aus Metadata
- Zone wird bei jedem `apply-metadata` neu geschrieben
- Peers erhalten den Hub als DNS-Server (schon via `WG_DNS` env var moglich)

**Backend:**
- Neues Feld `dnsNames: string[]` in Link-Metadata
- `syncDnsZone()` in `wireguard.js` -- generiert dnsmasq-Config aus Metadata
- Hook in `applyMetadata` -- ruft `syncDnsZone()` nach erfolgreichem Apply auf
- `GET /api/wireguard/dns` -- aktuelle DNS-Eintraege als JSON

**Frontend:**
- DNS-Name-Feld im Link-Metadata-Editor (Chips/Tags Input)
- DNS-Tabelle im Routing-Tab (Name → IP → Peer)

**Inspiration:** Pangolin DNS Aliase (friendly names across sites)

---

### Service Health Checks

**Goal:** Aktiver Health-Status pro entdecktem Service. Nicht nur "Agent zuletzt gesehen", sondern "Service antwortet auf Port 443: ja/nein, Latenz 12ms".

**Scope:**
- Agent pruft discovered Services per TCP-Connect oder HTTP-GET alle 30s
- Health-Status (`healthy`, `degraded`, `down`) + Latenz im Heartbeat mitgesendet
- UI zeigt grun/gelb/rot Badge pro Service auf der Link-Card
- History: letzte 24h Health-Daten fur Mini-Uptime-Chart

**Backend:**
- Agent loop script: `check_services()` Funktion, TCP-Connect mit 3s Timeout
- Heartbeat-Payload erweitern: `services: [{ name, port, status, latency_ms }]`
- `GET /api/agents/:id/health` -- Health-History pro Agent/Service

**Frontend:**
- Health-Badge (grun/gelb/rot) auf der Link-Card neben discovered Services
- Tooltip mit Latenz und letztem Check-Zeitpunkt
- Optional: Mini-Uptime-Bar (24h, 1px pro Minute)

**Inspiration:** Pangolin Health Checks + Load Balancing

---

## Recently Shipped

| Version | Highlights |
|---------|-----------|
| v1.3.4  | Agent version display, WCAG focus-visible, responsive layout, 7 backend bug fixes, design + QA audit fixes |
| v1.3.3  | AllowedIPs conflict detection, auto-MASQUERADE, full i18n, error handling fixes |
| v1.3.2  | Security hardening: access control, JWT cap, rate limiter, HMAC agent signing, CSP, CORS |
| v1.3.1  | WireGuard peer + interface CRUD, live-vs-conf drift fix, AllowedIPs sync bugfix, CI fix |
| v1.2.4  | Peer config export, QR code modal, routing matrix, active peer names |
| v1.2.2  | i18n (DE/FR/EN), WireGuard routing automation, agent self-update, Fail2Ban dashboard, CI workflow |
| v1.2.1  | Install script, German translations, compiled locales |
| v1.2.0  | WireGuard hub/spoke topology, link management, route planning |
| v1.1.0  | WireGuard VPN management (initial), peer tracking |
| v1.0.0  | Fork of nginx-proxy-manager v2.14.0, FloppyGuard rebranding |
