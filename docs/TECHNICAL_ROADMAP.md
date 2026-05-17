# FloppyGuard Technical Roadmap

Stand: 2026-05-17

## Was bereits fertig ist

- WireGuard read + metadata-write Layer
- Agent-System (register, heartbeat, service discovery, install one-liner)
- Remote management mode `agent` — Agents direkt auf WireGuard-Link-Karten
- Link-Planer (type, networks, return path, management mode) — direkt speicherbar
- Service-Buttons direkt auf Link-Karten sichtbar
- **WireGuard Routing Automation** — `syncHubConf` + `syncAgentConfigs` on every apply;
  hub wg0.conf und alle Agent-Configs werden automatisch aktualisiert
- **Auto-MASQUERADE** (v1.3.8) — `syncAgentConfigs` generiert PostUp/PostDown mit
  MASQUERADE-Regeln fuer Remote-Site-Netze automatisch; kein manuelles iptables/nft mehr
- **Agent Self-Update** — `AGENT_SCRIPT_VERSION` + `GET /api/agent/loop-script`;
  Agents updaten sich selbst innerhalb von 30s bei Version-Bump
- **Kernel Route Sync** — `sync_routes()` im Loop-Script addiert fehlende ip-Routes
  nach `wg syncconf` (wg syncconf beruehrt die Kernel-Routing-Tabelle nicht)
- CI-Pipeline (Backend Lint + Test, Frontend Lint + Build, OpenAPI Lint)
- **Peer CRUD** (v1.3.1) — `createPeer`, `deletePeer`, `updatePeer` mit Live-`wg set`, Conf-Rewrite, Metadata-Cleanup und Safety-Backup
- **Interface CRUD** (v1.3.1) — `createInterface`, `deleteInterface` mit wg-quick up/down, systemctl enable/disable, Keypair-Generierung
- **Live-vs-Conf Drift-Fix** (v1.3.1) — `syncHubConf` vergleicht jetzt Live-State gegen Conf und korrigiert automatisch
- **Config-Generierung + QR-Code / Client-Export** (v1.2.4)
- **Interface Selector** (v1.3.1) — Tunnel-Erstellung unterstuetzt alle Interfaces, nicht nur wg0
- **Restore + Backup** — `restoreMetadataBackup` mit Audit-Eintrag, getestet
- **Network ACLs** (v1.3.6) — `allowed_networks` und `allowed_sites` pro Agent
- **Netz-Auswahl UI** (v1.3.7) — Checkbox-Karten pro Site mit einzeln waehlbaren Subnetzen
- **wg-gui abgeloest** — Port 8080 nicht mehr in Nutzung, WireGuard-UI komplett in FloppyGuard

## Noch offen

### P2 — Platform + Capabilities (mittlere Prioritaet)

- Platform-Feld auf reale Capabilities und naechste Schritte ausrichten
- Statuskarten an `capabilities` koppeln (z.B. "Agent connected", "Config synced", "Routes OK")
- Audit-Historienansicht im Frontend ausbauen (Backend-Route existiert bereits)

### P3 — Tests (hohe Prioritaet)

- **Backend-Tests Agent-System** — register, heartbeat, token-reset, config-sync, masquerade-gen
- **Frontend-Tests /wireguard** — Link-Karten, Agent-Modal, Tunnel-Erstellung, Netz-Auswahl

### P4 — Betriebshaertung (laufend)

- Monitoring-Dashboard (Prometheus/Grafana-Export oder eigene Metriken-Route)
- Alerting bei fehlendem Agent-Heartbeat (> 5 min)
- Automatisches Backup der DB vor Plan-Apply

---

## GitHub Issues (offen)

- **#1** DNS Auto-Provisioning (Cloudflare/IPv64) — automatisch DNS-Records bei Proxy Host Erstellung
- **#3** Tunnel Failure Alerting — Notification bei fehlendem Handshake
- **#4** Long-term Bandwidth Metrics — History in DB statt nur 10-Min Ring-Buffer
- **#5** Zero-Touch Enrollment — Peer bekommt ID+Secret, zieht Config automatisch
- **#6** Docker Deployment Support — Dockerfile, docker-compose, Container Registry

---

## Nicht jetzt

- Remote-Apply per SSH (agent-mode ist bereits live und zuverlaessig)
- Grosse UX-Ausbauten ohne stabiles Backend-Modell
- Multi-Hub-Support (mehrere WireGuard-Hubs zentral verwalten)
