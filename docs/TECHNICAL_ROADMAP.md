# FloppyGuard Technical Roadmap

Stand: 2026-06-07

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
- **Client-Peer Route Clash Fix** (v1.3.9) — Client-Peers bekommen keine importedNetworks als Hub-AllowedIPs; updatePeer loest syncAgentConfigs aus
- **PostUp Route Generation** (v1.3.10) — `buildHubPostUp`/`buildHubPostDown` generieren `ip route add/del` fuer alle Peer-AllowedIPs; Agents verlieren keine Routen nach Neustart
- **Hub-LAN MASQUERADE** (v1.3.11) — Zwei MASQUERADE-Regeln pro physischem Interface (lokales Subnet + Tunnel-Subnet); MASQUERADE-Regex erkennt beide Reihenfolgen
- **AllowedIPs Conflict Blocking** (v1.3.12) — Doppelte Subnet-Zuweisungen werden blockiert; Metadata-Aenderungen sofort live; syncHubConf synct alle Interfaces
- **Stale Route Cleanup** (v1.3.12) — `sync_routes()` entfernt veraltete wg0-Routen und ueberspringt physisch angeschlossene Netze; Hub-Seite filtert ebenfalls
- **Road Warrior AllowedIPs** (v1.3.13) — Config-Export fuer Road Warriors (Laptop/Mobile) sammelt automatisch alle exportedNetworks anderer Peers; Endpoint nutzt Domain statt IP; Key-Rotation verliert keine Metadata mehr
- **WG-Netzwerkfeld-Validierung** (v1.3.14) — `importedNetworks`/`exportedNetworks`/`routeTargets` werden am Eingang UND an der Sink-Seite (`syncHubConf`) strikt als IPv4/IPv6-CIDR validiert (Command-Injection-Schutz, da die Werte als root in `ip route add` fliessen); Rate-Limit auch auf `GET /api/agent/install`
- **Hub-URL-Propagation + Agent-ACL-Editor** (v1.3.15) — `GET /api/agent/config` liefert die Hub-URLs aus dem Setting `agent-hub-url`; der Agent uebernimmt sie in `config.env` erst nach `reach`-Check (Typo brickt keinen Agent); `allowed_networks` pro Agent in der UI editierbar (loest `syncAgentConfigs` aus); strikte ACL-CIDR-Validierung (jedes `/0` abgelehnt); `sanitizeHubUrl`
- **Zentrale Hub-URL-Einstellung** (v1.3.16) — der pro-Agent-Hub-URL-Editor aus v1.3.15 ist jetzt ein einziges globales Steuerelement oben im WireGuard-Tab „Overview" (reine UI-Umstellung)
- **Hub→Agent-Sync gehaertet** (v1.3.21) — REMOVE/DELETE/RENAME propagieren zuverlaessig: `deletePeer`/`deleteInterface`/Link-Rename/`createPeer`/`wg_link_name`-Rebind triggern jetzt `syncAgentConfigs`, plus ein 5-Min-Reconciler als Defense-in-Depth; alle Metadaten-Store-Mutationen + Reconciler unter `withWriteLock` (kein Lost-Write); Hub autoritativ fuer Hub-Peer-AllowedIPs; Per-Agent-Fehlerisolierung im Sync-Loop; `%i`→`$iface` vor `eval` (MASQUERADE/FORWARD); Site-Netze strikt IPv4 + kanonisch (IPv6 abgelehnt, Host-Bits maskiert); Root-Command-Injection im Install-Skript geschlossen; `last_server_url` im Heartbeat fuer Hub-Move-Sichtbarkeit. (Konsolidiert die Tages-Releases v1.3.17–v1.3.20.)

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
