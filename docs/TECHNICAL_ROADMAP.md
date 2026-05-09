# FloppyGuard Technical Roadmap

Stand: 2026-05-04

## Was bereits fertig ist

- WireGuard read + metadata-write Layer
- Agent-System (register, heartbeat, service discovery, install one-liner)
- Remote management mode `agent` — Agents direkt auf WireGuard-Link-Karten
- Link-Planer (type, networks, return path, management mode) — direkt speicherbar
- Service-Buttons direkt auf Link-Karten sichtbar
- **WireGuard Routing Automation** — `syncHubConf` + `syncAgentConfigs` on every apply;
  hub wg0.conf und alle Agent-Configs werden automatisch aktualisiert
- **Agent Self-Update** — `AGENT_SCRIPT_VERSION` + `GET /api/agent/loop-script`;
  Agents updaten sich selbst innerhalb von 30s bei Version-Bump
- **Kernel Route Sync** — `sync_routes()` im Loop-Script addiert fehlende ip-Routes
  nach `wg syncconf` (wg syncconf berührt die Kernel-Routing-Tabelle nicht)
- CI-Pipeline (Backend Lint + Test, Frontend Lint + Build, OpenAPI Lint)
- **Peer CRUD** (v1.3.1) — `deletePeer` + `updatePeer` mit Live-`wg set`, Conf-Rewrite, Metadata-Cleanup und Safety-Backup
- **Live-vs-Conf Drift-Fix** (v1.3.1) — `syncHubConf` vergleicht jetzt Live-State gegen Conf und korrigiert automatisch

## Empfohlene Reihenfolge

1. WireGuard Live-Write-Layer (P1)
2. Gateway + Platform an Domain-Modell koppeln (P2)
3. Tests und Betriebshärtung (P3)

---

## P1 — WireGuard Live-Write-Layer

Ziel: echte WireGuard-Konfigurationsänderungen mit Diff, Backup, Rollback.

- ~~Peer CRUD (add/modify/delete peers via `wg set` + conf-write)~~ ✔ v1.3.1
- ~~Interface CRUD~~ ✔ v1.3.1
- ~~Config-Generierung + QR-Code / Client-Export~~ ✔ v1.2.4
- Restore-Preview vor echtem Restore
- Audit-Historienansicht ausbauen
- Klare Trennung: `metadata-write` / `config-write` / `remote-apply`

Betroffene Dateien:
- `backend/internal/wireguard.js`
- `backend/internal/wireguard-plan.js`
- `backend/routes/wireguard.js`
- `frontend/src/pages/WireGuard/index.tsx`

---

## P2 — Gateway + Platform an Domain koppeln

- Gateway auf importierte/exportierte Netze, fehlende Rückwege, NAT-Kandidaten ausrichten
- Platform auf reale Capabilities und nächste Schritte ausrichten
- Statuskarten an `capabilities` koppeln

Betroffene Dateien:
- `frontend/src/pages/Gateway/index.tsx`
- `frontend/src/pages/Platform/index.tsx`

---

## P3 — Tests + Betriebshärtung

- Backend-Tests für WireGuard-Heuristiken und Metadatenpersistenz
- Backend-Tests für Agent-System (register, heartbeat, token-reset, service scan)
- Frontend-Tests für `/wireguard`
- wg-gui (Port 8080) ablösen sobald WireGuard-UI stabil
- Logrotate und monitoring ausbauen

---

## Nicht jetzt

- Remote-Apply per SSH (agent-mode ist bereits live)
- Große UX-Ausbauten ohne stabiles Backend-Modell
- MariaDB Docker-Container entfernen (erst nach vollständiger Datenmigration verifizieren)
