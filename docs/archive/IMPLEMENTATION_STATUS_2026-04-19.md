# FloppyGuard Implementation Status

Stand: 2026-04-19

## Bereits vorhanden

- Fork basiert klar auf NPM `2.14.0`-Generation, aber mit bewussten FloppyGuard-Erweiterungen
- lokale Preview und produktionsnaehere Laufskripte sind vorhanden:
  - `scripts/start-local-preview`
  - `scripts/start-production`
- neue Produktseiten sind bereits eingebunden:
  - `/`
  - `/platform`
  - `/gateway`
  - `/wireguard`
- WireGuard-Backend ist angeschlossen:
  - `GET /api/wireguard/status`
  - `GET /api/wireguard/metadata`
  - `PUT /api/wireguard/metadata`
  - `POST /api/wireguard/plan-preview`
  - `POST /api/wireguard/apply-metadata`
  - `GET /api/wireguard/apply-state`
  - `POST /api/wireguard/restore-metadata`
- `wireguard/status` liefert bereits:
  - Interfaces
  - Peers
  - Links
  - Routes
  - Topology
  - Capabilities
  - Summary
  - Warnings / Next Actions
- UI kann bereits Link-Metadaten fuer Planungszwecke speichern
- UI arbeitet jetzt mit Review-/Preview-Logik vor dem Speichern:
  - Planner
  - Link-Metadateneditor
  - Interface-Editor
- Metadaten koennen jetzt real angewendet werden, aber nur fuer `metadata-only`
- vor jedem Apply wird ein Backup erzeugt
- Backup-Liste, letzter Apply und Restore sind im WireGuard-UI sichtbar
- Tests sind jetzt vorhanden fuer:
  - Frontend-Seiten `/wireguard`, `/gateway`, `/platform`
  - Backend-Heuristiken in `backend/internal/wireguard.js`
  - einen schmalen Backend-Integrationstest fuer `getStatus()`
  - Dry-Run / Apply / Restore in `backend/internal/wireguard-plan.js`

## Teilweise vorhanden

- WireGuard-Domaenenmodell ist begonnen, aber noch heuristisch
  - Rollen wie `client-hub`, `site-to-site`, `hub-link`
  - Return-Path- und Remote-Management-Felder
  - `wg0`-Peers mit genau einem privaten Netz werden inzwischen bewusst als `client` behandelt
  - noch keine belastbare Netzmodellierung fuer alle Faelle
- WireGuard-UI ist mehr als ein Status-Screen
  - Topology Map
  - Link Planner Preview
  - Routing Hints
  - Apply-Readiness
  - Backup-/Restore-Status
  - aber noch kein gefuehrter Wizard
- sicherer Write-Layer ist begonnen, aber noch bewusst eng begrenzt
  - aktuell nur Metadaten-Datei
  - noch kein Live-Write fuer `wg` / Routen / Host-Konfig
- Produktionsmodus ist als Laufmodus vorbereitet
  - aber noch ohne systemd/nginx/static-serving-Haertung

## Fehlt noch

- echter Write-Layer fuer WireGuard-Configs
  - Peer CRUD
  - Interface CRUD
  - Config-Generierung / Download / QR
  - `wg set` / Conf-Write / Reload
- sauberer Wizard fuer Site-to-Site / Hub-to-Hub
- Remote-Management via SSH oder Agent
- Restore-Preview vor echtem Backup-Restore
- bessere Audit-/Historienansicht statt nur letzter Aktion
- breitere Testabdeckung fuer mehr Randfaelle der WireGuard-Heuristik
- bereinigte und konsolidierte Projektdoku fuer den Fork als Produktbasis

## Wichtige Klarstellung

Der aktuelle Stand ist **nicht** mehr nur read-only. Korrekt ist:

- Live-WireGuard-Konfigurationen werden noch nicht geschrieben
- Planungsrelevante Metadaten werden gelesen, geprueft, angewendet und aus Backups wiederhergestellt
- der Fork ist damit aktuell `runtime-read + metadata-write + metadata-restore`, nicht `full write`

## Naechster Arbeitsrahmen

Die priorisierte technische Umsetzungsreihenfolge steht in:

- `docs/TECHNICAL_ROADMAP_2026-04-19.md`
- `docs/WORKLOG_2026-04-19.md`
