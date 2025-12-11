# FloppyGuard Technical Roadmap

Stand: 2026-04-19

## Ziel

Diese Roadmap uebersetzt den aktuellen Repo-Stand in konkrete technische Arbeitspakete fuer den Fork unter `/var/www/nginx-proxy-manager-fork-base`.

## Prioritaet 1: WireGuard-Domain stabilisieren

Ziel:
`wireguard/status` soll fachlich belastbarer werden, bevor echte Schreibzugriffe auf Live-Konfigurationen kommen.

Arbeitspakete:

- Link-Typen und Rollen vereinheitlichen
  - Altwerte wie `site-link` beim Einlesen auf `site-to-site` normalisieren
- API-Form finalisieren fuer:
  - `interfaces`
  - `links`
  - `routes`
  - `topology`
  - `capabilities`
- Heuristiken fuer:
  - `exportedNetworks`
  - `importedNetworks`
  - `returnPathMode`
  - `warnings`
  - konservative `wg0`-Klassifikation fuer Client-Links statt vorschneller `site-to-site`-Einordnung

Betroffene Dateien:

- `backend/internal/wireguard.js`
- `backend/routes/wireguard.js`
- `frontend/src/api/backend/models.ts`
- `docs/FloppyGuard_WireGuard_Domain_Model_2026-04-19.md`

Abnahme:

- API-Felder sind dokumentiert und konsistent
- keine Typ-/Namensdrift zwischen Backend, Frontend und Doku
- `wg0`-Client-Faelle bleiben in Backend, Frontend und Doku gleich modelliert

## Prioritaet 2: WireGuard-UI als Arbeitsoberflaeche fertigziehen

Ziel:
Die vorhandene Seite `/wireguard` soll vom Status-Screen zu einer klaren Arbeitsansicht werden.

Arbeitspakete:

- Bereiche klar trennen:
  - Interfaces
  - Client Links
  - Site-to-Site / Hub Links
  - Routing & Reachability
  - Warnings / Next Actions
- Metadaten-Editor ausbauen:
  - Interface-Metadaten
  - Link-Metadaten
  - bessere Validierung und Speichern-Feedback
- Planner-Preview in eine gefuehrte UI ueberfuehren

Betroffene Dateien:

- `frontend/src/pages/WireGuard/index.tsx`
- `frontend/src/hooks/useWireGuardStatus.ts`
- `frontend/src/hooks/useWireGuardMetadata.ts`
- `frontend/src/api/backend/getWireGuardStatus.ts`
- `frontend/src/api/backend/updateWireGuardMetadata.ts`

Abnahme:

- Seite ist ohne Doku verstaendlich bedienbar
- Planungsdaten koennen bearbeitet und wieder geladen werden

## Prioritaet 3: Gateway- und Platform-Seiten an das Modell anbinden

Ziel:
`/gateway` und `/platform` sollen dieselbe Domäne sprechen wie `/wireguard`, nicht nur dekorative Zusammenfassungen liefern.

Arbeitspakete:

- Gateway auf:
  - importierte Netze
  - exportierte Netze
  - fehlende Rueckwege
  - NAT-Kandidaten
  - Konflikte
  ausrichten
- Platform-Seite auf reale Faehigkeiten und naechste Schritte ausrichten
- Statuskarten an `capabilities` koppeln

Betroffene Dateien:

- `frontend/src/pages/Gateway/index.tsx`
- `frontend/src/pages/Platform/index.tsx`
- `frontend/src/api/backend/models.ts`

Abnahme:

- dieselben Begriffe und Typen wie in `wireguard/status`
- keine abweichenden Eigeninterpretationen im Frontend

## Prioritaet 4: Sicheren Write-Layer vorbereiten

Ziel:
Vor echtem Host-Schreiben muessen Backup, Diff und Fehlerpfade sauber definiert sein.

Aktueller Stand:

- `plan-preview` ist vorhanden
- `apply-metadata` ist fuer `metadata-only` produktiv vorhanden
- Backups, Apply-Audit und `restore-metadata` fuer Metadaten sind vorhanden
- echter Live-Write fuer WireGuard-/Routing-Konfiguration bleibt weiter gesperrt

Arbeitspakete:

- Restore-Preview vor echtem Restore bauen
- Audit-/Historienansicht ausbauen
- Write-Konzept definieren fuer:
  - Peer CRUD
  - Interface CRUD
  - Config-Generierung
  - Share-/Install-Flows
- Trennung zwischen:
  - metadata-write
  - metadata-restore
  - config-write
  - remote-apply
- spaeterer Host-Write nur mit:
  - Diff
  - Backup
  - Fehlerpfad
  - Rollback

Betroffene Dateien:

- neue Backend-Module unter `backend/internal/`
- neue oder erweiterte Routen unter `backend/routes/`
- `docs/FloppyGuard_Fork_Plan_2026-04-19.md`

Abnahme:

- Metadaten-Apply und Metadaten-Restore sind nachvollziehbar und rueckverfolgbar
- kein Live-Schreibcode fuer WireGuard-/Routing-Hostzustand ohne dokumentierten Backup- und Rollback-Pfad

## Prioritaet 5: Tests und Betriebsfaehigkeit

Ziel:
Die neuen FloppyGuard-Funktionen brauchen belastbare Regression-Sicherheit.

Arbeitspakete:

- Backend-Tests fuer WireGuard-Heuristiken und Metadatenpersistenz
- Frontend-Tests fuer:
  - `/wireguard`
  - `/gateway`
  - `/platform`
- Smoke-Test fuer Preview-Start und Kernnavigation
- Produktionsmodus weiter haerten:
  - systemd
  - statisches Frontend-Serving
  - klar getrennte Datenpfade

Betroffene Dateien:

- `frontend/src/App.smoke.test.tsx`
- neue Tests in `frontend/src/**`
- `test/`
- `scripts/start-production`
- `scripts/stop-production`
- `docs/PRODUCTION_MODE.md`

Abnahme:

- Kernpfade laufen reproduzierbar lokal
- neue WireGuard-Features brechen nicht stillschweigend
- zentrale Heuristiken wie `wg0 -> client` sind explizit regression-getestet

## Empfohlene Reihenfolge

1. Domain-Modell konsistent machen
2. WireGuard-Seite strukturieren und Metadaten-UI sauber machen
3. Gateway und Platform auf dasselbe Modell ziehen
4. Write-Layer entwerfen, noch nicht blind implementieren
5. Tests und Produktionshaertung nachziehen

## Nicht jetzt

- direkte Live-Aenderungen an `/etc/wireguard`
- Remote-Apply per SSH oder Agent
- grosse UX-Ausbauten ohne stabiles Backend-Modell
