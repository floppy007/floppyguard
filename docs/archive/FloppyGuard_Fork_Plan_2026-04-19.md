# FloppyGuard Fork Plan

Stand: 2026-04-19

## Ausgangslage

Aktueller Hauptpfad fuer FloppyGuard ist nicht mehr die alte PHP-App unter `/var/www/wg-gui`, sondern der Produkt-Fork auf Basis von Nginx Proxy Manager unter:

- `/var/www/nginx-proxy-manager-fork-base`

Der Fork ist bereits deutlich weiter als nur ein Rohgeruest:

- FloppyGuard Branding ist vorhanden
- Preview laeuft lokal auf dem Host
- Live-NPM-Daten koennen in die Preview importiert werden
- neue Produktseiten existieren bereits:
  - Dashboard
  - Platform
  - Gateway
  - WireGuard
- ein erstes WireGuard-Modul mit Runtime-Read plus Metadaten-Write ist bereits integriert

Gleichzeitig bleibt die alte PHP-App fachlich wichtig, weil dort noch die produktiven WireGuard-Schreibfunktionen und die heute vollstaendigere WG-Funktionalitaet liegen.

## Was bereits im Fork vorhanden ist

### Infrastruktur und Preview

- lokale Preview via Vite + Node Backend
- Frontend Preview auf `:5173`
- Backend Preview auf `:3300`
- Import-Skript fuer Live-NPM-Daten vorhanden
- Vorschau-Login vorhanden

### Produktseiten

Im Fork sind bereits eigene Seiten fuer die neue Produktstruktur vorhanden:

- `/`
- `/platform`
- `/gateway`
- `/wireguard`
- bestehende NPM-Bereiche wie Proxy, Certificates, Access, Users etc.

### WireGuard im Fork

Aktuell existiert ein Backend-Modul mit lesendem Host-Zugriff und einer kleinen persistierten Planungs-/Metadaten-Schicht:

- `backend/internal/wireguard.js`
- `backend/routes/wireguard.js`

Dieses liefert heute bereits:

- erkannte WireGuard-Interfaces
- aktive und inaktive Interfaces
- Peer-Anzahl / aktive Peer-Anzahl
- RX/TX Werte
- erkannte WireGuard-Routen
- private Routen
- abgeleitete Link-Typen
- Topologie-Block
- Capabilities-Block
- persistierte Interface-/Link-Metadaten
- Hub-Zusammenfassung

Die aktuelle UI zeigt damit bereits:

- WireGuard-Inventar
- Interface-Liste
- aktive Peers
- Gateway-/Routing-Vorschau
- Plattform-Summary
- einfacher Link-Planer mit Diff-Vorschau
- Editierbarkeit von Link-Metadaten ohne Live-Config-Schreibzugriff

## Was in der alten PHP-App noch vorhanden ist und im Fork fehlt

Die alte App unter `/var/www/wg-gui` enthaelt noch die vollere operative WireGuard-Fachlogik.

### Noch nicht in den Fork uebernommen

- Peer CRUD fuer `wg0`
  - anlegen
  - bearbeiten
  - loeschen
- Client-Config-Erzeugung
  - Konfig anzeigen
  - Download
  - QR-Code
- Share-/Install-Flow
  - Install-Token
  - Config-Link
  - Install-Script-Link
  - Token-Revoke
- Settings fuer WG-App
  - Endpoint Host/Port
  - Client AllowedIPs Default
  - Admin-/App-bezogene Einstellungen
- Interface-Write-Funktionen
  - Interface anlegen
  - Config speichern
  - entfernen
  - Labels pflegen

## Wichtige Hinweise aus der vorhandenen Projektdoku

Die vorhandene Doku zeigt klar, dass das Ziel nicht nur eine Portierung der alten Peer-GUI ist.

### 1. NPM-Fork ist die strategische Hauptbasis

Die vorhandenen Dateien `docs/HANDOFF_2026-04-15.md`, `docs/LIVE_2_14_GAP.md` und `docs/LOCAL_PREVIEW.md` beschreiben den Zielpfad eindeutig:

- bestehendes Live-NPM bleibt zunaechst unangetastet
- neuer Produktweg geht ueber den NPM-Fork
- WireGuard wird zuerst lesend integriert
- danach folgt ein sicherer Write-Layer fuer echte Host-Aenderungen
- erst spaeter erfolgt ein produktiver Cutover

### 2. WireGuard soll zum Netzwerk- und Routing-Produkt ausgebaut werden

`/var/www/wg-gui/docs/NETWORK-WIZARD-CONCEPT-2026-04-17.md` beschreibt die eigentliche naechste Produktstufe:

Nicht nur Peer-Verwaltung, sondern ein **Network Wizard**, der modelliert:

- Interface
- Link
- exportierte Netze
- importierte Netze
- Return-Path-Mode
- Remote-Management

Ziel ist nicht nur das Editieren von AllowedIPs, sondern die saubere Modellierung von:

- Site-to-Site
- Hub-to-Hub
- Routing
- NAT
- Rueckwegen
- Gegenstellenanpassungen

### 3. Remote-Management ist fachlich bereits vorgesehen

In der Konzeptdoku sind fuer Gegenstellen-Management bereits drei Stufen vorgesehen:

- `none`
- `ssh`
- `agent`

Das bedeutet:
FloppyGuard soll perspektivisch nicht nur lokal anzeigen oder lokal schreiben, sondern spaeter auch entfernte Knoten orchestrieren koennen.

## Strategische Entscheidung

Ab jetzt wird **im Fork weitergebaut**, nicht mehr primaer in der alten PHP-App.

Die alte PHP-App bleibt:

- Referenz fuer bestehende WireGuard-Funktionalitaet
- Quelle fuer spaeter zu portierende Fachlogik
- Hilfsmittel fuer Datenmodell und vorhandene Ablaufe

Der Fork wird:

- Hauptproduktbasis
- neue UI- und API-Heimat
- Ort fuer weitere WireGuard-, Routing- und Netzwerk-Funktionen

## Produktbild ab jetzt

FloppyGuard ist nicht nur eine Peer-Verwaltungsoberflaeche, sondern soll sich entwickeln zu einer:

- Reverse-Proxy- und Gateway-Plattform
- WireGuard Control Plane
- Netzwerk-/Routing-Planungsoberflaeche
- Site-to-Site- und Hub-to-Hub-Steuerung
- spaeter moeglicherweise Agent-gestuetzte Multi-Node-Verwaltung

## Empfohlene Prioritaet fuer die naechsten Arbeiten

Die Prioritaet verschiebt sich dadurch leicht.

Nicht zuerst blind Peer-CRUD portieren, sondern zuerst das fachliche Fundament im Fork richtig anlegen.

## Arbeitsplan

### Phase 1: WireGuard-Domain im Fork schaerfen

Ziel:
Das aktuelle Runtime-/Metadaten-Modul von einem reinen Runtime-Status auf ein fachlich brauchbares Domänenmodell erweitern.

Zu ergaenzende fachliche Konzepte:

- Interface-Rollen
  - client-hub
  - site-to-site
  - hub-link
  - auxiliary
- Link-/Peer-Typen
  - client
  - site-to-site
  - hub-link
  - imported/unknown
- exportierte Netze
- importierte Netze
- Return-Path-Hinweise
- NAT-Kandidaten
- Remote-Management-Hinweise
- Warnungen und Plausibilitaetspruefungen

Geplantes Ergebnis:
Eine API-Antwort, die nicht nur technische Live-Daten, sondern ein erstes fachliches Netzwerkmodell liefert.

### Phase 2: WireGuard UI im Fork neu strukturieren

Ziel:
Die bestehende `/wireguard`-Seite von einem reinen Status-Screen zu einer Arbeitsoberflaeche ausbauen.

Empfohlene Bereiche:

- Hub / Interfaces
- Client Peers
- Site-to-Site / Hub Links
- Routing & Reachability
- Warnings / Next Actions

Wichtig:
Die UI soll zuerst lesend und analysierend sein, nicht sofort schreibend.

### Phase 3: Wizard-Vorstufe als Planer

Ziel:
Ersten Planungsflow schaffen, noch ohne Live-Schreibzugriff.

Mindestumfang:

- Link-Typ waehlen
- lokale Netze exportieren
- entfernte Netze importieren
- Return-Path-Modell waehlen
- Hinweise auf fehlende Gegenstellen- oder NAT-Anpassungen
- Plan-/Diff-Vorschau

Noch kein Ziel dieser Phase:

- direkte produktive Aenderung an Live-Interfaces
- direkte Remote-Ausrollung

### Phase 4: Sicheren Write-Layer vorbereiten

Ziel:
Schreibende WireGuard-Funktionen erst nach sauberem Modell und Planungslogik in den Fork holen.

Erst spaeter zu portieren:

- Peer CRUD
- Config/QR/Share
- Interface-Write
- Remote-Apply

Regel:

- zuerst Runtime und Metadaten sauber verstehen
- dann planen
- dann gezielt schreiben

### Phase 5: Remote-Management vorbereiten

Ziel:
Die im Konzept vorgesehene Fernverwaltung fachlich vorbereiten.

Stufenmodell:

- none
- ssh
- agent

Zuerst nur im Modell und in der Doku beruecksichtigen.
Noch keine vorschnelle technische Implementierung.

## Konkreter naechster Umsetzungsschritt

Der direkt naechste technische Block ist:

### `WireGuard Domain Model + API Expansion`

Konkret:

- bestehende `wireguard/status` Antwort im Fork analysieren und erweitern
- sinnvolle neue Felder fuer Link-, Netz- und Routing-Modell definieren
- daraus eine erste klare Datenbasis fuer die neue `/wireguard`-Arbeitsoberflaeche schaffen

## Kurzfazit

Der Fork sieht bereits gut aus und ist als neue Hauptbasis richtig.

Die naechste sinnvolle Arbeit ist nicht, die alte WG-App 1:1 nachzubauen, sondern:

- die Produktidee aus den vorhandenen Docs ernst zu nehmen
- das WireGuard-/Netzwerkmodell im Fork sauber zu verankern
- darauf aufbauend spaeter Wizard, Write-Layer und Remote-Management zu entwickeln
