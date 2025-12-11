# FloppyGuard WireGuard Domain Model

Stand: 2026-04-19

## Zweck

Dieses Dokument konkretisiert Phase 1 aus dem Fork-Plan:

- das bestehende WireGuard-Modul im Fork soll von einem Runtime-Status plus Metadaten-Layer zu einem fachlich brauchbaren Netzwerk- und Link-Modell erweitert werden
- diese Struktur ist die Grundlage fuer spaetere UI-Ausbaustufen, Wizard-Logik und einen sicheren Write-Layer

## Aktueller Stand im Fork

Der Fork liefert heute bereits ueber `wireguard/status`:

- Interfaces
- aktive Peers
- Routen
- Traffic
- Links
- Topology
- Capabilities
- Next Actions / Warnings
- Hub-Zusammenfassung
- einfache Warnungen

Ueber `wireguard/metadata` koennen heute bereits Interface- und Link-Metadaten gespeichert werden. Das ist noch **kein** Live-Write-Layer fuer WireGuard-Configs, aber bereits mehr als reines read-only.

Neu hinzugekommen sind:

- `wireguard/plan-preview` fuer Dry-Run / Diff / Warnungen
- `wireguard/apply-metadata` fuer echten, aber bewusst begrenzten Metadaten-Apply
- `wireguard/apply-state` fuer Backup- und Audit-Status
- `wireguard/restore-metadata` fuer Restore eines bekannten Metadaten-Backups

Das ist als Runtime-Inventar gut, aber fachlich noch zu flach fuer:

- Site-to-Site
- Hub-to-Hub
- Routing-Planung
- NAT-/Rueckweg-Analyse
- Remote-Management

## Ziel

Die API soll kuenftig nicht nur technische Live-Daten liefern, sondern ein erstes fachliches Modell fuer:

- Interfaces
- Links
- exportierte Netze
- importierte Netze
- Reachability / Return Path
- Remote-Management-Faehigkeit
- Warnungen und naechste Schritte

## Fachliche Zielobjekte

### 1. Interface

Ein WireGuard-Interface auf dem lokalen Host.

Neue Felder:

- `role`
  - `client-hub`
  - `site-to-site`
  - `hub-link`
  - `auxiliary`
  - `unknown`
- `managementMode`
  - `local`
  - `imported`
  - `unknown`
- `exportedNetworks`
- `importedNetworks`
- `routeTargets`
- `health`
  - `healthy`
  - `warning`
  - `inactive`
- `notes[]`

### 2. Link

Ein logischer Verbindungsdatensatz auf einem Interface.
Nicht jeder Peer ist nur ein Client. Ein Peer kann auch ein Site-to-Site- oder Hub-Link sein.

Neue Felder:

- `id`
- `interfaceName`
- `type`
  - `client`
  - `site-to-site`
  - `hub-link`
  - `imported`
  - `unknown`
- `name`
- `peerPublicKey`
- `remoteEndpoint`
- `allowedIps`
- `tunnelAddresses`
- `exportedNetworks`
- `importedNetworks`
- `latestHandshake`
- `rxBytes`
- `txBytes`
- `active`
- `hasMetadata`
- `returnPathMode`
  - `auto`
  - `routed`
  - `static-route`
  - `nat`
  - `unknown`
- `remoteManagementMode`
  - `none`
  - `ssh`
  - `agent`
  - `unknown`
- `warnings[]`
- `nextActions[]`

### 3. Routing Analysis

Neuer Analyseblock fuer das Gesamtbild des Hosts.

Neue Felder:

- `exportedNetworks`
- `importedNetworks`
- `staticRoutes`
- `wireguardRoutes`
- `missingReturnRoutes`
- `natCandidates`
- `conflicts`
- `splitTunnelCandidates`
- `observations[]`

### 4. Capabilities

Ein eigener Block, um zwischen Runtime-Read, Metadaten-Write und spaeteren echten Write-Modi unterscheiden zu koennen.

Vorschlag:

```json
{
  "mode": "metadata-write",
  "supports": {
    "peerCrud": false,
    "interfaceCrud": false,
    "configDownload": false,
    "shareLinks": false,
    "wizardPlanning": true,
    "metadataCrud": true,
    "remoteSsh": false,
    "remoteAgent": false
  }
}
```

Das hilft fuer die UI, damit Aktionen bewusst als geplant, readonly oder spaeter markiert werden koennen.

### 5. Metadata Apply Lifecycle

Der Fork hat jetzt einen klaren Zwischenzustand zwischen Preview und spaeterem Live-Write:

- Preview:
  - validiert Patch-Ziele
  - erzeugt Diff
  - leitet Warnungen / Next Actions / Apply-Readiness ab
- Apply:
  - nur fuer `metadata-only`
  - nur wenn `apply.canApply === true`
  - erzeugt vor dem Schreiben ein Backup
  - schreibt nur die Metadaten-Datei
- Restore:
  - nur fuer serverseitig bekannte Backups
  - erzeugt vor dem Restore erneut ein Backup des aktuellen Stands
  - schreibt ebenfalls nur die Metadaten-Datei

Wichtig:

- das ist **kein** Live-Write fuer `wg`-Konfiguration, `wg set` oder Systemrouten
- das ist ein sicherer Metadaten-Layer mit Preview, Apply, Backup, Audit und Restore

## Heuristiken fuer die erste Ausbaustufe

Die erste Version muss nicht perfekt sein. Sie darf mit klaren Heuristiken arbeiten.

### Interface-Rolle

- `wg0` -> standardmaessig `client-hub`
- weiteres `wgN` mit wenigen Peers und privaten Zielnetzen -> eher `site-to-site` oder `hub-link`
- kein klares Muster -> `unknown`

### Link-Typ

- nur eine einzelne Tunnel-IP oder einzelnes Client-/32-Netz -> eher `client`
- auf `wg0` gilt konservativ:
  - null oder genau ein privates Zielnetz -> eher `client`
  - mehrere private Zielnetze -> eher `hub-link`
- mehrere private Netze hinter einem Peer -> eher `site-to-site`
- dedizierter Link zwischen zwei Hubs / mehreren Standortnetzen -> eher `hub-link`
- keine Metadaten / unklare AllowedIPs -> `unknown` oder `imported`

Das ist absichtlich vorsichtig, damit klassische `wg0`-Road-Warrior- oder Client-Peers nicht zu frueh als `site-to-site` modelliert werden.

### Exported vs Imported Networks

- `importedNetworks` = Netze aus Peer-AllowedIPs, die ueber die Gegenstelle erreichbar werden
- `exportedNetworks` = lokale RFC1918- oder relevante Hostnetze, die ueber diesen Link veroeffentlicht werden sollen oder bereits bekannt sind

Die erste Ausbaustufe darf `exportedNetworks` auch zunaechst konservativ halten und als heuristische Kandidaten markieren.

### Return Path / NAT Hinweise

Wenn importierte Netze sichtbar sind, aber keine passenden Rueckweg-Hinweise oder nur asymmetrische Konstellationen vorliegen, sollen Warnungen entstehen:

- `missingReturnRoute`
- `natLikelyNeeded`
- `remoteSideUnknown`

## Zielstruktur fuer `wireguard/status`

Vorschlag fuer die neue API-Form:

```json
{
  "available": true,
  "mode": "metadata-write",
  "hub": {},
  "interfaces": [],
  "links": [],
  "routes": {
    "all": [],
    "wireguard": [],
    "privateRoutes": [],
    "missingReturnRoutes": [],
    "natCandidates": [],
    "conflicts": [],
    "splitTunnelCandidates": []
  },
  "topology": {
    "exportedNetworks": [],
    "importedNetworks": [],
    "siteLinks": [],
    "clientLinks": [],
    "hubLinks": []
  },
  "capabilities": {
    "mode": "metadata-write",
    "supports": {
      "peerCrud": false,
      "interfaceCrud": false,
      "configDownload": false,
      "shareLinks": false,
      "wizardPlanning": true,
      "metadataCrud": true,
      "remoteSsh": false,
      "remoteAgent": false
    }
  },
  "summary": {},
  "warnings": [],
  "nextActions": []
}
```

## Nutzen fuer die UI

Mit dieser Struktur kann die Fork-UI deutlich zielgerichteter werden.

### `/wireguard`

Kann gegliedert werden in:

- Interfaces
- Client Links
- Site-to-Site / Hub Links
- Routing & Reachability
- Warnings / Next Actions

### `/gateway`

Kann statt reiner Routenliste zeigen:

- importierte Netze
- exportierte Netze
- fehlende Rueckwege
- NAT-Kandidaten
- Konflikte

## Aktuelle Klarstellung zur Heuristik

Stand heute ist die Heuristik bewusst konservativ:

- `wg0` bleibt als Interface `client-hub`
- ein einzelner privater Peer auf `wg0` wird als `client` modelliert
- `site-to-site` soll eher auf dedizierten `wgN`-Interfaces oder bei mehreren privaten Zielnetzen auftauchen

Das ist inzwischen durch Backend- und Frontend-Tests abgesichert und nicht mehr nur eine lose Modellannahme.

### `/platform`

Kann den Reifegrad des Produkts sauberer anzeigen:

- Runtime visibility complete
- topology modeling in progress
- safe write layer pending
- remote management pending

## Erster Implementierungsblock

### Block 1A: Backend-Datenmodell erweitern

In `backend/internal/wireguard.js`:

- Interface-Rollen einfuehren
- Link-Inventar aus Dumps + Config ableiten
- imported/exported network sets bilden
- erste NAT-/Return-Path-Heuristiken erzeugen
- `capabilities` und `nextActions` hinzufuegen

Noch keine Schreiblogik.

### Block 1B: Frontend-Modelle erweitern

In `frontend/src/api/backend/models.ts`:

- neue Typen fuer `WireGuardLink`
- neue Felder fuer `WireGuardInterface`
- neue Routing-/Topology-Typen
- `capabilities` und `nextActions`

### Block 1C: UI auf neue Struktur vorbereiten

In `frontend/src/pages/WireGuard/index.tsx`:

- aktive Peers nicht mehr als alleinige Hauptsicht
- eigene Sektionen fuer:
  - interfaces
  - links
  - topology
  - warnings

## Noch bewusst nicht Teil dieses Blocks

- Peer CRUD
- Interface Write
- QR/Config Download
- Share Links
- Remote SSH Apply
- Agent

Diese Dinge kommen spaeter auf Basis des hier beschriebenen Modells.

## Kurzfazit

Der wichtigste Schritt jetzt ist, den Fork nicht nur als Status-Dashboard weiterzubauen, sondern als echte fachliche WireGuard- und Netzwerkbasis.

Das Ziel fuer Phase 1 ist deshalb:

- aus Runtime-Daten ein erstes brauchbares Netzwerkmodell ableiten
- damit UI, Wizard und Write-Layer spaeter sauber darauf aufbauen koennen
