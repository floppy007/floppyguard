# Changelog

All notable changes to FloppyGuard are documented here.
This project diverges from upstream nginx-proxy-manager starting at v1.0.0.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [1.3.24] – 2026-06-20

Schließt die wiederkehrende „Tunnel nach Reboot tot"-Fehlerklasse strukturell: Der WireGuard-Endpoint in Agent-Configs wird jetzt vom Hub propagiert, statt einmalig beim Install eingebacken zu bleiben. Entwickelt mit anschließendem Multi-Agent-Audit (Finden → adversariale Verifikation → Fix, vier Durchläufe). Health-Stack grün (Backend 106/106, Frontend tsc + beide Lints sauber). Reiner Hub-seitiger Fix — `AGENT_SCRIPT_VERSION` bewusst auf 1.3.23 gelassen (das Agent-Skript ist unverändert, kein Flotten-Restart nötig; Agents ziehen die neue `config_text` beim normalen Poll).

### Fixed

- **WG-Endpoint propagiert jetzt an bestehende Agents (Hub ist autoritativ).** Bisher setzte nur die Erst-Generierung den `[Peer] Endpoint` aus `WG_HUB_HOST`; `syncAgentConfigs` schrieb ausschließlich die `AllowedIPs` um. Ein Hub-Domain-Wechsel (z. B. `floppyguard.comnic.de` → `hub.comnic.de` → `proxy.comnic.de`) erreichte deshalb keine bereits installierte Agent-Config — die veraltete, dual-stack-aufgelöste Domain blieb eingebacken und führte nach jedem Reboot zum Blackhole, wenn der Standort kein funktionierendes IPv6 hat (3× live aufgetreten: PVE, Floppy Home, Daniel Home). `_syncOneAgent` schreibt die Endpoint-Zeile jetzt bei jedem Sync aus `WG_HUB_HOST` neu, sodass die Änderung beim nächsten ~30-s-Poll die ganze Flotte erreicht.

### Robustness

- **Endpoint-Rewrite ist konservativ und gezielt.** Nur der **erste** `[Peer]` (= Hub-Peer) wird angefasst — ein port-loser/fehlender Hub-Endpoint kann keinen späteren Peer in Multi-Peer-Configs überschreiben. **IP-Literale bleiben unberührt** (eine bewusst gepinnte robuste IPv4/IPv6 wird nie auf einen Dual-Stack-Namen herabgestuft — genau die AAAA-Blackhole-Ursache), außer bei einer echten IP→IP-Hub-Migration. Der Hostvergleich ist case-insensitiv, ein Trailing-Inline-Comment und Whitespace ums `:` werden toleriert, und eine gleichbleibende Host-Zeile wird byte-identisch belassen (kein unnötiger Flotten-`wg0`-Bounce).
- **`WG_HUB_HOST` wird vor dem Einbacken gesäubert.** `resolveHubHost()`/`configuredHubHost()` trimmen, lehnen Whitespace/Newline/Shell-Metazeichen ab (kein Fleet-weites Einschleusen über eine fehlkonfigurierte Env-Variable) und bracket-wrappen eine bare IPv6. Ist `WG_HUB_HOST` ungesetzt/ungültig, bleibt der eingebackene Endpoint unangetastet statt mit dem OS-Hostnamen-Fallback überschrieben zu werden.
- **Reconciler-Log unterscheidet** erwartete Endpoint-Propagation von echtem Konfig-Drift, damit ein Domain-Wechsel den „missed trigger"-Alarm nicht übertönt.
- 14 neue Regressionstests (`_rewriteHubPeerEndpoint`, `resolveHubHost`/`configuredHubHost`).

## [1.3.23] – 2026-06-13

Konsolidiertes Tagesrelease. Bündelt den großen Sicherheits- und Stabilitäts-Audit-Batch (siehe 1.3.22) mit einem Betriebs-Fix für die Log-Rotation. Health-Stack vollständig grün, in Produktion deployt und verifiziert (Live-API meldet die neue Version, Logrotate ohne Warnung).

### Fixed

- **Log-Rotation funktioniert wieder** — das Backend rief alle 2 Tage `logrotate /etc/logrotate.d/floppyguard` auf, aber die Datei wurde nie angelegt: Bei jedem Tick eine `cannot stat`-Warnung, und die Per-Host-nginx-Logs unter `/data/logs` wuchsen ungebremst (Fallback-Logs ~270 MB). Die Konfig liegt jetzt als Repo-Asset (`backend/config/logrotate.d/floppyguard`) bei, und `ensureLogrotateConfig()` installiert sie beim Start nach `/etc/logrotate.d/`, falls sie fehlt — ein frischer Deploy heilt sich selbst.

### Enthält (aus 1.3.22, gleicher Tag)

Das komplette Multi-Agent-Audit der App (Finden → adversariale Verifikation → Fix, drei Durchläufe): Privilege Escalation über `PUT /api/users/me`, zwei Root-RCE-Pfade derselben Newline-Injection-Klasse (`createInterface` address, `createPeer` peer name), config.env-Injection über Agent-Felder, SSRF-Eindämmung, DoS-Fix bei Key-Upload, `setting.js`-Crash, sowie die Zertifikats-Renewal-Bricking, WireGuard-Conf-Races/Locking, atomare Metadaten-Writes, Subnetz-Mathematik, Key-Rotation-Cache, Hub-Routen für Site-Peers, idempotente Agent-Registrierung, getrennte Rate-Limiter, speicherbare Hub-URL-Propagation, sqlite-portable Migration und reparierte Frontend↔Backend-Payload-Verträge. Vollständige Details unten unter 1.3.22.

## [1.3.22] – 2026-06-13

Sicherheits- und Stabilitäts-Release aus einem strukturierten Multi-Agent-Audit der gesamten App (Finden → adversariale Verifikation → Fix, drei Durchläufe). Behebt zwei kritische Privilege-Escalation-/Datenverlust-Fehler, zwei weitere Root-RCE-Pfade derselben Newline-Injection-Klasse wie v1.3.21, sowie eine Reihe von WireGuard-Races, Agent-Robustheitsproblemen und kaputten Frontend↔Backend-Verträgen. Health-Stack vollständig grün (Backend 87/87, Frontend 23/23, tsc + beide Lints sauber).

### Security

- **Privilege Escalation über `PUT /api/users/me` geschlossen** — ein normaler Benutzer konnte sich mit `{"roles":["admin"]}` selbst zum Admin machen (das Schema erlaubte `roles`, `update()` patchte es ungefiltert). Self-Updates dürfen `roles` jetzt nur noch ändern, wenn der Requester laut DB selbst Admin ist.
- **Root-RCE in `createInterface` geschlossen** — das `address`-Feld lief nur durch `String.trim()` und floss per Newline-Injection als `PostUp = <cmd>` in die wg-quick-Conf (root). Neuer strenger `isValidInterfaceAddress`-Validator (anchored IPv4/IPv6 + Prefix, lehnt Whitespace/Newline ab).
- **Root-RCE über Peer-Namen geschlossen** — derselbe Sink in `createPeer`: ein Peer-Name mit Newline schmuggelte eine `[Interface]`/`PostUp`-Sektion in `wg0.conf`. Namen laufen jetzt durch `stripLinkNameControlChars`.
- **Config.env-Injection über Agent-Felder geschlossen** — `mode`/`wg_interface` waren unvalidiert und landeten in der als root ge-`source`ten `config.env`. Neue Whitelists (`sanitizeAgentMode`, `sanitizeWgInterface`), auch am Sink in `getInstallScript` erneut erzwungen.
- **SSRF vom Hub eingedämmt** — agent-kontrollierte `hostname`/`lan_ip` aus dem Heartbeat trieben serverseitige Portscans + `curl`. Ziele sind jetzt auf RFC1918-Adressen beschränkt; `hostname`/`agent_version` werden längen-geklammert.
- **Remote-DoS bei Key-Upload behoben** — `checkPrivateKey()` warf aus einem `setTimeout`-Callback (unfangbar → Prozess-Crash) beim Upload eines passwortgeschützten Private Keys.
- **Backend-Crash in `setting.js` behoben** — fehlendes `return` im Default-Site-Fehlerpfad führte zu einer unhandled Rejection (Prozess-Absturz) bei gleichzeitigem HTTP 200.

### Fixed

- **Zertifikats-Erneuerung bricked nginx nicht mehr** — die stündliche Auto-Renewal löschte gültige Zertifikate VOR dem certbot-Lauf; schlug certbot fehl (LE-Ausfall, Rate-Limit), war das Zertifikat weg und `nginx -t` scheiterte fleetweit. Löschung erfolgt jetzt erst nach erfolgreicher Erneuerung; Renewal lädt nginx neu.
- **WireGuard-Conf-Races serialisiert** — alle `<iface>.conf`-Read-Modify-Writes (`deletePeer`, `generatePeerConfig`, `syncHubConf`) laufen jetzt unter `withWriteLock`; `syncAgentConfigs` läuft im Lock mit frischen Metadaten (kein Last-Write-Wins mehr).
- **Atomare Metadaten-Writes** — Store wird via tmp+rename geschrieben; Lesefehler liefern keinen leeren Store mehr, der echte Daten überschreibt.
- **Korrekte Subnetz-Mathematik** — Tunnel-IP-Allokation respektiert die echte Prefix-Länge statt hartem /24.
- **Key-Rotation-Cache** — Download/QR rotieren den Peer-Key nicht mehr gegenseitig kaputt; Cache wird bei Edit/Delete invalidiert.
- **Hub-Routen für Site-Peers** — neue Site-Netzwerke bekommen live Kernel-Routen + persistente PostUp-Zeilen (überleben Reboot).
- **Eindeutige Link-Namen erzwungen** — Duplikat-Namen froren vorher den Agent-Sync ein.
- **Agent-Registrierung ist idempotent** — geht die HTTP-Antwort verloren, bricked der Agent nicht mehr; der `reg_token` wird erst nach nachgewiesenem Empfang zurückgezogen.
- **Rate-Limiter pro Bucket getrennt** — Login- und Agent-Limiter teilten einen per-IP-Zähler und sperrten sich gegenseitig aus (NAT).
- **Hub-URL-Propagation speicherbar** — das Settings-PUT-Schema lehnte das `agent-hub-url`-Payload ab (Feature aus v1.3.15/16 war ein No-op); jetzt conditional auf die Setting-ID validiert, ohne `default-site` zu lockern.
- **Migration läuft auf sqlite** — `agent_allowed_sites` nutzte MySQL-only `SHOW COLUMNS` und brach lokale Dev-DBs; jetzt portables `hasColumn`.
- **Frontend↔Backend-Verträge repariert** — Create-Peer/Restore-Metadata/Create-Interface sendeten snake_case bzw. falsche Keys, die das Backend (camelCase) still verwarf (`fullTunnel`, `importedNetworks`, `ifaceName`, `backupPath`, Listen-Port).
- **Client-Reach-List löst keinen falschen „AllowedIPs conflict" mehr aus** — Road-Warrior-Clients, die ein bestehendes Site-Netz erreichen, lassen sich wieder anlegen/bearbeiten.
- **Audit-Log-Suche** — fehlendes abschließendes `%` im LIKE-Muster matchte nur Einträge, die mit der Query endeten.

## [1.3.21] – 2026-06-07

Großes Härtungs-Release der gesamten Hub→Agent-WireGuard-Sync-Struktur (zwei vollständige Audit-Runden + Re-Audit an einem Tag, konsolidiert). Behebt eine ganze Familie von Fällen, in denen eine hub-seitige Änderung — vor allem REMOVE/DELETE/RENAME — nicht zuverlässig am Remote-Agent ankam, plus eine kritische RCE.

### Security

- **Root-Command-Injection im Install-Skript geschlossen** — `getInstallScript` validierte `public_url`/`tunnel_url` schwächer als `sanitizeHubUrl` und liess `"`/Whitespace durch; die URLs landen in der als **root** ge-`source`ten `config.env`. `https://a/x" <cmd>"` führte `<cmd>` als root aus (auch über den JWT-losen `/agent/install`). Beide Felder laufen jetzt durch `sanitizeHubUrl`.
- **UniFi-Credentials validiert** — `unifi_url/user/pass/site` mit Quotes/Newline/`$`/Backtick werden abgelehnt (config.env-Injection-Schutz).

### Changed

- **Netz-Entfernen propagiert jetzt zuverlässig** — der Hub ist autoritativ für die Hub-Peer-AllowedIPs (`_computeHubPeerAllowedIPs`); Client-Reichweiten-Listen verschmutzen die Site-Netz-Menge nicht mehr (`_collectSiteNetworks` schliesst `type:"client"` aus); leeres `importedNetworks` droppt das Subnetz autoritativ (hub- und agent-seitig).
- **Site-Netze strikt IPv4 + kanonisch** — `importedNetworks`/`exportedNetworks`/`allowed_networks` werden auf die Netzadresse maskiert (Host-Bits weg) und IPv6-CIDRs abgelehnt. IPv6-Routing in lokale LANs ist out-of-scope; die Hub/App-Erreichbarkeit über IPv6 ist davon unberührt (Proxy/Endpoint, kein geroutetes Site-Netz).
- **Hintergrund-Timer** (Service-Scan + Config-Reconciler) starten explizit über `internalAgent.startBackgroundTasks()` (Server-Entrypoint), nicht beim Import → Testsuite läuft deterministisch ohne `--test-force-exit`.

### Fixed

- **deletePeer / deleteInterface / Link-Rename / createPeer / `wg_link_name`-Rebind triggern jetzt einen Agent-Resync** — vorher blieben gelöschte/umgezogene Site-Netze auf allen anderen Agents stehen (AllowedIPs + Route + MASQUERADE) bzw. neue Netze erreichten sie erst nach Minuten. Rename cascadet `wg_link_name`/`allowed_sites` (exakt-case) und lehnt Namens-Kollisionen ab.
- **Periodischer Reconciler (5 Min)** als Defense-in-Depth — heilt jeden künftig vergessenen Resync-Trigger; läuft unter demselben `withWriteLock` wie alle Metadaten-Store-Mutationen → kein Lost-Write/Resurrect eines gelöschten Links mehr.
- **Per-Agent-Fehlerisolierung** — ein vergifteter Link (z.B. eine CIDR, die `assertCIDR` wirft) bricht den Fleet-Sync nicht mehr ab; alle übrigen Agents werden trotzdem reconciled.
- **Agent räumt MASQUERADE/FORWARD wieder korrekt ab** — `%i` wird vor dem `eval` durch `$iface` ersetzt (schlug vorher still fehl, MASQUERADE entfernter Netze blieb hängen); `sync_routes` nutzt echten CIDR-Overlap-Test (kein LAN-Hijack durch überlappende Remote-Subnetze).
- **Hub-seitiger Stale-Route-Prune** (`syncHubConf`) räumt Routen entfernter Netze ab — auch ohne Peer-Delta und in `deletePeer` (sonst Reboot-Blackhole).
- **`allowed_networks`-ACL** wird mit den real exportierten Netzen geschnitten (verwaiste/host-bits-Einträge blackholen nicht mehr).
- **`wg syncconf`-Fallback + Force-set repariert** — Whitespace-Toleranz im Strip-Fallback; der Force-set nimmt jetzt alle CIDRs (statt nur der ersten) und matcht einen literalen `[Peer]`-Header.
- **Upload-Config-Reinfektion** verhindert — ein Agent ohne `wg_link_name` kann keine längst entfernten Site-Netze mehr re-injizieren.
- **UniFi-Apply** prunt verwaiste `FG-WG-*`-Firewall-Regeln und deaktiviert den VPN-Client bei leeren `allowed_ips`.
- **Heartbeat** speichert die genutzte Hub-URL (`last_server_url`, neue Spalte) für Sichtbarkeit beim Domain/Endpoint-Move.

`AGENT_SCRIPT_VERSION` → 1.3.21. 78 Backend-Tests (umfangreiche Regressionstests ergänzt). Offen (Backlog, latent): vollständige UniFi-Delete-Teardown-Orchestrierung (0 UniFi-Agenten produktiv), volles IPv6-Site-Routing (bewusst out-of-scope).

---

## [1.3.16] – 2026-06-02

### Changed

- **Zentrale Hub-URL-Einstellung statt pro Agent** — Der in v1.3.15 eingefuehrte Hub-URL-Editor (Primary + Fallback) lag im Panel jedes einzelnen Agents, obwohl `agent-hub-url` ein globales Setting ist — er erschien dadurch redundant einmal pro Agent und legte faelschlich nahe, die URL liesse sich je Agent unterschiedlich setzen. Der Editor ist jetzt ein einziges Steuerelement oben im WireGuard-Tab „Overview". Verhalten unveraendert: Er schreibt dasselbe `agent-hub-url`-Setting, das alle Agents beim naechsten Poll erreichbarkeitsgeprueft uebernehmen. Reine UI-Umstellung — das Agent-Loop-Skript ist unveraendert (`AGENT_SCRIPT_VERSION` bleibt 1.3.15, kein Flotten-Restart).

---

## [1.3.15] – 2026-06-02

### Added

- **Hub-URL-Propagation** — Die Hub-Adresse (Primary + Fallback) lebte bisher nur einmalig pro Agent in `/etc/floppyguard-agent/config.env`, eingebrannt beim Install aus der Browser-Origin des Admins. Ein Domain-Wechsel erreichte keinen laufenden Agent. Jetzt liefert `GET /api/agent/config` die URLs aus dem neuen Setting `agent-hub-url` mit; der Agent-Loop uebernimmt sie in seine `config.env` (analog zur Token-Rotation), aber erst nachdem er die neue URL als erreichbar verifiziert hat (`reach`) — so brickt ein Typo keinen Agent. Editierbar in der Web-UI (Agent-Panel, „Hub (global)").
- **Agent-Netzwerk-ACL in der UI** — `allowed_networks` (welche Remote-Subnetze ein Agent ueber den Hub routen darf) ist jetzt pro Agent im WireGuard-Tab editierbar. Aenderungen loesen automatisch `syncAgentConfigs` aus, der Agent zieht die neue `config_text` beim naechsten Poll (~30 s).

### Fixed

- **Register-Retry im Agent-Loop** — Schlug die einmalige Install-Registrierung fehl, blieb der Agent fuer immer stumm (`FGTOKEN` blieb der `reg_token`, `/config` lehnte ab, kein erneuter `/register`-Versuch). Der Loop versucht jetzt die Registrierung erneut, wenn der Hub erreichbar ist aber `/config` ablehnt — gedrosselt auf max. 1×/5 min, damit das geteilte IP-Rate-Limit von `/register` nicht ausgereizt wird.
- **`config.env`-Upsert** — Fehlt einem aelteren Agent die `PRIMARY_URL=`/`FALLBACK_URL=`-Zeile, wird sie jetzt angehaengt statt vom `sed` still uebergangen.
- **Latenter `logger`-Bug** — `uploadConfig` referenzierte ein nicht importiertes `logger`-Objekt (haette beim ersten Aufruf geworfen); Logger wird jetzt korrekt importiert.

### Security

- **ACL-Netzwerke werden am Eingang strikt CIDR-validiert** — `allowed_networks` flossen ungeprueft in `syncAgentConfigs` → `ip route add <net> dev wgN` (als root auf dem Agent). `update()` validiert jetzt jeden Eintrag streng (Oktett ≤255, Prefix ≤32) und lehnt jedes `/0` ab (`0.0.0.0/0` und Aliase wie `0.0.0.0/00` haetten die Default-Route des Agents gekapert). Ein leeres Array wird als „keine Einschraenkung" (null) gespeichert, nie als `"[]"`. Konsistent mit `[[project_wg_network_validation]]`.
- **Hub-URL-Validierung** — `sanitizeHubUrl` erzwingt http(s) und verwirft sed-/Shell-Metazeichen, bevor eine URL an Agents propagiert und dort via `sed`/`curl` als root verwendet wird. Die UI sperrt das Speichern ungueltiger URLs.

---

## [1.3.14] – 2026-05-31

### Security

- **Command-Injection in WireGuard-Netzwerkfeldern geschlossen** — `importedNetworks`, `exportedNetworks` und `routeTargets` wurden bisher nur als Strings getrimmt/dedupliziert, aber nicht als CIDR validiert. Diese Werte fliessen in `ip route add <net> dev wgN`-Befehle, die als `PostUp`/`PostDown` in die wg-quick-Config geschrieben und als root ausgefuehrt werden. Ein Wert wie `10.0.0.0/24; <befehl>` haette beim Anwenden der Config beliebigen Code als root ausgefuehrt. Alle Netzwerkfelder werden jetzt am Eingang (`createPeer`, `updatePeer`, Metadata-Sanitizer) und an der Sink-Seite (`syncHubConf`) strikt als IPv4/IPv6-Adresse oder -CIDR validiert; alles andere wird verworfen. Neuer Regressionstest in `wireguard.test.js`.
- **Rate-Limit auf `GET /api/agent/install`** — Der Endpoint akzeptierte ein `reg_token` ohne Rate-Limit, waehrend das gleichwertige `POST /api/agent/register` bereits limitiert war. Jetzt gilt fuer beide dasselbe Limit (10 Requests / 15 min).

---

## [1.3.13] – 2026-05-31

### Fixed

- **Road-Warrior-Peers erhalten jetzt alle exportierten Netze** — Laptop-/Mobile-Peers erben automatisch alle `exportedNetworks` der anderen Peers in den AllowedIPs, statt nur das Tunnel-Subnet zu bekommen.
- **Endpoint nutzt die konfigurierte Domain** — Peer- und Agent-Configs verwenden `WG_HUB_HOST` statt eines Platzhalters; neue `resolveHubHost()` mit OS-Hostname-Fallback. `install.sh` schreibt `WG_HUB_HOST` aus der beim Setup eingegebenen Domain.
- **Key-Rotation verliert keine Metadaten mehr** — Die Metadata-Migration nach einer Key-Rotation laeuft nur noch bei tatsaechlich erfolgreicher Rotation, sodass DNS, fullTunnel und platform bei fehlgeschlagener Rotation nicht verloren gehen.
- **DNS-Feld in API-Responses** — Link- und Interface-Responses enthalten jetzt das DNS-Feld, sodass die Web-UI gespeicherte DNS-Server beim Bearbeiten eines Peers anzeigt.

---

## [1.3.12] – 2026-05-27

### Fixed

- **AllowedIPs-Konflikte werden jetzt blockiert** — `applyMetadata` und `PUT /wireguard/metadata` pruefen vor dem Speichern, ob zwei non-client Peers das gleiche Subnetz in `importedNetworks` beanspruchen. Doppelte Subnet-Zuweisungen fuehrten bisher dazu, dass WireGuard Traffic nur an einen der Peers routete und der andere die Verbindung verlor.
- **Metadata-Aenderungen werden sofort live angewendet** — `PUT /wireguard/metadata` rief bisher weder `syncHubConf` noch `syncAgentConfigs` auf. Aenderungen an `importedNetworks` im Metadata-Editor wirkten erst beim naechsten `apply-metadata`. Jetzt werden Hub-Config und Agent-Configs automatisch nach jedem Metadata-Save gesynct.
- **`syncHubConf` synct alle Interfaces** — `applyMetadata` rief `syncHubConf` nur fuer `wg0` auf. Aenderungen an Peers auf anderen Interfaces (wg1, wg2, ...) wurden nie in die conf-Datei uebernommen. Jetzt werden alle erkannten WG-Interfaces gesynct.
- **Agent `wg syncconf` verschluckte AllowedIPs-Aenderungen** — Wenn sich nur die AllowedIPs eines bestehenden Peers aenderten (gleicher PublicKey), ignorierte `wg syncconf` die Aenderung manchmal. Der Agent-Loop setzt AllowedIPs jetzt zusaetzlich explizit per `wg set peer ... allowed-ips ...` nach jedem `syncconf`.
- **Stale wg0-Routen blockierten lokale Netze** — `sync_routes()` im Agent fugte Kernel-Routen fuer AllowedIPs hinzu, raeumte aber nie veraltete Routen auf. Wenn ein Subnetz aus den AllowedIPs entfernt wurde, blieb die alte `ip route ... dev wg0` bestehen und ueberschrieb die lokale LAN-Route. Border-Router konnten dadurch eigene VLANs (z.B. 192.168.11.0/24) nicht mehr erreichen. `sync_routes()` entfernt jetzt stale Routen und ueberspringt Netze die bereits auf physischen Interfaces liegen. Gleiches Filtering auch auf der Hub-Seite in `syncHubConf`.

---

## [1.3.11] – 2026-05-27

### Fixed

- **WG-Peers konnten Hub-LAN nicht erreichen** — `syncHubConf` generierte MASQUERADE-Regeln nur fuer die Source-CIDR der physischen Schnittstelle (`-s 10.10.10.0/24 -o eth1`), aber nicht fuer Traffic aus dem WG-Tunnel-Subnet (`-s 10.10.0.0/24 -o eth1`). PVE-Hosts sahen Pakete mit unbekannter Source-IP und verwarfen die Antwort. Jetzt werden pro physischer Schnittstelle automatisch zwei MASQUERADE-Regeln generiert — eine fuer das lokale Subnet und eine fuer das Tunnel-Subnet.
- **MASQUERADE-Regex erkannte Regel-Varianten nicht** — `masqRe` in `_rewriteHubConf` matchte nur `-o ... -s ...` Reihenfolge. Manuell oder von aelteren Versionen gesetzte Regeln mit `-s ... -o ...` wurden beim Sync nicht gestripped und fuehrten zu Duplikaten. Regex akzeptiert jetzt beide Reihenfolgen.

---

## [1.3.10] – 2026-05-20

### Fixed

- **WireGuard Routen nach Agent-Neustart** — Agent-Configs mit `Table = off` verloren nach einem CT/VM-Neustart alle Routen, weil `PostUp` nur iptables-Regeln enthielt aber keine `ip route add`-Befehle. `buildHubPostUp`/`buildHubPostDown` generieren jetzt automatisch `ip route add/del`-Eintraege fuer alle AllowedIPs aus dem `[Peer]`-Block. Alle bestehenden Agents wurden via `syncAgentConfigs` aktualisiert.

---

## [1.3.9] – 2026-05-20

### Fixed

- **Client-Peers bekamen falsche Hub-AllowedIPs** — `_buildPeerUpdates` und `createPeer` schrieben `importedNetworks` als Hub-seitige AllowedIPs auch fuer Client-Type Links. Client-Peers erhalten jetzt nur ihre eigene `/32`-Adresse.
- **updatePeer loeste keinen Agent-Sync aus** — Aenderungen an AllowedIPs ueber die GUI wurden nicht an Agents weitergegeben. `updatePeer` ruft jetzt `syncAgentConfigs` auf.

### Changed

- **Interface- und Proxy-Host-Editoren redesignt** — Grouped Card Layout, Full-Width Sections, Monospace CIDR-Felder, responsive unter 768px.
- **CI: Node.js 20 → 22** — Node 20 EOL Juni 2026; `--test-force-exit` und `timeout-minutes: 10` verhindern haengende Tests.

---

## [1.3.8] – 2026-05-17

### Added

- **Auto-MASQUERADE fuer Cross-Site-Traffic** — Agent-Configs enthalten jetzt automatisch MASQUERADE-Regeln fuer alle Remote-Site-Netze die ueber den WG-Tunnel ans lokale LAN weitergeleitet werden. Keine manuellen iptables/nft-Regeln mehr noetig — alles wird ueber die App gesteuert und bei Plan-Apply an die Agents gepusht.

### Fixed

- **PBS-Erreichbarkeit von Remote-Sites** — Remote-Peers (z.B. Daniel Home) konnten lokale LAN-Geraete (z.B. PBS 192.168.10.19) nicht erreichen, weil MASQUERADE-Regeln auf dem Ziel-Gateway fehlten. Wird jetzt automatisch durch syncAgentConfigs generiert.

---

## [1.3.7] – 2026-05-10

### Added

- **Netz-Auswahl beim Tunnel erstellen** — Checkbox-Karten pro Site mit einzeln waehlbaren Subnetzen statt manueller CIDR-Eingabe; Clients werden aus der Auswahl ausgeblendet
- **Platform-Badge auf Link-Karten** — zeigt Desktop/Mobile Badge in der WireGuard-Uebersicht
- **Type/Platform/FullTunnel im Metadata-Editor** — Verbindungstyp, Platform und Full-Tunnel nachtraeglich aenderbar; Platform und Full-Tunnel nur bei Client-Type sichtbar

### Fixed

- **Client-Links erzeugen keine falschen Warnungen mehr** — `remote-management-mode-undefined` und `link-not-currently-active` werden fuer Client-Type uebersprungen
- **delete-peer/update-peer akzeptiert camelCase und snake_case** — Frontend sendet `link_id`, Backend las nur `linkId`; jetzt werden beide Formate akzeptiert
- **AllowedIPs Konfliktpruefung** — `createPeer` und `updatePeer` verhindern doppelte Subnet-Zuweisungen mit Fehlermeldung
- **Agent Script-Update vor Config-Apply** — verhindert Crash-Loop wenn der Agent ein Script-Update braucht um einen Config-Bug zu fixen

---

## [1.3.6] – 2026-05-10

### Added

- **Agent config auto-upload** — agents upload their local WG config (with masked PrivateKey) to the hub when the server has no config stored; enables `syncAgentConfigs` for agents that were registered without providing their config; new endpoint `POST /api/agent/upload-config` (rate-limited)
- **Per-agent network access control** — new `allowed_sites` and `allowed_networks` JSON columns on the agent table; `allowed_networks` (explicit CIDRs) takes priority over `allowed_sites` (link-name whitelist) over full-mesh (null = all networks); deny-by-default when configured
- **Hub-managed firewall rules** — all agent PostUp/PostDown rules are generated by the hub via `normalizeAgentConfig()`; no local firewall configuration needed on VPN gateways; tunnel subnet derived automatically from Address field
- **Agent PostUp/PostDown live apply** — agent detects PostUp/PostDown changes from hub, runs old PostDown to clean up, then applies new PostUp rules without tunnel restart
- **Agent PrivateKey preservation** — agent restores local PrivateKey from `/etc/wireguard/*.conf` when hub sends `(hidden)` placeholder; prevents tunnel breakage on config push

### Fixed

- **WireGuard interfaces fail to start after reboot** — `wg-quick` auto-route injection collides with existing kernel routes (e.g. `10.10.10.0/24` on `eth1`), tearing down the entire interface; `createInterface()` now sets `Table = off` so route management is handled exclusively by PostUp/PostDown with error suppression
- **Backend hangs indefinitely when database is unreachable** — startup retry loop had no limit (1 s interval forever, no useful log); now retries up to 30 times with exponential backoff (1 s to 15 s), logs a clear "Database unreachable — check `systemctl status mariadb`" message, and exits with code 1 so systemd marks the service as failed
- **Missing migration file** — `20260503150000_agent_wg_link.js` was recorded in the DB but absent from disk, causing knex migration errors on fresh `migrateUp()`; file restored

### Changed

- **Install script MariaDB support** — `install_systemd()` detects MariaDB/MySQL, adds `After=mariadb.service` + `Wants=mariadb.service` to the systemd unit, and installs a `mariadb-rundir.service` safety net that creates `/run/mysqld/` before MariaDB starts (fixes LXC containers where `systemd-tmpfiles` fails due to UID mapping)
- **Agent script version** bumped to 1.3.6 (auto-update via hub)

---

## [1.3.4] – 2026-05-09

### Added

- **Agent version display** — agent script version shown as badge on link cards and in agent panel; agents report their version via heartbeat; new `agent_version` DB column with auto-migration
- **WCAG focus-visible** — keyboard focus ring on all SiteMenu nav items (was: `outline: none` with no replacement)
- **WireGuard responsive layout** — link cards and tabs now usable on mobile (768px breakpoint, scrollable tabs, single-column grid)
- **Dark mode SVG colors** — topology map type colors defined as CSS variables with light/dark mode variants
- **Auto-MASQUERADE for cross-interface routing** — `syncHubConf()` discovers non-WG interfaces and adds NAT rules so WireGuard peers can reach hosts on eth1/etc

### Security

- **Shell injection prevented** — `publicUrl`/`tunnelUrl` in agent install scripts validated against URL format; shell-unsafe characters rejected

### Fixed

- **Race condition in `createPeer`** — serialized via in-process write mutex; prevents duplicate tunnel IP assignment
- **Write ordering in `createPeer`** — conf file written BEFORE live `wg set`; rolls back on failure
- **Metadata write mutex** — `applyMetadataPatch` serialized; prevents last-write-wins data loss
- **Bandwidth NaN** — `__ts__` sentinel skipped in polling loop
- **`generatePeerConfig` stale linkId** — uses new link ID after key rotation for metadata lookup
- **`_rewriteHubConf` missing PostUp** — injects PostUp/PostDown when none exist in original conf
- **`revokeObjectURL` wrong variable** — blob URLs now correctly revoked after config download (was: memory leak)
- **`processResponse` crash on non-JSON** — gracefully handles nginx 502, HTML error pages
- **`download()` missing error check** — non-2xx responses now throw instead of downloading garbage
- **AuthContext `refresh` not memoized** — wrapped in `useCallback` to prevent interval churn
- **AuthContext `logout` not clearing 2FA** — `twoFactorChallenge` now reset on logout
- **`data.routes` not null-guarded** — optional chaining prevents crash if backend omits routes
- **Active peers table `colSpan`** — empty state now spans all 7 columns (was: 6)
- **Hardcoded German placeholder** — tunnel name placeholder and AllowedIPs hint now use i18n
- **Login form fields** — added `required` attribute to email and password inputs
- **Dead CSS** — removed stray `:host` selector, fixed monospace font stacks to use Tabler tokens
- **Toast component** — converted px to rem for accessibility (respects browser font-size)

---

## [1.3.3] – 2026-05-09

### Added

- **AllowedIPs conflict detection** — WireGuard status API now detects and warns when multiple peers claim the same subnet; shown as a prominent alert in the UI with affected peers listed
- **Auto-MASQUERADE for cross-interface routing** — `syncHubConf()` automatically discovers non-WireGuard interfaces with private IPs and adds MASQUERADE rules so WireGuard peers can reach hosts on those LANs (e.g., VMs on eth1)
- **Full i18n coverage** — all hardcoded German strings in the tunnel creation form (15 strings), routing matrix (5 keys), Login page (3 strings), and misc WireGuard labels translated to EN/DE/FR

### Fixed

- **Unhandled promise rejections** — replaced all 8 bare `mutateAsync()` calls in onClick handlers with the `mutate()` callback form; prevents crashes in strict environments
- **TypeScript type safety** — added `dns` and `fullTunnel` fields to `WireGuardLink` and `WireGuardInterface` types; removed 5 `as any` casts
- **useEffect loop risk** — AgentSection auto-create effect now uses a ref guard instead of unstable mutation dependencies
- **Clipboard error handling** — `navigator.clipboard.writeText()` now catches rejections
- **Redundant middleware** — removed duplicate `requireAdmin()` on PUT /wireguard/metadata

### Changed

- **README badge** — version updated to 1.3.3

---

## [1.3.2] – 2026-05-09

### Security

- **Broken access control fixes** — added `requireAdmin()` to all `/api/agents` CRUD routes, `/api/wireguard/status`, `/metadata` (GET), `/bandwidth`, `/apply-state`, `/link-config`, `/link-config-qr`, `GET /api/users`, and `GET /api/security/fail2ban`; previously any authenticated user could access these admin-only endpoints
- **Unauthenticated file upload closed** — `POST /api/design/screenshot` now requires JWT + admin role; added magic-bytes validation to reject files whose content doesn't match the declared extension
- **Bulk user delete removed** — `DELETE /api/users` (previously guarded only by `CI=true && DEBUG=true` env vars) now always returns 404; eliminates unauthenticated account-wipe risk
- **Agent self-update signed** — server computes HMAC-SHA256 of the loop script using the agent token as key; agents verify the signature before accepting a self-update, preventing server-compromise-to-RCE escalation
- **JWT expiry capped** — token expiry now limited to 30 days maximum; prevents long-lived tokens that survive password changes
- **Rate limiter persistent** — replaced in-memory rate limiter with SQLite-backed storage; survives process restarts and is shared across cluster workers
- **CORS hardened** — disallowed cross-origin requests now receive 403 instead of silently proceeding without CORS headers
- **CSP header added** — `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; frame-ancestors 'none'`
- **GitHub Actions SHA-pinned** — all `actions/checkout`, `actions/setup-node`, and `actions/stale` references pinned to immutable commit SHAs
- **CODEOWNERS added** — `.github/workflows/` now requires review from `@floppy007`
- **Shell injection mitigated** — converted 3 of 4 `utils.exec()` calls (shell-based) to `utils.execFile()` (argument array, no shell)
- **Dockerfile hardened** — Cypress test image now explicitly sets `USER 1000` before CMD

### Fixed

- **Frontend test drift** — fixed 10 failing WireGuard tests (missing `useAgents` mock export + stale text assertions), 1 failing Platform test (missing `useFail2BanStatus` mock), 1 failing Gateway test (untranslated key assertions)
- **Backend lint warnings** — removed 2 unused parameters in `buildApplyContract()`, renamed unused `err` to `_err` in `require-admin.js`
- **Frontend dependency vulnerabilities** — resolved 6 high-severity npm audit findings (vite path traversal, lodash prototype pollution, picomatch ReDoS, postcss XSS)

### Changed

- **`.gitignore` updated** — added `.env`, `.env.*`, `.gstack/` to prevent accidental secret commits
- **Default DB credentials** — `backend/config/default.json` now uses `changeme` placeholder instead of `npm`/`npm`
- **Agent script version bumped** — `AGENT_SCRIPT_VERSION` incremented to `1.3.0` to trigger self-update on all connected agents

---

## [1.3.1] – 2026-05-09

### Added

- **WireGuard Peer CRUD** — delete button on every link card with confirmation modal; removes peer from live interface, config file and metadata; creates safety backup before deletion; `POST /api/wireguard/update-peer` for live AllowedIPs changes with automatic hub sync
- **WireGuard Interface CRUD** — create new interfaces (wg2, wg3, …) with auto-generated keypair, address and listen port; delete non-hub interfaces with confirmation modal; `wg-quick up/down` and `systemctl enable/disable` handled automatically
- **Interface selector** — tunnel creation form and header now show an interface dropdown when multiple interfaces exist (was hardcoded to wg0)
- **Live-vs-conf drift detection** — `syncHubConf` now compares the running WireGuard interface against the config file and corrects any discrepancies automatically

### Fixed

- **AllowedIPs stripped on sync** — `_buildPeerUpdates` removed non-host networks from peers when `importedNetworks` was empty in metadata; now preserves existing AllowedIPs from the config file when metadata has no override
- **WireGuard nav icon** — replaced wide text logo SVG (1874×333) with shield-only icon; nav item now renders at correct 16×16 size
- **Interface card layout** — consistent vertical layout with fixed button position at bottom, all info rows always visible
- **CI lint errors** — fixed all `useOptionalChain` and `noParameterAssign` errors across backend

---

## [1.3.0] – 2026-05-06

### Added

- **WireGuard tunnel creation** — new "Neuer Tunnel" button on WireGuard page; creates peer with keypair, auto-assigns tunnel IP, generates downloadable client config
- **Tunnel configuration options** — name, type (client/site-to-site/hub-link), DNS servers, platform (desktop/mobile), full tunnel toggle, custom AllowedIPs
- **Platform-aware AllowedIPs** — desktop uses `/1`-split routing (no routing loop), mobile uses `0.0.0.0/0` (OS VPN tunnel flag)
- **DNS/nameserver config** — configurable per interface and per link; falls back to `WG_DNS` env variable; written into `[Interface] DNS =` of generated peer configs
- **DonutGauge component** — SVG ring gauge for stat cards showing ratios (e.g. 10/12 active)
- **PeerSparkline component** — mini bandwidth sparkline chart per peer connection
- **Chart legends** — bandwidth charts show peer name + color + current rate

### Changed

- **Dashboard redesign** — stat cards with donut gauges, peer link preview with sparklines and scroll, higher bandwidth charts
- **Traffic page redesign** — donut stat cards, per-peer sparkline column in link table
- **Header redesign** — compact 56px glassmorphism header, pill-style nav links, Light/Dark pill toggle, avatar with initials
- **CSS simplification** — removed heavy body gradients, grid overlays, pseudo-element decorations; cards use `backdrop-filter: blur` and `color-mix`

### Fixed

- Bandwidth charts starting in the middle when history is incomplete (left-padded with zeros)
- Nav link active state not visible (Tabler CSS specificity override)

---

## [1.2.4] – 2026-05-05

### Added

- **WireGuard peer config export** — download client config files with auto-generated keypair; `GET /api/wireguard/link-config` returns the full `.conf` file as attachment
- **QR code modal** — `GET /api/wireguard/link-config-qr` generates a PNG QR code for mobile enrollment; shown in a modal on the link card
- **Routing matrix** — visual matrix showing which peers export which networks; displayed in the Routing tab
- **Active peer names** — peer names from metadata shown in status cards and link headers instead of raw public keys

### Fixed

- CI test failures from upstream dependency updates

---

## [1.2.3] – 2026-05-04

### Fixed

- **Certificate renewal (HTTP challenge)** — `certbot renew` replaced with `certonly --force-renewal`; added missing `--webroot-path` and `--non-interactive` flags; uses virtualenv certbot at `/opt/certbot/bin/certbot` instead of system binary (which lacks DNS plugins)
- **Certificate renewal (DNS challenge)** — fixed "unrecognized arguments" error by switching from `--authenticator dns-cloudflare` to `--dns-cloudflare`; credentials are now fetched directly from the database (bypassing the `omissions()` security filter that strips them from API responses)
- **Certbot versioned lineage** — added `clearCertDirsForRenewal()` helper that removes `archive/`, `live/` and `renewal/` entries for a certificate before `certonly`, preventing certbot from creating suffixed lineages like `npm-116-0001` instead of `npm-116`
- **New certificate request (DNS challenge)** — fixed same `--authenticator` → `--<plugin>` flag for initial issuance
- **Modal header alignment** — fixed tab nav being pushed down in Redirection Host, Proxy Host, Dead Host and Stream modals; adjusted card-header padding and removed double-rendered `<Alert>` (replaced `show={!!errorMsg}` with conditional rendering)

### Changed

- Scripts (`check-production-routes`, `start-production`, `status-production`) — replaced hardcoded external URL default with `http://127.0.0.1:81`

### Added

- `ROADMAP.md` — documents planned DNS auto-provisioning feature (Cloudflare + IPv64)

---

## [1.2.2] – 2026-05-04

### Added

- **WireGuard routing automation** — `syncHubConf()` rewrites hub `wg0.conf` AllowedIPs and
  PostUp/PostDown ip-route commands from metadata on every UI apply; applies live via `wg set` +
  `ip route add` without restarting wg0
- **Agent config sync** — `syncAgentConfigs()` updates every connected agent's WireGuard peer
  AllowedIPs so all sites can reach each other through the hub; agents pick up changes on their
  next 30 s poll; both syncs fire automatically on `metadata-with-config-intent` apply
- **Agent self-update** — `AGENT_SCRIPT_VERSION` constant tracks the loop-script version; agents
  compare their local version on every config poll and self-update automatically via
  `GET /api/agent/loop-script` + `exec` — no token reset or manual reinstall required
- **`sync_routes()` in agent loop script** — adds missing kernel ip routes after `wg syncconf`
  (which updates WireGuard peer tables but never touches the kernel routing table); runs on every
  config change and once at startup
- **Full multilanguage UI (EN / DE / FR)** — all user-visible strings in WireGuard, Dashboard,
  Platform, Gateway and Fail2Ban sections are now translated; topology labels, badge labels,
  table headers, editors, planners, stat cards, empty states and backend warning codes all go
  through the i18n system
- **Agent duplicate-link guard** — `create` and `update` reject `wg_link_name` when more than one
  link shares that name; `syncAgentConfigs` skips ambiguous agents with a warning; plan preview
  reports a validation error on duplicate link names

### Changed

- WireGuard apply response now includes `hubSync` and `agentSync` result fields
- UI shows live sync feedback after apply: hub peer count updated, agent names synced, or warnings on error
- GitHub Actions CI pipeline added (lint, test, build)
- Install script added (`scripts/install`) for host-based deployment
- Docker dev stack removed (will be rebuilt as a proper feature)
- Remaining NPM leftovers removed, package fully renamed to `floppyguard`

---

## [1.2.1] – 2026-05-03

First public release of FloppyGuard, forked from nginx-proxy-manager v2.14.0.

### Added

- **WireGuard management** — interface, peer and link CRUD with live status polling; visual
  topology map (hub / site / client nodes, link edges); planning layer with discover → shape →
  validate → ready stages; dry-run plan preview; one-step apply and restore
- **Remote agent system** — native Linux agent with curl-based install one-liner and automatic
  token registration; UniFi-compatible mode; service discovery across registered agents
- **Platform dashboard** — combined home page with proxy stats, WireGuard summary, gateway
  overview and Fail2Ban status; Fail2Ban UI with jail list, banned IPs and one-click unban
- **Gateway page** — reachability map, private route inventory, peer network inventory, routing
  hints (missing return routes, NAT candidates, observations)
- **Security hardening** — nftables firewall with strict INPUT policy; fail2ban jails for API
  auth brute-force, admin bot scans and SSH

### Changed

- Merged Platform and Dashboard pages into a single home page (`/`), removed standalone `/platform` route
- WireGuard planner: removed mandatory preview step before saving
- Footer: copyright Florian Hesse | Comnic-IT with version number
- Dark mode: fixed missing `--tblr-bg-surface-rgb` CSS variables
- Package name changed to `floppyguard`, author updated to Florian Hesse

### Base (upstream nginx-proxy-manager v2.14.0)

- Proxy hosts, redirection hosts, streams, 404/dead hosts
- Let's Encrypt certificates via certbot (HTTP and DNS challenge)
- DNS challenge integrations: Cloudflare, dns-multi (ipv64, name.com, etc.)
- Access lists with HTTP Basic Auth
- Multiple users with role-based permissions
- Audit log
- React 19 + Vite frontend, Express.js backend, Objection.js ORM

---

## [1.2.0] – 2026-02-17

### Added

- **WireGuard management page** — visual topology map showing hub, site and client nodes with
  link edges; interface and peer status from live `wg show` output; link metadata editor and
  planner

---

## [1.1.0] – 2025-11-11

### Added

- **Remote agent system** — agent registration with token-based authentication; install
  one-liner generator; token reset and agent management UI

---

## [1.0.0] – 2025-10-14

Initial fork of nginx-proxy-manager v2.14.0.

---

*nginx-proxy-manager v2.14.0 by [Jamie Curnow](https://github.com/jc21) — MIT License*
