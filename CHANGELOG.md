# Changelog

All notable changes to FloppyGuard are documented here.
This project diverges from upstream nginx-proxy-manager starting at v1.0.0.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [2.5.0] - 2026-10-25

Direct links between sites. **Agent script 1.6.0:** every agent self-updates once. Without a direct link nothing changes on a gateway (same routes, same NAT, byte-identical Freigaben ruleset); only the 30 s poll pause is now split into 10 s steps.

### English

#### Added

- **Direct links ("Direktverbindungen")** between two site agents, managed on the Freigaben page. Site A listens (fixed public IP, port forward on its router), site B dials A's address (IPv4 or DNS name, re-resolved while the handshake is stale). Traffic between the two sites goes directly instead of through the hub; when the direct path fails it goes through the hub again automatically. The hub stays the configuration source and the fallback.
- Each agent generates the WireGuard key of a direct link itself and reports only the public key; private keys never leave the gateway. Interface `fgd<id>` (never `wgN`, so foreign WireGuard tunnels on a gateway are not touched), own private /30 transfer net.
- **Routing:** the partner's networks go into a routing table per link (`52000+id`, `ip rule pref 31000`) in front of the main table. The agent fills it only while the link is healthy (handshake younger than 180 s and ping to the partner's tunnel address, checked every 10 s): 3 failed checks empty the table and the unchanged hub routes on the WireGuard interface carry the traffic, 3 successful checks switch back. Conntrack entries of flows to the partner are dropped on a switch (needs the `conntrack` tool) so NATed flows are re-NATed for the new path.
- **Networks:** each side routes exactly the networks it reaches through the hub today (same `allowed_networks`/`allowed_sites` ACL) that the partner site exports, minus anything overlapping its own site networks or its hub tunnel subnet.
- **NAT stays as through the hub:** the transfer net is masqueraded into the LAN like the hub tunnel subnet; a per-side option masquerades the site's own traffic into the direct tunnel, for gateways that masquerade into the hub tunnel today. Firewalls, RADIUS and AD on the other side see the same senders on both paths.
- **Freigaben apply on both paths:** the `FG_IN` ruleset repeats every rule and the final drop per direct interface. A restricted gateway does not bring up (or takes down) a direct interface its filter does not cover, judged from the live chain and the cached ruleset.
- Sites separated under "Standorte untereinander" never get an active direct link (the separation only exists on the hub); a link created before a separation is taken down and can still be switched off or edited.
- A link is not activated while a side set to "Freigaben only" has a partner that masquerades into the direct tunnel (its Freigaben would drop the partner's traffic), or while side A's endpoint lies inside a site or tunnel network.
- Status per side in the UI (path direct / via hub, round-trip time, handshake age, error). API: `GET/POST /api/direct-links`, `PUT/DELETE /api/direct-links/:id` (admin, audit-logged). Deleting an agent removes its direct links.

#### Changed

- The Freigaben line limit (`MAX_LINES_TOTAL`) counts every interface the ruleset is generated for; enabling a direct link is refused when it would push either agent past the limit.

### Deutsch

#### Neu

- **Direktverbindungen** zwischen zwei Standort-Agents, verwaltet auf der Freigaben-Seite. Standort A lauscht (feste öffentliche IP, Portweiterleitung am Router), Standort B baut zu A auf (IPv4 oder DNS-Name, der bei veraltetem Handshake neu aufgelöst wird). Verkehr zwischen den beiden Standorten läuft direkt statt über den Hub; fällt der Direktweg aus, läuft er automatisch wieder über den Hub. Der Hub bleibt Konfigurationsquelle und Rückfall.
- Jeder Agent erzeugt den WireGuard-Schlüssel einer Direktverbindung selbst und meldet nur den öffentlichen Schlüssel; private Schlüssel verlassen das Gateway nie. Interface `fgd<id>` (nie `wgN`, fremde WireGuard-Tunnel auf einem Gateway bleiben unberührt), eigenes privates /30-Transfernetz.
- **Routing:** Die Netze des Partners kommen in eine eigene Routing-Tabelle pro Verbindung (`52000+id`, `ip rule pref 31000`) vor der Haupttabelle. Der Agent füllt sie nur, solange die Verbindung gesund ist (Handshake jünger als 180 s und Ping auf die Tunneladresse des Partners, Prüfung alle 10 s): nach 3 Fehlversuchen wird die Tabelle geleert und die unveränderten Hub-Routen tragen den Verkehr, nach 3 Erfolgen geht es zurück auf direkt. Beim Umschalten werden die Conntrack-Einträge zum Partner gelöscht (braucht das Tool `conntrack`), damit maskierte Verbindungen für den neuen Weg neu maskiert werden.
- **Netze:** Jede Seite routet genau die Netze, die sie heute über den Hub erreicht (gleiche ACL `allowed_networks`/`allowed_sites`) und die der Partnerstandort exportiert, ohne Netze, die sich mit den eigenen Standortnetzen oder dem eigenen Hub-Tunnelnetz überschneiden.
- **NAT bleibt wie über den Hub:** Das Transfernetz wird wie das Hub-Tunnelnetz ins LAN maskiert; eine Option pro Seite maskiert den eigenen Verkehr in den Direkttunnel, für Gateways, die heute in den Hub-Tunnel maskieren. Firewalls, RADIUS und AD auf der Gegenseite sehen auf beiden Wegen dieselben Absender.
- **Freigaben gelten auf beiden Wegen:** Der `FG_IN`-Regelsatz wiederholt jede Regel und das abschließende Verwerfen pro Direkt-Interface. Ein Gateway mit "nur Freigaben" bringt ein Direkt-Interface, das sein Filter nicht abdeckt, nicht hoch bzw. baut es ab (geprüft an der laufenden Kette und am gespeicherten Regelsatz).
- Unter "Standorte untereinander" getrennte Standorte bekommen nie eine aktive Direktverbindung (die Trennung gibt es nur am Hub); eine vor der Trennung angelegte Verbindung wird abgebaut und lässt sich weiter ausschalten oder bearbeiten.
- Eine Verbindung wird nicht aktiv, solange eine Seite auf "nur Freigaben" steht und der Partner in den Direkttunnel maskiert (die Freigaben würden dessen Verkehr verwerfen), oder solange der Endpunkt von A in einem Standort- oder Tunnelnetz liegt.
- Status pro Seite in der Oberfläche (Weg direkt / über Hub, Laufzeit, Alter des Handshakes, Fehler). API: `GET/POST /api/direct-links`, `PUT/DELETE /api/direct-links/:id` (Admin, im Audit-Log). Das Löschen eines Agents entfernt seine Direktverbindungen.

#### Geändert

- Das Zeilenlimit der Freigaben (`MAX_LINES_TOTAL`) zählt jedes Interface, für das der Regelsatz erzeugt wird; das Einschalten einer Direktverbindung wird abgelehnt, wenn es einen der Agents über das Limit bringen würde.

## [2.4.0] - 2026-10-24

Audit follow-up, a three-pass ultracode audit (299 reported, 265 confirmed, 253 fixed), the relevant upstream nginx-proxy-manager fixes from v2.15.0 to v2.16.0 and dependency security updates. **Agent script stays 1.5.1:** the agent loop script is unchanged since 2.3.0, so this release triggers no fleet self-update. The agent-side behaviour below that refers to "1.5.0" already shipped with agent script 1.5.1 in 2.3.0.

### English

#### Security

- **2FA QR code is rendered locally.** The setup dialog sent the TOTP secret to `api.qrserver.com` to draw the QR code. The backend now returns a PNG data URL (`qr_data_url`, `qrcode` package); the secret no longer leaves the host.
- **Tokens are revoked on a password change** (upstream #5836). A password change stamps `password_changed_at`; every token issued before it is refused with 401, also on token refresh, on the 2FA challenge and on admin-only routes. **Users are logged out after changing their own password:** the dialog shows a notice and returns to the login page. SSO-only accounts are not affected.
- **TOTP disable code moved to the request body.** `DELETE /api/users/:id/2fa` takes `{ "code": ... }` in the body instead of `?code=` in the URL (no more codes in access logs); the query parameter is still accepted for an old cached frontend.
- 2FA enable/disable/backup codes and the password change are rate limited (10 per 15 minutes per IP); login runs the same bcrypt work for unknown e-mails, so accounts can no longer be enumerated by timing; "login as" refuses disabled users; "login as", 2FA changes and settings changes are written to the audit log.
- **DNS-challenge credentials are only on disk during a certbot run** (upstream #5814): written with mode 0600 right before certbot and removed afterwards. At startup stale `credentials-<id>` files (and interrupted `.tmp` copies) are removed from the credentials directories, except when the file is the only copy (a DNS certificate without credentials stored in the database).
- Streams check certificate ownership (a user could attach another user's certificate and key to a stream); proxy host responses and audit entries no longer contain access-list basic-auth passwords, and masked passwords no longer reveal their first character and length; renewing a certificate no longer returns or audit-logs the DNS provider credentials; dead hosts return the certificate without its meta.
- htpasswd: usernames with `:` or control characters are rejected, and a password starting with `-` is no longer parsed as an openssl option (which left a half-written file that locked all users out).
- Custom certificate private keys are written with mode 0600; the certificate download no longer leaves a zip in `/tmp`.
- CloudFront/Cloudflare IP ranges are validated before they are written into `ip_ranges.conf`, and an error page from cloudflare.com no longer empties the `set_real_ip_from` list for 6 hours.
- Site isolation fails closed: when the live WireGuard status is unavailable, links keep their last known type and imported networks instead of dropping to "no networks", and an apply that would drop a pair while one of its links is unresolved is refused.
- Agent `mgmt_url` is validated (http/https, max. 512 characters) before it is shown as a link; user auth records are validated on create (type, secret length); the hub URL check matches the agents' own whitelist; external domain links open with `rel="noopener noreferrer"`.
- **Dependencies:** express 5.3.0 with proxy-addr 2.0.8 (GHSA-jqcg-44mw-7w3h), plus body-parser 2.4.0, qs 6.16.1, fast-uri 3.1.9, ip-address 10.7.4, js-yaml 4.3.2, brace-expansion 5.0.12 (backend) and vite 7.3.7, postcss 8.5.31, nanoid 3.3.20 (frontend).

#### Changed

- **Ingress mode "open" with rules is now observation only.** Agent script 1.4.0 ACCEPTed matching flows (and all RELATED,ESTABLISHED traffic) in `FG_IN` at FORWARD position 1. From 1.5.0 on, an *open* agent with rules only RETURNs: the rules count hits, but everything falls through to the gateway's own FORWARD rules (e.g. VPN_MGR, ufw, docker). Every open agent with rules gets a new ruleset hash and changes behaviour on its first poll after the self-update. Only *restricted* filters. **Rollout:** remove an external filter such as VPN_MGR only after the agent is switched to *restricted* and the panel shows the filter as applied: an open agent without VPN_MGR filters nothing. The panel now says so for open agents with rules.
- **Agents report a re-checked config hash.** On the first start of 1.5.0 the agent drops the `last_hash` written by 1.4.0 (which was also written after a failed apply) and re-applies the current config once (no-op when it is already live), so "applied" in the UI is confirmed again.
- **Pending ingress state is polled for at most 3 minutes** after a change; an agent without a heartbeat for 5 minutes is shown as *agent offline* instead of *pending*.
- **Hub URLs for the internet path are https only.** The public URL of the agent hub-URL setting (`agent-hub-url` value / fallback) and `public_url` of the agent install script are rejected with 400 when they use `http://`; the internal primary URL may stay http. Agent 1.5.0 `get_server` no longer falls back to a plain-http URL outside the tunnel: when the primary is unreachable and the fallback is http and not routed through the tunnel, the agent waits instead of sending its token in cleartext. Switch an http fallback to https before the agents update.
- **Agents can be force-deleted** (`DELETE /api/agents/:id?force=1`, second confirmation in the UI) once they have not reported for 1 hour. The tokens are revoked, but the gateway keeps its last Freigaben filter (`FG_IN`) until it is removed there by hand.
- **Deleting a WireGuard link or interface handles its bound agents in the backend.** `deletePeer`/`deleteInterface` refuse (409) while non-deleted agents are bound to the link name(s) (an agent would outlive the link with a valid token and be inherited by a later link of the same name). With `deleteBoundAgents` every bound agent is checked first (nothing is removed while one refuses, e.g. Freigaben filter still active), then the peer/interface is removed and only after that the agents. `dryRun: true` reports the bound agents and whether each can be deleted; `forceAgentIds` force-deletes agents offline for 1 hour. The UI runs this as one operation.
- **Network lists reject prefixes shorter than /8.** Every WireGuard metadata network list (link and interface exported/imported networks, route targets) and the reach list of a new or edited client reject `/0` and any prefix below `/8` (`0.0.0.0/1` + `128.0.0.0/1` covered the default route in two pieces). Full tunnel is the client option. Stored legacy values below /8 are no longer put on hub peer AllowedIPs or agent routes.
- **Site network conflicts are checked by CIDR overlap**, not string equality (link edit, retyping a client to a site, metadata save, plan preview): `192.168.0.0/16` against another site's `192.168.20.0/24` is refused.
- **Freigaben check:** hub-sourced rules without a port list, or with ports no proxy host/stream uses, are listed as too broad; an upstream without a known port (e.g. `proxy_pass $server` without scheme/port) gets no one-click rule.
- **System certbot.timer must leave FloppyGuard certificates alone.** Since the DNS credentials only exist during FloppyGuard's own certbot runs, the distribution's `certbot.timer` can no longer renew the `npm-*` DNS certificates and would only log failures. Limit it to the certificates FloppyGuard does not manage. On the hub this is done with a `certbot.service` drop-in that runs `certbot renew --cert-name sso-comnic-it-de`.
- **UI languages are English, German and French only.** The 19 unmaintained locale bundles were removed (see Removed); a browser in another language falls back to English.
- Validation errors in the WireGuard, agent, user and certificate routes return 400 instead of 500, and every token failure (bad signature, malformed token) returns 401, so the frontend's automatic logout works again.
- Unparseable entries in WireGuard network lists are rejected with a clear error instead of being dropped silently (a typo such as `10.3.20.0/24x` used to revoke the site's network on the hub and every agent). An IPv6 entry in imported networks now gives a 400 on save.
- The 2FA issuer label in authenticator apps reads "FloppyGuard" (was "Nginx Proxy Manager"); new 2FA setups only.
- Help texts are rendered as Markdown; re-login after an expired session returns to the page you were on.
- Other dependency updates: mysql2 3.24.6, pg 8.23.1, better-sqlite3 12.11.1, knex 3.3.0, liquidjs 10.30.0, otplib 13.5.0, moment 2.31.0, compression 1.8.2, React 19.3.1, @tanstack/react-query 5.104.5, react-router-dom 7.18.4, @tabler/core 1.7.1, vitest 4.1.12, Biome 2.6.2 and smaller frontend updates. nginx templates render byte-identical with liquidjs 10.30.

#### Known limitations

- **Site ACLs are not enforced at the hub.** The hub forwards everything between its WireGuard peers (`FORWARD -i/-o wgN -j ACCEPT`); `allowed_networks`/`allowed_sites` and client reach lists only shape the routes/AllowedIPs of the restricted party's own gateway or client config. A site or client that adds routes itself can reach every other site through the hub. Do not treat them as a security boundary; filter at the target with Freigaben (*restricted*).
- **Hub-sourced Freigaben also admit the Hetzner LAN.** The hub masquerades `10.10.10.0/24` to its tunnel address, so a rule with the hub as source also lets Mailcow, the web server CT, … in. Keep such rules limited to the upstream ports (the check flags broader ones).
- **Agent config upload masks only `PrivateKey = ...` with spaces around `=`.** A gateway conf written as `PrivateKey=...` sends its real key to the hub when the config is uploaded. The fix is in the agent script and was deliberately left for the next agent script release (1.5.1 stays in this release).

#### Fixed

- Deleting a WireGuard peer rewrites `wg0.conf` before removing the peer live: a failed rewrite leaves the link fully intact and retryable.
- **Site LANs reach hosts on the hub LAN again.** Agents with `preserve_lan_source_ip` forward their LAN un-NATed; a host on the hub LAN (e.g. `10.10.10.108`) answered via its own default gateway instead of the hub, so the reply never reached the tunnel (on the Hetzner PVE it was even masqueraded to the public IP on the bridge). The hub auto-MASQUERADE now covers every net routed into the tunnel (`-o eth1 -s <site LAN>`), so hosts on the hub LAN see the hub address (`10.10.10.106`). The generated rules are reconciled live on every hub sync (`-C` before `-A`, previously owned keys removed) instead of only on `wg-quick up`; with a `WG_CONF_DIR` other than `/etc/wireguard` and no `IPTABLES_BIN` nothing is touched (installer-provisioned hubs, which always set `WG_CONF_DIR=/etc/wireguard`, were skipped before this was fixed in the audit).
- Hub MASQUERADE rules are owned by set membership (marker comment `# floppyguard-masq:` above PostUp), so an operator rule written as `-o eth1 -s X` is no longer dropped on rewrite.
- Restoring a metadata backup keeps a link's current name, type and imported networks when the backup has none, so bound agents keep their link; renames follow the effective name.
- Saving a proxy host/redirection/stream/404 host whose new config fails `nginx -t` keeps the previous config live (new one kept as `.err`, error in `nginx_err`).
- The ingress check reports VPN clients from the live status, including road warriors without imported networks and full-tunnel clients.
- Agent: PostDown/PostUp hooks run only after a successful `wg syncconf` and are not re-run on retries.
- SSO: every sign-in and every refused account link is written to the audit log (no tokens).
- `PUT /api/wireguard/metadata` with link changes failed with "is not a function".
- nginx: disabling/deleting hosts and writing the Let's Encrypt request conf now run under the same lock as saving a host, so they cannot interleave with its backup/test/restore.
- Imported Freigaben (VPN_MGR import) get the same `armed_on` start as hand-made ones.
- Freigaben check: an agent bound to an unnamed link (`<type>-<key>`) keeps its link when the inferred type changes; a link typed as client is reported as such instead of "not found".
- Traffic/Dashboard: peer colours come from the current links only (12 colours), so a peer keeps its colour across ranges and pages, and the charted peers never share a colour.
- Admin UI (install script): content-hashed `/assets/` are cached for a year (`immutable`); `worker_shutdown_timeout 30s` bounds how long old nginx workers live after a reload.

#### Fixed (ultracode audit, 3 passes, 265 confirmed findings)

Three audit passes (131, 89 and 79 findings, 34 rejected on verification). 253 were fixed in the passes, 11 of the 12 deferred ones in a follow-up; only the agent key masking above is open. Backend tests went from 390 to 564, frontend tests from 185 to 240.

- **WireGuard deletes:** the UI sent the delete options snake_cased while the backend read camelCase, so a *dry run* deleted the link or interface for real and the bound-agent cascade was unreachable.
- **Hub:** live MASQUERADE reconcile was skipped on every installer-provisioned hub; a MASQUERADE rule shared by two interfaces was deleted by the second one's PostDown; the tunnel subnet assumed /24; a conf with PostUp but no PostDown never got route/MASQUERADE teardown; extra `AllowedIPs =` lines of a hub peer survived every sync.
- **Metadata and links:** `PUT /api/wireguard/metadata` rejects unknown links/interfaces, validates the whole patch under one lock before writing, checks subnet conflicts against unmanaged peers too, catches two links renamed to the same name, and can clear fields; clearing a link name or retyping an unnamed link moves its agent binding along; `deleteInterface` does all its work under the lock; a failed hub sync in `updatePeer` no longer skips the agent resync; invalid `type`/`platform`/`listenPort` values are rejected.
- **Keys and traffic:** "Download config"/"Show QR" right after creating a link no longer rotates its key; a key rotation keeps the bandwidth history; one failed `wg show all dump` no longer wipes the live bandwidth buffer; the apply audit file is written atomically and a corrupt file is no longer overwritten with an empty history.
- **Agents:** `preserve_lan_source_ip: null` turned the flag on (default stays off); the admin install script for an already registered agent carried an empty token and broke the gateway; changing `wg_interface` brought up a second tunnel and left config/boot unit on the old name; unbinding an agent left the old cross-site AllowedIPs and MASQUERADE in its config; a corrupt update status file no longer blocks `/version/update` and startup; concurrent version checks share one GitHub request and a failed refresh keeps the cached result.
- **Freigaben and site isolation:** rule limits are checked under the lock; an agent's own site link is no longer listed as a VPN client; an unreadable wg conf no longer reports every upstream as missing; reordering sources/targets no longer re-arms a rule; `SITE_ISOLATION_DISABLED=true` really writes nothing; no contradictory warnings for a vanished link.
- **nginx and certificates:** the dead-host disable route was not awaited and could crash the backend; hosts regenerated after a certificate issue or access-list delete lost their SSL and access-list config, and a re-enabled host rendered `deny all`; a failed nginx reload or DB write after a successful certbot run no longer deletes the certificate row; DNS-challenge issuance no longer takes the hosts offline for the whole certbot run; Cloudflare sync tries the apex domain and no longer overwrites the nginx status; bulk config renders no longer race the restore; access lists without items no longer crash and leave an orphan; a custom certificate upload without key or with a failed upload no longer leaves a broken row.
- **Auth and users:** permission denials returned 500 instead of 403; a new user's permissions and audit entry used the auth id; backup codes failed for legacy 10-byte TOTP secrets; fail2ban unban reported success on failure; e-mails are normalized on create; `/api/schema` errors no longer throw.
- **Frontend:** the agent dialog on the WireGuard page crashed (link outside the router); the Freigaben picker opened behind the editor modal; applying a link rename created a duplicate agent; agent online status in the topology went stale; backend warnings were not shown; toggles swallowed API errors; a search filter could hide the Add button with no way out; truncated lists (networks, warnings, routes) now show "+N more"; DNS-challenge fields were not cleared; double submit, permission dialog errors, the settings menu for non-admins with permissions, interface notes containing commas and many hard-coded English/German strings were fixed.
- **Performance and consolidation:** Ajv schemas and the permission file are compiled/read once; the JWT is verified once per request; `nginx -t` runs once per host save; the agent heartbeat is a single UPDATE; repeated status/metadata reads collapsed; the Freigaben list no longer fetches every agent's rules (N+1); duplicated helpers merged (token lookups, Express route helper `lib/express/route.js`, certbot argument builders, WireGuard post-write pipeline, table wrappers, time/rate formatters, query-key lists).

#### Fixed (upstream nginx-proxy-manager v2.15.0 to v2.16.0)

- `scripts/regenerate-config` writes every host with its own model and type (#5813); before, all were written as `proxy_host/<id>.conf`.
- Certificate CN parsing works with OpenSSL 3 (`subject=CN=...`) as well as 1.1 and 1.0; a subject like `C=DE, O=..., CN=...` no longer yields `["DE,"]`, and no certificate gets `[null]` domain names.
- An access list with users but no client rules no longer adds `deny all`, so it also works with *Satisfy All* (#5543); an empty access list stays closed.
- IPv6 stream upstreams are wrapped in `[...]` (#5741); access-list users and rules are saved in the order entered (#5421); the Streams table shows Enable/Disable by state (#5489); certbot plugin installs use `SETUPTOOLS_USE_DISTUTILS=local` and quoted pip arguments; error payloads carry the status code (ee1f7ba).

#### Removed

- 19 unused locale bundles (bg, cs, es, et, ga, hu, id, it, ja, ko, nl, no, pl, pt, ru, sk, tr, vi, zh) with their compiled copies and HelpDoc folders.
- The unrouted Platform page and its 22 locale keys (`/platform` still opens the Dashboard).
- `POST /api/design/screenshot` (no caller, wrote into the served frontend directory).
- Dead code: `lib/express/pagination.js`, unused user/certificate/nginx helpers, the legacy VPN_MGR compare helpers, unused frontend hooks and API helpers (`useCertificate`, `useDeleteWireGuardPeer`, `getWireGuardMetadata`, `updateWireGuardMetadata`, table pagination helpers) and the non-functional notifications bell.

### Deutsch

Audit-Nacharbeiten, ein dreistufiger Ultracode-Audit (299 gemeldet, 265 bestätigt, 253 behoben), die passenden Upstream-Fixes aus nginx-proxy-manager v2.15.0 bis v2.16.0 und Sicherheits-Updates der Abhängigkeiten. **Das Agent-Skript bleibt 1.5.1:** Das Loop-Skript ist seit 2.3.0 unverändert, es gibt also kein Selbst-Update der Agents. Das unten mit „1.5.0“ beschriebene Agent-Verhalten ist bereits mit Agent-Skript 1.5.1 in 2.3.0 ausgeliefert worden.

#### Sicherheit

- **Der 2FA-QR-Code wird lokal erzeugt.** Der Einrichtungsdialog schickte das TOTP-Geheimnis an `api.qrserver.com`, um den QR-Code zu zeichnen. Das Backend liefert jetzt eine PNG-Data-URL (`qr_data_url`, Paket `qrcode`); das Geheimnis verlässt den Server nicht mehr.
- **Tokens werden bei einer Passwortänderung widerrufen** (Upstream #5836). Eine Passwortänderung setzt `password_changed_at`; jedes vorher ausgestellte Token wird mit 401 abgewiesen, auch beim Erneuern, bei der 2FA-Abfrage und auf Admin-Routen. **Wer das eigene Passwort ändert, wird abgemeldet:** Der Dialog zeigt einen Hinweis und führt zur Anmeldung. Reine SSO-Konten sind nicht betroffen.
- **Der TOTP-Code zum Abschalten steht im Request-Body.** `DELETE /api/users/:id/2fa` erwartet `{ "code": ... }` im Body statt `?code=` in der URL (keine Codes mehr in Access-Logs); der Query-Parameter wird für ein altes, zwischengespeichertes Frontend noch angenommen.
- 2FA aktivieren/abschalten/Backup-Codes und die Passwortänderung sind begrenzt (10 pro 15 Minuten je IP); die Anmeldung rechnet auch bei unbekannten E-Mails dieselbe bcrypt-Arbeit, Konten lassen sich nicht mehr über die Antwortzeit ermitteln; „Anmelden als“ lehnt deaktivierte Benutzer ab; „Anmelden als“, 2FA-Änderungen und Einstellungen stehen im Audit-Log.
- **Zugangsdaten für DNS-Challenges liegen nur während eines certbot-Laufs auf der Platte** (Upstream #5814): mit Rechten 0600 direkt vor certbot geschrieben und danach entfernt. Beim Start werden alte `credentials-<id>`-Dateien (und abgebrochene `.tmp`-Kopien) aus den Credentials-Verzeichnissen gelöscht, außer die Datei ist die einzige Kopie (DNS-Zertifikat ohne in der Datenbank gespeicherte Zugangsdaten).
- Streams prüfen den Besitz des Zertifikats (ein Benutzer konnte das Zertifikat samt Schlüssel eines anderen an einen Stream hängen); Antworten und Audit-Einträge von Proxy-Hosts enthalten keine Basic-Auth-Passwörter von Zugriffslisten mehr, und maskierte Passwörter verraten weder erstes Zeichen noch Länge; das Erneuern eines Zertifikats liefert und protokolliert die Zugangsdaten des DNS-Anbieters nicht mehr; 404-Hosts liefern das Zertifikat ohne dessen Meta-Daten.
- htpasswd: Benutzernamen mit `:` oder Steuerzeichen werden abgelehnt, und ein Passwort, das mit `-` beginnt, wird nicht mehr als openssl-Option gelesen (das hinterließ eine halb geschriebene Datei und sperrte alle Benutzer aus).
- Private Schlüssel eigener Zertifikate werden mit Rechten 0600 geschrieben; der Zertifikat-Download lässt kein Zip mehr in `/tmp` liegen.
- IP-Bereiche von CloudFront/Cloudflare werden geprüft, bevor sie in `ip_ranges.conf` landen, und eine Fehlerseite von cloudflare.com leert die `set_real_ip_from`-Liste nicht mehr für 6 Stunden.
- Die Trennung der Standorte schließt im Zweifel: Ist der WireGuard-Live-Status nicht verfügbar, behalten Verbindungen ihren zuletzt bekannten Typ und ihre importierten Netze, statt auf „keine Netze“ zu fallen, und ein Anwenden, das ein Paar mit einer ungeklärten Verbindung entfernen würde, wird abgelehnt.
- `mgmt_url` von Agents wird geprüft (http/https, höchstens 512 Zeichen), bevor sie als Link erscheint; Anmeldedaten von Benutzern werden beim Anlegen geprüft (Typ, Länge des Geheimnisses); die Prüfung der Hub-URL entspricht der Whitelist der Agents; externe Domain-Links öffnen mit `rel="noopener noreferrer"`.
- **Abhängigkeiten:** express 5.3.0 mit proxy-addr 2.0.8 (GHSA-jqcg-44mw-7w3h), dazu body-parser 2.4.0, qs 6.16.1, fast-uri 3.1.9, ip-address 10.7.4, js-yaml 4.3.2, brace-expansion 5.0.12 (Backend) sowie vite 7.3.7, postcss 8.5.31, nanoid 3.3.20 (Frontend).

#### Geändert

- **Modus „offen" mit Freigaben beobachtet nur noch.** Agent-Skript 1.4.0 hat passende Verbindungen (und allen RELATED,ESTABLISHED-Verkehr) in `FG_IN` an Position 1 von FORWARD per ACCEPT durchgelassen. Ab 1.5.0 springt ein *offener* Agent mit Freigaben nur noch per RETURN zurück: Die Freigaben zählen Treffer, der Verkehr läuft weiter durch die eigenen FORWARD-Regeln des Gateways (z. B. VPN_MGR, ufw, docker). Jeder offene Agent mit Freigaben bekommt einen neuen Regelsatz-Hash und ändert sein Verhalten beim ersten Abruf nach dem Selbst-Update. Gefiltert wird nur im Modus *nur Freigaben*. **Umstellung:** Einen externen Filter wie VPN_MGR erst entfernen, wenn der Agent auf *nur Freigaben* steht und der Bereich den Filter als gesetzt meldet: Ein offener Agent ohne VPN_MGR filtert gar nichts. Der Bereich weist bei offenen Agents mit Freigaben jetzt darauf hin.
- **Agents melden einen neu geprüften Konfigurations-Hash.** Beim ersten Start von 1.5.0 verwirft der Agent die von 1.4.0 geschriebene `last_hash` (die auch nach einem fehlgeschlagenen Anwenden geschrieben wurde) und wendet die aktuelle Konfiguration einmal neu an (ohne Wirkung, wenn sie schon aktiv ist).
- **Ein ausstehender Freigaben-Status wird nach einer Änderung höchstens 3 Minuten abgefragt**; ein Agent ohne Heartbeat seit 5 Minuten erscheint als *Agent offline* statt *ausstehend*.
- **Hub-URLs für den Weg übers Internet nur noch per https.** Die öffentliche URL der Einstellung `agent-hub-url` (Wert / Fallback) und `public_url` des Agent-Installationsskripts werden mit `http://` per 400 abgelehnt; die interne Primär-URL darf http bleiben. `get_server` im Agent 1.5.0 fällt außerhalb des Tunnels nicht mehr auf eine http-URL zurück: Ist die Primär-URL nicht erreichbar und der Fallback http und nicht durch den Tunnel geroutet, wartet der Agent, statt sein Token im Klartext zu senden. Einen http-Fallback vor dem Agent-Update auf https umstellen.
- **Agents lassen sich erzwungen löschen** (`DELETE /api/agents/:id?force=1`, in der Oberfläche mit zweiter Bestätigung), wenn sie sich seit 1 Stunde nicht gemeldet haben. Die Tokens werden widerrufen, das Gateway behält aber seinen letzten Freigaben-Filter (`FG_IN`), bis er dort von Hand entfernt wird.
- **Beim Löschen einer WireGuard-Verbindung oder -Schnittstelle kümmert sich das Backend um gebundene Agents.** `deletePeer`/`deleteInterface` lehnen ab (409), solange nicht gelöschte Agents an den Verbindungsnamen gebunden sind (ein Agent würde die Verbindung mit gültigem Token überleben und von einer späteren Verbindung gleichen Namens geerbt). Mit `deleteBoundAgents` wird zuerst jeder gebundene Agent geprüft (lehnt einer ab, z. B. weil der Freigaben-Filter noch aktiv ist, wird nichts gelöscht), dann der Peer bzw. die Schnittstelle entfernt und erst danach die Agents. `dryRun: true` meldet die gebundenen Agents und ob sie sich löschen lassen; `forceAgentIds` löscht seit 1 Stunde stumme Agents erzwungen. Die Oberfläche führt das als einen Vorgang aus.
- **Netzlisten lehnen Präfixe kürzer als /8 ab.** Alle Netzlisten der WireGuard-Metadaten (exportierte/importierte Netze von Verbindungen und Schnittstellen, Routenziele) und die Erreichbarkeitsliste eines neuen oder bearbeiteten Clients lehnen `/0` und jedes Präfix unter `/8` ab (`0.0.0.0/1` + `128.0.0.0/1` deckten die Default-Route in zwei Teilen ab). Full-Tunnel ist die Client-Option. Gespeicherte Altwerte unter /8 landen nicht mehr in den AllowedIPs der Hub-Peers oder in Agent-Routen.
- **Netzkonflikte zwischen Standorten werden per CIDR-Überlappung geprüft** statt per Textgleichheit (Verbindung bearbeiten, Client zu Standort umtypisieren, Metadaten speichern, Plan-Vorschau): `192.168.0.0/16` gegen das `192.168.20.0/24` eines anderen Standorts wird abgelehnt.
- **Freigaben-Prüfung:** Freigaben vom Hub ohne Port-Liste oder mit Ports, die kein Proxy-Host/Stream nutzt, werden als zu weit gemeldet; ein Upstream ohne bekannten Port (z. B. `proxy_pass $server` ohne Schema/Port) bekommt keinen Ein-Klick-Vorschlag.
- **Der System-certbot.timer muss FloppyGuard-Zertifikate auslassen.** Weil die DNS-Zugangsdaten nur noch während der certbot-Läufe von FloppyGuard existieren, kann der `certbot.timer` der Distribution die `npm-*`-DNS-Zertifikate nicht mehr erneuern und würde nur Fehler protokollieren. Ihn auf die Zertifikate beschränken, die FloppyGuard nicht verwaltet. Am Hub geschieht das über ein Drop-in für `certbot.service`, das `certbot renew --cert-name sso-comnic-it-de` ausführt.
- **Die Oberfläche gibt es nur noch auf Englisch, Deutsch und Französisch.** Die 19 nicht gepflegten Sprachpakete wurden entfernt (siehe Entfernt); ein Browser in einer anderen Sprache fällt auf Englisch zurück.
- Validierungsfehler in den Routen für WireGuard, Agents, Benutzer und Zertifikate liefern 400 statt 500, und jeder Token-Fehler (falsche Signatur, kaputtes Token) liefert 401, sodass die automatische Abmeldung im Frontend wieder greift.
- Nicht lesbare Einträge in WireGuard-Netzlisten werden mit klarer Meldung abgelehnt, statt still zu verschwinden (ein Tippfehler wie `10.3.20.0/24x` entzog dem Standort sein Netz am Hub und auf jedem Agent). Ein IPv6-Eintrag in den importierten Netzen ergibt beim Speichern jetzt 400.
- Der 2FA-Aussteller in Authenticator-Apps heißt „FloppyGuard“ (bisher „Nginx Proxy Manager“); gilt nur für neue Einrichtungen.
- Hilfetexte werden als Markdown dargestellt; nach einer abgelaufenen Sitzung führt die Anmeldung zurück auf die vorherige Seite.
- Weitere Abhängigkeiten: mysql2 3.24.6, pg 8.23.1, better-sqlite3 12.11.1, knex 3.3.0, liquidjs 10.30.0, otplib 13.5.0, moment 2.31.0, compression 1.8.2, React 19.3.1, @tanstack/react-query 5.104.5, react-router-dom 7.18.4, @tabler/core 1.7.1, vitest 4.1.12, Biome 2.6.2 und kleinere Frontend-Updates. Die nginx-Vorlagen werden mit liquidjs 10.30 byte-gleich erzeugt.

#### Bekannte Einschränkungen

- **Standort-ACLs werden am Hub nicht durchgesetzt.** Der Hub leitet zwischen seinen WireGuard-Peers alles weiter (`FORWARD -i/-o wgN -j ACCEPT`); `allowed_networks`/`allowed_sites` und die Erreichbarkeitslisten von Clients bestimmen nur Routen/AllowedIPs am Gateway bzw. in der Client-Konfiguration der eingeschränkten Seite. Ein Standort oder Client, der selbst Routen setzt, erreicht über den Hub jeden anderen Standort. Sie sind keine Sicherheitsgrenze; gefiltert wird am Ziel mit Freigaben (*nur Freigaben*).
- **Freigaben mit dem Hub als Quelle lassen auch das Hetzner-LAN herein.** Der Hub maskiert `10.10.10.0/24` auf seine Tunnel-Adresse; eine Freigabe vom Hub lässt daher auch Mailcow, den Webserver-CT usw. durch. Solche Freigaben auf die Ports der Upstreams beschränken (die Prüfung meldet weitere).
- **Der Agent maskiert beim Hochladen der Konfiguration nur `PrivateKey = ...` mit Leerzeichen um `=`.** Eine Gateway-Konfiguration mit `PrivateKey=...` schickt beim Hochladen den echten Schlüssel an den Hub. Die Korrektur gehört ins Agent-Skript und wurde bewusst für das nächste Agent-Skript-Release zurückgestellt (in diesem Release bleibt 1.5.1).

#### Behoben

- Beim Löschen eines WireGuard-Peers wird zuerst `wg0.conf` umgeschrieben und erst dann der Peer live entfernt: Schlägt das Umschreiben fehl, bleibt die Verbindung vollständig erhalten und das Löschen kann wiederholt werden.
- **Standort-LANs erreichen Hosts im Hub-LAN wieder.** Agents mit `preserve_lan_source_ip` leiten ihr LAN ungenattet weiter; ein Host im Hub-LAN (z. B. `10.10.10.108`) antwortete über sein eigenes Default-Gateway statt über den Hub, die Antwort fand den Tunnel nie (am Hetzner-PVE wurde sie auf der Bridge sogar auf die öffentliche IP maskiert). Die Auto-MASQUERADE des Hubs umfasst jetzt jedes in den Tunnel geroutete Netz (`-o eth1 -s <Standort-LAN>`), Hosts im Hub-LAN sehen die Hub-Adresse (`10.10.10.106`). Die erzeugten Regeln werden bei jedem Hub-Sync live abgeglichen (`-C` vor `-A`, früher eigene Schlüssel entfernt) statt nur bei `wg-quick up`; mit einem `WG_CONF_DIR` außer `/etc/wireguard` ohne `IPTABLES_BIN` wird nichts angefasst (vom Installer eingerichtete Hubs, die immer `WG_CONF_DIR=/etc/wireguard` setzen, wurden vor dem Audit-Fix übersprungen).
- MASQUERADE-Regeln des Hubs gehören FloppyGuard nur noch per Mengenzugehörigkeit (Markierung `# floppyguard-masq:` über PostUp); eine eigene Regel der Form `-o eth1 -s X` wird beim Umschreiben nicht mehr entfernt.
- Beim Wiederherstellen einer Metadaten-Sicherung bleiben Name, Typ und importierte Netze einer Verbindung erhalten, wenn die Sicherung keine enthält; gebundene Agents behalten ihre Verbindung.
- Speichern eines Hosts, dessen neue Konfiguration `nginx -t` nicht besteht, lässt die bisherige Konfiguration aktiv (die neue bleibt als `.err`, Fehler in `nginx_err`).
- Die Freigaben-Prüfung meldet VPN-Clients aus dem Live-Status, auch Road-Warrior ohne importierte Netze und Full-Tunnel-Clients.
- Agent: PostDown/PostUp laufen erst nach erfolgreichem `wg syncconf` und bei Wiederholungen nicht erneut.
- SSO: Jede Anmeldung und jede abgewiesene Kontoverknüpfung steht im Audit-Log (ohne Tokens).
- `PUT /api/wireguard/metadata` mit Verbindungsänderungen schlug mit „is not a function“ fehl.
- nginx: Deaktivieren/Löschen von Hosts und das Schreiben der Let's-Encrypt-Anfrage-Konfiguration laufen jetzt unter derselben Sperre wie das Speichern eines Hosts und können sich nicht mehr mit dessen Sichern/Testen/Zurückspielen überschneiden.
- Importierte Freigaben (VPN_MGR-Import) bekommen denselben `armed_on`-Start wie von Hand angelegte.
- Freigaben-Prüfung: Ein Agent an einer unbenannten Verbindung (`<Typ>-<Schlüssel>`) behält seine Verbindung, wenn sich der erkannte Typ ändert; eine als Client eingetragene Verbindung wird als solche gemeldet statt „nicht gefunden“.
- Traffic/Dashboard: Die Peer-Farben kommen nur aus den aktuellen Verbindungen (12 Farben); ein Peer behält seine Farbe über Zeiträume und Seiten hinweg, und die Peers im Diagramm teilen sich nie eine Farbe.
- Admin-Oberfläche (Installationsskript): Die Dateien unter `/assets/` (mit Inhalts-Hash) werden ein Jahr gecacht (`immutable`); `worker_shutdown_timeout 30s` begrenzt, wie lange alte nginx-Worker nach einem Reload weiterlaufen.

#### Behoben (Ultracode-Audit, 3 Durchläufe, 265 bestätigte Funde)

Drei Audit-Durchläufe (131, 89 und 79 Funde, 34 bei der Prüfung verworfen). 253 wurden in den Durchläufen behoben, 11 der 12 zurückgestellten in einer Nacharbeit; offen ist nur die oben genannte Schlüssel-Maskierung im Agent. Backend-Tests von 390 auf 564, Frontend-Tests von 185 auf 240.

- **Löschen in WireGuard:** Die Oberfläche schickte die Löschoptionen in snake_case, das Backend las camelCase; ein *Probelauf* löschte Verbindung bzw. Schnittstelle also wirklich, und das Mitlöschen gebundener Agents war nicht erreichbar.
- **Hub:** Der Live-Abgleich der MASQUERADE-Regeln wurde auf jedem vom Installer eingerichteten Hub übersprungen; eine von zwei Schnittstellen geteilte MASQUERADE-Regel wurde vom PostDown der zweiten gelöscht; das Tunnel-Subnetz setzte /24 voraus; eine Konfiguration mit PostUp, aber ohne PostDown bekam nie das Abräumen von Routen/MASQUERADE; zusätzliche `AllowedIPs =`-Zeilen eines Hub-Peers überlebten jeden Sync.
- **Metadaten und Verbindungen:** `PUT /api/wireguard/metadata` lehnt unbekannte Verbindungen/Schnittstellen ab, prüft den ganzen Patch unter einer Sperre vor dem Schreiben, prüft Netzkonflikte auch gegen nicht verwaltete Peers, erkennt zwei auf denselben Namen umbenannte Verbindungen und kann Felder leeren; Leeren eines Verbindungsnamens oder Umtypisieren einer unbenannten Verbindung nimmt die Agent-Bindung mit; `deleteInterface` arbeitet vollständig unter der Sperre; ein fehlgeschlagener Hub-Sync in `updatePeer` überspringt den Agent-Abgleich nicht mehr; ungültige Werte für `type`/`platform`/`listenPort` werden abgelehnt.
- **Schlüssel und Traffic:** „Config herunterladen“/„QR anzeigen“ direkt nach dem Anlegen einer Verbindung rotiert ihren Schlüssel nicht mehr; eine Schlüsselrotation behält den Traffic-Verlauf; ein einzelnes fehlgeschlagenes `wg show all dump` leert den Live-Puffer nicht mehr; die Apply-Audit-Datei wird atomar geschrieben, eine beschädigte Datei wird nicht mehr mit leerem Verlauf überschrieben.
- **Agents:** `preserve_lan_source_ip: null` schaltete die Option ein (Standard bleibt aus); das Admin-Installationsskript für einen schon registrierten Agent enthielt ein leeres Token und legte das Gateway lahm; eine Änderung von `wg_interface` startete einen zweiten Tunnel und ließ Konfiguration/Boot-Unit auf dem alten Namen; nach dem Lösen der Bindung blieben alte standortübergreifende AllowedIPs und MASQUERADE in der Konfiguration; eine beschädigte Update-Statusdatei blockiert `/version/update` und den Start nicht mehr; gleichzeitige Versionsprüfungen teilen sich eine GitHub-Anfrage, ein fehlgeschlagenes Erneuern behält das zwischengespeicherte Ergebnis.
- **Freigaben und Trennung der Standorte:** Regel-Obergrenzen werden unter der Sperre geprüft; die eigene Standortverbindung eines Agents erscheint nicht mehr als VPN-Client; eine nicht lesbare wg-Konfiguration meldet nicht mehr jeden Upstream als fehlend; Umsortieren von Quellen/Zielen schärft eine Freigabe nicht neu; `SITE_ISOLATION_DISABLED=true` schreibt wirklich nichts; keine widersprüchlichen Warnungen für eine verschwundene Verbindung.
- **nginx und Zertifikate:** Die Route zum Deaktivieren von 404-Hosts wurde nicht abgewartet und konnte das Backend abstürzen lassen; nach dem Ausstellen eines Zertifikats oder dem Löschen einer Zugriffsliste neu erzeugte Hosts verloren SSL- und Zugriffslisten-Konfiguration, ein wieder aktivierter Host bekam `deny all`; ein fehlgeschlagener nginx-Reload oder DB-Schreibvorgang nach erfolgreichem certbot-Lauf löscht den Zertifikatseintrag nicht mehr; Ausstellen per DNS-Challenge nimmt die Hosts nicht mehr für den ganzen certbot-Lauf offline; der Cloudflare-Sync probiert die Apex-Domain und überschreibt den nginx-Status nicht mehr; Sammel-Erzeugung von Konfigurationen kollidiert nicht mehr mit dem Zurückspielen; Zugriffslisten ohne Einträge stürzen nicht mehr ab und hinterlassen keine Waise; ein Upload eigener Zertifikate ohne Schlüssel oder mit fehlgeschlagenem Upload hinterlässt keinen kaputten Eintrag.
- **Anmeldung und Benutzer:** Verweigerte Berechtigungen ergaben 500 statt 403; Berechtigungen und Audit-Eintrag eines neuen Benutzers nutzten die Auth-ID; Backup-Codes scheiterten bei alten 10-Byte-TOTP-Geheimnissen; das Entsperren in fail2ban meldete auch bei Fehlern Erfolg; E-Mails werden beim Anlegen normalisiert; Fehler in `/api/schema` werfen nicht mehr.
- **Oberfläche:** Der Agent-Dialog auf der WireGuard-Seite stürzte ab (Link außerhalb des Routers); die Auswahl in Freigaben öffnete sich hinter dem Editor; das Anwenden einer Umbenennung legte einen doppelten Agent an; der Online-Status der Agents in der Topologie veraltete; Backend-Warnungen wurden nicht angezeigt; Schalter verschluckten API-Fehler; ein Suchfilter konnte den Hinzufügen-Knopf ohne Ausweg verstecken; gekürzte Listen (Netze, Warnungen, Routen) zeigen jetzt „+N weitere“; DNS-Challenge-Felder wurden nicht geleert; doppeltes Absenden, Fehler im Berechtigungsdialog, das Einstellungsmenü für Nicht-Admins mit Rechten, Schnittstellen-Notizen mit Komma und viele fest verdrahtete englische/deutsche Texte wurden korrigiert.
- **Leistung und Zusammenführung:** Ajv-Schemas und die Berechtigungsdatei werden einmal übersetzt/gelesen; das JWT wird einmal pro Anfrage geprüft; `nginx -t` läuft einmal pro Speichern eines Hosts; der Agent-Heartbeat ist ein einzelnes UPDATE; wiederholte Status-/Metadaten-Lesevorgänge zusammengefasst; die Freigaben-Liste lädt nicht mehr die Regeln jedes Agents einzeln (N+1); doppelte Helfer zusammengeführt (Token-Suche, Express-Routenhelfer `lib/express/route.js`, certbot-Argumente, WireGuard-Ablauf nach dem Schreiben, Tabellen-Rahmen, Zeit-/Ratenformatierung, Query-Key-Listen).

#### Behoben (Upstream nginx-proxy-manager v2.15.0 bis v2.16.0)

- `scripts/regenerate-config` schreibt jeden Host mit seinem eigenen Modell und Typ (#5813); bisher landeten alle als `proxy_host/<id>.conf`.
- Das Auslesen des CN von Zertifikaten funktioniert mit OpenSSL 3 (`subject=CN=...`) sowie 1.1 und 1.0; ein Subject wie `C=DE, O=..., CN=...` ergibt nicht mehr `["DE,"]`, und kein Zertifikat bekommt `[null]` als Domains.
- Eine Zugriffsliste mit Benutzern, aber ohne Client-Regeln setzt kein `deny all` mehr und funktioniert damit auch mit *Satisfy All* (#5543); eine leere Zugriffsliste bleibt geschlossen.
- IPv6-Upstreams von Streams stehen in `[...]` (#5741); Benutzer und Regeln von Zugriffslisten werden in der eingegebenen Reihenfolge gespeichert (#5421); die Streams-Tabelle zeigt Aktivieren/Deaktivieren je nach Zustand (#5489); certbot-Plugins werden mit `SETUPTOOLS_USE_DISTUTILS=local` und gequoteten pip-Argumenten installiert; Fehlerantworten enthalten den Statuscode (ee1f7ba).

#### Entfernt

- 19 ungenutzte Sprachpakete (bg, cs, es, et, ga, hu, id, it, ja, ko, nl, no, pl, pt, ru, sk, tr, vi, zh) samt übersetzten Kopien und HelpDoc-Ordnern.
- Die nicht eingebundene Platform-Seite und ihre 22 Sprachschlüssel (`/platform` öffnet weiterhin das Dashboard).
- `POST /api/design/screenshot` (ohne Aufrufer, schrieb in das ausgelieferte Frontend-Verzeichnis).
- Toter Code: `lib/express/pagination.js`, ungenutzte Helfer für Benutzer/Zertifikate/nginx, die alten VPN_MGR-Vergleichshelfer, ungenutzte Frontend-Hooks und API-Helfer (`useCertificate`, `useDeleteWireGuardPeer`, `getWireGuardMetadata`, `updateWireGuardMetadata`, Tabellen-Paginierung) und die funktionslose Benachrichtigungsglocke.

## [2.3.0] - 2026-10-10

Per-agent ingress filter ("Freigaben") with an intuitive editor, a modern topology map and the fixes of a four-round audit. Agent script 1.5.1.

Per-agent ingress filter ("Freigaben"): FloppyGuard now decides which traffic arriving through a site's tunnel may reach which targets in that site's LAN. This replaces the external VPN_MGR chain of the UniFi Manager on the Floppy Home gateway, so routing (exported/imported networks) and filtering live in one place. Agent script 1.4.0, then 1.5.1 later the same day (also ships the UniFi clean-up from 2.2.2). One migration runs on startup (`agent.ingress_mode`, table `agent_ingress_rule`). Agents without rules are untouched: no chain, no rule.

### English

#### Added

- **Ingress rules per agent.** Each rule has sources (CIDRs, e.g. the hub tunnel address or a site network), destinations (empty = any target), optional ports (tcp/udp, ranges) and a note. Mode per agent: *open* (no filter) or *restricted* (everything else arriving via the tunnel is dropped; established return traffic always passes). Switching to restricted, or disabling/deleting the last active rule while restricted, is refused so a site cannot be cut off by accident.
- **Agent applies the filter itself** as chain `FG_IN`: atomic `iptables-restore --noflush` (a broken ruleset changes nothing), exactly one jump at FORWARD position 1, inserted before the old one is removed. The ruleset is cached on the agent and restored at start before the hub is reachable, so a reboot never leaves a restricted gateway open; a flushed chain or a moved jump is repaired on the next poll. Payloads are hash-checked and validated (only `FG_IN` rules with ACCEPT/DROP).
- **Proxy check.** Proxy hosts and streams whose upstream lies behind a restricted agent but is not covered by a rule are listed with a one-click "create rule"; rules from the hub address whose targets no proxy host/stream uses are flagged.
- **Hit counters.** Agents report packet counters per rule in the heartbeat; the UI shows the last hit and flags rules without hits for 30 days.
- **UI.** New page *Freigaben* (admin), a summary block with a dialog in the agent panel, generated-rules preview, audit log entries (`agent-ingress`). Translations: en, de, fr.
- **API.** `GET/PUT /api/agents/:id/ingress`, `GET /api/agents/:id/ingress/preview`, `POST /api/agents/:id/ingress/rules`, `PUT/DELETE /api/agents/:id/ingress/rules/:ruleId`, `GET /api/agent-ingress/check`.

#### Fixed

- **Duplicate tunnel rules on agents.** Older PostUp re-runs left exact duplicate `-i/-o <wg>` FORWARD and NAT rules (on the Floppy Home gateway 12 FORWARD and ~50 NAT copies). The agent now removes later copies of terminal rules on start and after each config apply; behaviour is unchanged.

### Deutsch

#### Neu

- **Freigaben pro Agent.** Jede Freigabe hat Quellen (CIDRs, z. B. die Tunnel-Adresse des Hubs oder ein Standortnetz), Ziele (leer = alle), optional Ports (tcp/udp, Bereiche) und eine Notiz. Modus pro Agent: *offen* (kein Filter) oder *nur Freigaben* (alles andere, was über den Tunnel kommt, wird verworfen; Antwortverkehr bestehender Verbindungen geht immer durch). Das Umschalten auf „nur Freigaben" ohne aktive Freigabe sowie das Abschalten/Löschen der letzten aktiven Freigabe werden abgelehnt, damit kein Standort versehentlich abgeschnitten wird.
- **Der Agent setzt den Filter selbst** als Kette `FG_IN`: atomar per `iptables-restore --noflush` (ein fehlerhafter Regelsatz ändert nichts), genau ein Sprung an Position 1 in FORWARD, ohne Lücke. Der Regelsatz wird auf dem Agent zwischengespeichert und beim Start gesetzt, bevor der Hub erreichbar ist – nach einem Neustart steht ein Gateway also nie offen. Eine geleerte Kette oder ein verschobener Sprung wird beim nächsten Abruf repariert. Die Nutzlast wird per Hash geprüft und validiert (nur `FG_IN`-Regeln mit ACCEPT/DROP).
- **Proxy-Prüfung.** Proxy-Hosts und Streams, deren Ziel hinter einem Agent mit „nur Freigaben" liegt, aber von keiner Freigabe abgedeckt ist, werden mit „Freigabe anlegen" (ein Klick) angezeigt; Freigaben vom Hub, deren Ziele kein Proxy-Host/Stream mehr nutzt, werden markiert.
- **Trefferzähler.** Die Agents melden pro Freigabe die Paketzähler im Heartbeat; die Oberfläche zeigt den letzten Treffer und markiert Freigaben ohne Treffer seit 30 Tagen.
- **Oberfläche.** Neue Seite *Freigaben* (Admin), Übersicht mit Dialog im Agent-Bereich, Vorschau der erzeugten Regeln, Audit-Log-Einträge (`agent-ingress`). Übersetzungen: en, de, fr.

#### Behoben

- **Doppelte Tunnel-Regeln auf Agents.** Frühere PostUp-Wiederholungen hatten exakte Duplikate von `-i/-o <wg>`-Regeln in FORWARD und NAT hinterlassen (am Floppy-Home-Gateway 12 FORWARD- und rund 50 NAT-Kopien). Der Agent entfernt beim Start und nach jedem Konfigurations-Update spätere Kopien terminierender Regeln; das Verhalten bleibt gleich.

#### Added (later on 2026-10-10)

- **Intuitive Freigaben.** Sources and targets are picked by name from a catalog (sites, their networks, VPN clients, "Reverse Proxy (Hub)"; proxy hosts/streams with their domains, discovered services, site networks) instead of typing CIDRs; ports as presets (Web, SSH, SMB, LDAP, RDP, DNS, Proxmox, PBS). Three wizards: publish a service via the proxy, site may reach servers, site gets full access. Rules read as sentences grouped by source. A "may X reach Y?" tester shows the verdict and the matching rule. "Freigeben" for all missing proxy targets at once and "disable unused rules" (never the last active rule in restricted mode). API: `GET /api/agents/:id/ingress/catalog`, `POST /api/agents/:id/ingress/test`, bulk create/disable.
- **Modern topology map** on the WireGuard page: hub in the centre, cards per site/agent/client with type icons, status colour from the handshake age, traffic on the links, legend, light and dark theme, responsive fallback grid.

#### Fixed (ultracode audit, 4 rounds, 119 confirmed findings)

- **Certificate renewal could delete the live certificate** when certbot failed; intact lineages are now renewed in place, an interrupted renewal is restored, and a failing nginx reload no longer triggers a renewal on every timer run.
- **"Download config" / "Show QR" on a site or agent link rotated the hub-side key** and cut the site off; it is now refused for those links.
- **Renaming a link in the metadata editor orphaned its agent**; renames now cascade to the agent binding.
- **SSO users were logged out every 5 minutes** (token refresh called a non-existent method).
- **Agent script 1.5.1:** the WireGuard private key no longer lands in `/tmp`, the token no longer appears in the process list, failed applies are reported instead of being marked applied, the Freigaben are restored by a boot unit before WireGuard comes up, and the self-update check no longer fails at random on large scripts (SIGPIPE under pipefail). The hub now shows whether each agent actually applied its config and Freigaben.
- Timeouts for Cloudflare DNS and the remote version check, plus many smaller logic, resilience and performance fixes (see git history).

#### Neu (später am 10.10.2026)

- **Freigaben einfacher:** Quellen und Ziele per Auswahl mit Namen statt CIDR, Ports als Vorlagen, drei Assistenten, Regeln als Sätze nach Quelle gruppiert, Test „Darf X auf Y?“, alle fehlenden Proxy-Ziele auf einmal freigeben, ungenutzte Regeln abschalten.
- **Moderne Topologie-Karte** auf der WireGuard-Seite.

#### Behoben (Ultracode-Audit, 4 Runden, 119 bestätigte Funde)

- Zertifikats-Erneuerung konnte das Live-Zertifikat löschen; „Config herunterladen“ an Standort-Links schnitt den Standort ab; Umbenennen im Metadaten-Editor verwaiste Agents; SSO-Nutzer flogen alle 5 Minuten raus; Agent-Skript 1.5.1 (Schlüssel nicht mehr in /tmp, Token nicht in der Prozessliste, Fehler werden gemeldet, Freigaben vor WireGuard beim Booten, Selbst-Update scheitert nicht mehr zufällig).

## [2.2.2] - 2026-10-09

Removes the UniFi integration. The UniFi agent mode was never exposed in the UI and no agent used it. One migration runs on startup and drops the stored UniFi columns. The agent script changes only in dead UniFi code, so `AGENT_SCRIPT_VERSION` stays 1.3.23 to avoid a fleet-wide re-download and restart; the cleaned script ships with the next agent script bump.

### English

#### Removed

- **UniFi agent mode.** Agents only support `native` mode now. The UniFi controller apply path (login, VPN client, firewall rules), the `UNIFI_*` variables in `config.env` and the `unifi_url`, `unifi_user`, `unifi_pass` and `unifi_site` API fields are gone. The migration switches any `unifi` agent to `native` and drops the four columns, including any stored controller credentials.
- **UniFi detection in service discovery.** Ports 8080 and 8443 are now labelled "Web UI" instead of "UniFi Network".

### Deutsch

#### Entfernt

- **UniFi-Agent-Modus.** Agents unterstützen nur noch den Modus `native`. Der UniFi-Controller-Pfad (Login, VPN-Client, Firewall-Regeln), die `UNIFI_*`-Variablen in `config.env` und die API-Felder `unifi_url`, `unifi_user`, `unifi_pass` und `unifi_site` sind entfernt. Die Migration stellt etwaige `unifi`-Agents auf `native` um und löscht die vier Spalten samt gespeicherter Controller-Zugangsdaten.
- **UniFi-Erkennung im Service-Scan.** Die Ports 8080 und 8443 heißen jetzt "Web UI" statt "UniFi Network".

## [2.2.1] - 2026-10-02

Company-account sign-in (OpenID Connect) with in-app SSO settings, plus the fixes from a two-pass multi-agent audit (find, adversarially verify, fix: 43 confirmed findings, 36 fixed). Hub-side only: the agent script is unchanged, `AGENT_SCRIPT_VERSION` stays 1.3.23. Two migrations run on startup (traffic history indexes and BIGINT id).

### English

#### Added

- **Sign in with a company account (OpenID Connect).** The login page offers a second button next to the password form. Access is governed by a single group in the directory: whoever is a member may sign in and is an administrator, and the account is created on first sign-in. Accounts created this way have no password and can therefore only sign in through the provider. A locally configured second factor is not requested in addition - the provider owns authentication.
- **SSO settings in the app.** Settings > Sign-in (SSO) configures issuer, client, redirect URI, authorized group, groups claim, scopes, session lifetime and button label, with a provider connection test and a live button preview. Admin only; the client secret is never sent back to the browser, an empty field keeps it, and changes are audit-logged and take effect without a restart.
- **Account source in the user list.** A new column shows whether an account is local or SSO. SSO accounts are marked on every SSO login (auth type `oidc`, without a secret); password and 2FA checks only read `password` records.
- **Default SSO button label** is now "Mit Firmenkonto anmelden".

#### Fixed

- **Corrected the declared type of a token's expiry.** `TokenResponse.expires` is an ISO timestamp, not a number; the stored value was always read as text.
- **Login and WireGuard pages showed raw message IDs.** 50 translation keys (login form, 2FA, WireGuard create form, agent settings, routing matrix) existed only in the compiled locale files and were lost on recompilation; they now live in `locale/src`.
- **Traffic history on MySQL/MariaDB.** The history migration failed on its 67-character index name and was then marked as applied without indexes. Index names are now short, and a repair migration merges duplicate buckets and adds the missing indexes. Buckets are written with an atomic upsert.
- **Traffic history accuracy.** Recording starts at backend boot instead of on the first page visit; a database error no longer double-counts an interval; overlapping polls are skipped; traffic after a WireGuard counter reset is counted; daily buckets follow local midnight; the still-open bucket is averaged over the time elapsed so far.
- **Application updates.** A failed install, build or health check now rolls back to the previous commit (keeping local changes) and rebuilds it. A status stuck at "running" after a killed updater or reboot is detected and turned into "failed". Concurrent update requests no longer overwrite a running update's status.
- **WireGuard metadata save** re-reads metadata under the write lock before syncing agents, so a concurrent peer delete cannot be undone fleet-wide.
- **OIDC requests to the provider** time out after 10 seconds.
- **Row action menus were clipped** at the bottom of table cards. Menus now use a fixed Popper strategy, and table cards no longer use `backdrop-filter`, which had trapped the fixed menus inside the card.
- **Proxy host editor:** the scheme select lost its dropdown chevron and truncated "https". The chevron is back and the column is wider.

#### Security

- **SSO login is bound to the browser that started it.** `state` and the PKCE verifier live in an encrypted HttpOnly cookie instead of a global in-memory table (no login CSRF, no eviction of other users' pending logins). The token is collected once via `POST /api/oidc/exchange`; the login page no longer accepts a token or free error text from the URL.
- **SSO sessions end with the provider session.** Refreshing an SSO token never extends it past the original lifetime, so group removal at the provider takes effect. `GET /api/tokens` also refuses 2FA challenge tokens and disabled/deleted accounts.
- **Rate limits could be bypassed** via a spoofed `X-Forwarded-For` (`trust proxy` was effectively `true`); only loopback is trusted now. The 5-minute limiter's cleanup no longer wipes the 15-minute login/2FA/agent/SSO counters.
- **Agent registration:** non-string tokens (e.g. JSON numbers, which MySQL compares numerically against the hex token) are rejected before any lookup.
- **nginx directive injection:** custom location paths are validated (schema and render time). The `advanced_config` gate now tokenizes like nginx (quoted directive names, `#` inside a word) and also blocks `access_log`/`error_log` (except `access_log off`), temp/store paths and certificate/password/user files.
- **Startup DNS credential restore** no longer builds a shell command from user data.
- **`DEBUG=false` no longer enables debug mode**; stack traces are never sent to clients in production.
- The initial admin password is no longer written to the log; provider error codes are sanitized before logging.
- **Cloudflare DNS:** non-admins can no longer make the hub use the global or another user's Cloudflare token, and record IDs are no longer taken from client-supplied meta.
- **Certificates:** `POST /api/nginx/certificates/validate` requires authentication and uploads are size-limited. Route53 credentials are written without `credential_process`, so they cannot run commands as root.
- **ReDoS:** the domain/host patterns of redirection hosts no longer backtrack catastrophically.
- **Update rollback** also rolls back database migrations, so the restored version can start again.
- **Traffic history** uses a BIGINT id; removed or rotated peers are dropped from the live view; SSO session lifetime units `M`/`Q` are rejected.

### Deutsch

#### Hinzugefügt

- **Anmeldung mit dem Firmenkonto (OpenID Connect).** Die Anmeldeseite bietet neben dem Passwortformular einen zweiten Knopf. Wer hereinkommt, entscheidet eine einzige Gruppe im Verzeichnis: Wer darin ist, darf sich anmelden und ist Administrator, das Konto wird bei der ersten Anmeldung selbst angelegt. So angelegte Konten haben kein Passwort und können sich daher ausschließlich über den Anbieter anmelden. Eine lokal eingerichtete zweite Stufe wird nicht zusätzlich abgefragt - die Faktoren verwaltet der Anbieter.
- **SSO-Einstellungen in der App.** Einstellungen > Anmeldung (SSO) für Issuer, Client, Redirect-URI, berechtigte Gruppe, Gruppen-Claim, Scopes, Sitzungsdauer und Button-Text, mit Verbindungstest und Live-Vorschau des Buttons. Nur für Admins; das Client-Secret geht nie zurück an den Browser, ein leeres Feld behält es, Änderungen landen im Audit-Log und gelten ohne Neustart.
- **Herkunft in der Benutzerliste.** Eine neue Spalte zeigt, ob ein Konto lokal oder per SSO angelegt ist. SSO-Konten werden bei jeder SSO-Anmeldung markiert (Auth-Typ `oidc`, ohne Secret); Passwort- und 2FA-Prüfungen lesen nur `password`-Einträge.
- **Standard-Beschriftung des SSO-Buttons** ist jetzt „Mit Firmenkonto anmelden“.

#### Behoben

- **Typangabe der Token-Gültigkeit korrigiert.** `TokenResponse.expires` ist ein ISO-Zeitstempel und keine Zahl; gelesen wurde der Wert ohnehin immer als Text.
- **Anmelde- und WireGuard-Seite zeigten rohe Text-IDs.** 50 Übersetzungsschlüssel standen nur in den kompilierten Sprachdateien und gingen beim Neukompilieren verloren; sie liegen jetzt in `locale/src`.
- **Traffic-Historie unter MySQL/MariaDB.** Die Migration scheiterte am 67 Zeichen langen Indexnamen und galt danach ohne Indizes als erledigt. Die Namen sind jetzt kurz, eine Reparatur-Migration führt doppelte Buckets zusammen und legt fehlende Indizes an. Geschrieben wird per atomarem Upsert.
- **Genauigkeit der Traffic-Historie.** Aufzeichnung ab Backend-Start statt erst beim ersten Seitenaufruf; ein DB-Fehler zählt kein Intervall doppelt; überlappende Abfragen werden übersprungen; Traffic nach einem Zähler-Reset wird gezählt; Tageswerte beginnen um lokale Mitternacht; der offene Bucket wird über die bisher vergangene Zeit gemittelt.
- **Anwendungs-Updates.** Scheitern Installation, Build oder Health-Check, wird auf den vorherigen Commit zurückgerollt (lokale Änderungen bleiben) und neu gebaut. Ein nach Abbruch oder Neustart hängender Status „running“ wird erkannt und auf „failed“ gesetzt. Gleichzeitige Update-Anfragen überschreiben den Status eines laufenden Updates nicht mehr.
- **Speichern der WireGuard-Metadaten** liest vor dem Agent-Abgleich frisch unter der Schreibsperre, damit ein gleichzeitiges Löschen nicht flottenweit rückgängig gemacht wird.
- **OIDC-Anfragen an den Anbieter** brechen nach 10 Sekunden ab.
- **Aktionsmenüs in Tabellen wurden abgeschnitten.** Menüs nutzen jetzt eine feste Popper-Positionierung, und Tabellenkarten verwenden kein `backdrop-filter` mehr, das die Menüs in der Karte eingesperrt hat.
- **Proxy-Host-Editor:** Das Schema-Feld hatte keinen Dropdown-Pfeil und schnitt „https“ ab. Der Pfeil ist zurück, die Spalte ist breiter.

#### Sicherheit

- **SSO-Anmeldung ist an den startenden Browser gebunden.** `state` und PKCE-Prüfwert liegen verschlüsselt in einem HttpOnly-Cookie statt in einer globalen Tabelle (kein Login-CSRF, kein Verdrängen fremder Anmeldungen). Das Token wird einmalig per `POST /api/oidc/exchange` abgeholt; Token oder freier Fehlertext aus der URL werden nicht mehr übernommen.
- **SSO-Sitzungen enden mit der Anbieter-Sitzung.** Verlängerungen reichen nie über die ursprüngliche Laufzeit hinaus; das Entfernen aus der Gruppe wirkt damit. `GET /api/tokens` lehnt außerdem 2FA-Challenge-Tokens sowie deaktivierte/gelöschte Konten ab.
- **Rate-Limits waren umgehbar** über ein gefälschtes `X-Forwarded-For` (`trust proxy` war faktisch `true`); vertraut wird nur noch Loopback. Das Aufräumen des 5-Minuten-Limiters löscht nicht mehr die 15-Minuten-Zähler für Login/2FA/Agent/SSO.
- **Agent-Registrierung:** Tokens, die keine Zeichenkette sind (z. B. JSON-Zahlen, die MySQL numerisch mit dem Hex-Token vergleicht), werden vor jeder Abfrage abgewiesen.
- **nginx-Direktiven-Injektion:** Pfade eigener Locations werden geprüft (Schema und beim Rendern). Die `advanced_config`-Prüfung zerlegt jetzt wie nginx (Direktivnamen in Anführungszeichen, `#` im Wort) und sperrt zusätzlich `access_log`/`error_log` (außer `access_log off`), Temp-/Store-Pfade sowie Zertifikats-, Passwort- und Benutzerdateien.
- **Wiederherstellen der DNS-Zugangsdaten beim Start** baut keinen Shell-Befehl mehr aus Benutzerdaten.
- **`DEBUG=false` schaltet den Debug-Modus nicht mehr ein**; Stacktraces gehen in Produktion nie an Clients.
- Das initiale Admin-Passwort wird nicht mehr protokolliert; Fehlercodes des Anbieters werden vor dem Loggen bereinigt.
- **Cloudflare-DNS:** Nicht-Admins können den Hub nicht mehr mit dem globalen oder einem fremden Cloudflare-Token arbeiten lassen; Record-IDs kommen nicht mehr aus Client-Daten.
- **Zertifikate:** `POST /api/nginx/certificates/validate` erfordert eine Anmeldung, Uploads sind größenbegrenzt. Route53-Zugangsdaten werden ohne `credential_process` geschrieben und können keine Befehle als root ausführen.
- **ReDoS:** Die Domain-/Host-Muster von Weiterleitungen backtracken nicht mehr katastrophal.
- **Update-Rollback** setzt auch Datenbank-Migrationen zurück, damit die wiederhergestellte Version wieder startet.
- **Traffic-Historie** nutzt eine BIGINT-ID; entfernte oder rotierte Peers verschwinden aus der Live-Ansicht; Einheiten `M`/`Q` für die SSO-Sitzungsdauer werden abgelehnt.

## [2.0.1] - 2026-08-23

### Added

- **Persistent WireGuard traffic history.** The Traffic page now offers live, 24-hour, 30-day, and 12-month ranges. Per-peer traffic is stored in minute, 15-minute, and daily buckets with automatic retention.

### Deutsch

- **Persistente WireGuard-Traffic-Historie.** Die Traffic-Seite bietet nun Live-, 24-Stunden-, 30-Tage- und 12-Monats-Ansichten. Der Traffic je Peer wird in Minuten-, 15-Minuten- und Tageswerten mit automatischer Aufbewahrung gespeichert.

## [2.0.0] - 2026-08-23

### English

#### Added

- **Controlled in-app updates for administrators.** The dashboard announces new releases, and an administrator can start the update under Settings after explicit confirmation. A separate systemd job fetches only the approved Git upstream and checked-out branch, installs the locked dependencies, builds the frontend, restarts the backend, and reports progress or errors in the app.

#### Security

- **Hardened the update path against unintended code and data loss.** The start and status endpoints are admin-only and recorded in the audit log. The script accepts only the approved Git remote, uses fast-forward merges only, and never resets over local changes.

#### Changed

- **Updated the toolchain to Node 22.22.2+, npm 12.0.2, and Yarn 1.22.22.** The installer and the manual installation instructions use the same versions and reproducibly install both committed lockfiles.
- **Updated dependencies and lockfiles.** Runtime and build dependencies now use the current compatible major versions; the production check no longer reports npm audit findings.
- **Migrated the Archiver integration to version 8.** Certificate archives use the new `ZipArchive` API.
- **Refined the Proxy Host editor.** The expandable Advanced section in the SSL tab now has clear spacing from the SSL toggles. The Custom Nginx Configuration opens without an additional vertical offset.
- **Improved Nginx configuration editing.** The editor reliably displays input, numbers lines, and can be focused through its label. The Proxy Host help now documents the Advanced tab in German and English.
- **Made the footer version immediately current.** The health cache is versioned and refreshed on page load, so the app no longer shows a stale backend version for up to 15 minutes.
- **Added Cloudflare DNS synchronisation for Proxy Hosts.** The Advanced tab can create targeted A/AAAA records and update them on changes, including Cloudflare proxy mode. Tokens come from the matching Cloudflare DNS certificate or optionally `CLOUDFLARE_API_TOKEN`; the README and built-in help explain the domain-specific token assignment. Wildcard and manually managed records are not overwritten.

### Deutsch

#### Hinzugefügt

- **Kontrolliertes In-App-Update für Administratoren.** Das Dashboard weist auf neue Releases hin; unter Einstellungen kann ein Administrator das Update nach expliziter Bestätigung starten. Ein separater systemd-Job lädt ausschließlich den freigegebenen Git-Upstream und den ausgecheckten Branch, installiert die festgeschriebenen Abhängigkeiten, baut das Frontend, startet das Backend neu und zeigt Fortschritt bzw. Fehler in der App an.

#### Sicherheit

- **Updatepfad gegen unbeabsichtigten Code- und Datenverlust gehärtet.** Der Start- und Status-Endpunkt ist Admin-only und wird im Audit-Log festgehalten. Das Skript akzeptiert nur den freigegebenen Git-Remote, nutzt nur Fast-Forward-Merges und macht niemals einen Reset über lokale Änderungen.

#### Geändert

- **Toolchain auf Node 22.22.2+, npm 12.0.2 und Yarn 1.22.22 angehoben.** Installer und manuelle Installationsanleitung richten dieselben Versionen ein und installieren die beiden committed Lockfiles reproduzierbar.
- **Abhängigkeiten und Lockfiles aktualisiert.** Die Laufzeit- und Build-Abhängigkeiten wurden auf die aktuellen kompatiblen Hauptversionen aktualisiert; die Produktionsprüfung meldet keine npm-Audit-Funde mehr.
- **Archiver-Integration für Version 8 migriert.** Zertifikats-Archive verwenden die neue `ZipArchive`-API.

- **Proxy-Host-Editor überarbeitet.** Der aufklappbare Advanced-Bereich im SSL-Tab hat nun einen klaren Abstand zu den SSL-Schaltern. Die Custom-Nginx-Konfiguration öffnet ohne zusätzlichen vertikalen Versatz.
- **Nginx-Konfiguration komfortabler editieren.** Der Editor zeigt Eingaben zuverlässig an, nummeriert Zeilen und lässt sich über seine Beschriftung fokussieren. Die Hilfe für Proxy Hosts dokumentiert den Advanced-Tab jetzt auf Deutsch und Englisch.
- **Fußzeilen-Version sofort aktuell.** Der Health-Cache ist versioniert und wird beim Laden einer Seite aktualisiert, damit die App nicht mehr bis zu 15 Minuten lang eine alte Backend-Version anzeigt.
- **Cloudflare-DNS-Synchronisierung für Proxy Hosts.** Der Advanced-Tab kann gezielte A-/AAAA-Records erstellen und bei Änderungen aktualisieren, inklusive Cloudflare-Proxy-Modus. Tokens stammen aus dem passenden Cloudflare-DNS-Zertifikat oder optional aus `CLOUDFLARE_API_TOKEN`; README und integrierte Hilfe erklären die domaingenaue Token-Zuordnung. Wildcard- und manuell verwaltete Records werden nicht überschrieben.

---

## [1.3.26] - 2026-07-11

Security-Release aus einem mehrstufigen Multi-Agent-Audit (find -> adversariale Verifikation -> Fix). FloppyGuard verwaltet live-VPN-Tunnel und lädt generierte nginx-Configs als root - der Fokus lag entsprechend auf Injection in root-ausgeführte Configs. Sieben bestätigte Findings behoben, alle rein hub-seitig (kein Agent-Skript-Change, `AGENT_SCRIPT_VERSION` bleibt 1.3.23). Health-Stack grün (Backend 119/119, Frontend 23/23, tsc + beide Biome-Lints sauber, Schema valide).

### Security

- **nginx-Directive-Injection über `advanced_config` (HIGH).** Der frei editierbare `advanced_config` von Proxy-/Redirection-/Dead-Hosts wurde ungeprüft in die root-geladene nginx-Config gerendert. `alias`/`root`/`include`/`ssl_certificate*` = beliebiger Dateizugriff bzw. TLS-Key-Diebstahl, `*_by_lua*`/`perl` = RCE (die Images sind OpenResty). Neues `assertSafeAdvancedConfig()`-Allowlist-Gate am zentralen Render-Choke-Point blockt die gefährlichen Direktiven vor dem Rendern.
- **nginx-Breakout über per-Location `forward_host`/`forward_path` (HIGH).** Beide Felder wurden unquoted in `proxy_pass …;` gerendert; ein Newline + Direktiven brach aus. Strikte Schema-Patterns (create **und** update via `$ref`) plus `assertSafeForwardField()`-Gate am Render-Sink.
- **nginx-Injection über `default-site` `meta.redirect` (HIGH).** Nur `meta.html` war geguarded; `meta.redirect` floss verbatim in `return 301 …;`. Schema-Pattern + `assertSafeRedirect()` (nur plain http(s)-URL) in `internalSetting.update`.
- **nginx-Injection über Redirection-`forward_domain_name` (CRITICAL).** Das Schema-Domain-Pattern `^(?:[^.*]+\.?)+[^.]$` ließ interne Newlines durch (`[^.*]` matcht `\n`) -> Direktiven-Injection in die http-Server-Config, an `assertSafeAdvancedConfig` vorbei. Render-Gate in `generateConfig` + gehärtetes Pattern (`\s` ausgeschlossen).
- **nginx-Injection über Stream-`forwarding_host` (CRITICAL).** Analog, unquoted in `proxy_pass …;` der root-geladenen Stream-Config. Gleiches Render-Gate + Pattern-Härtung.
- **Stacktrace-Leak an unauthentifizierte Clients (MEDIUM).** Der globale Error-Handler gab Stacks + `err.previous` preis, sobald der (angreiferkontrollierte) Pfad den Substring `nginx/certificates` enthielt. Jetzt strikt auf `isDebugMode()` reduziert.
- **Mass-Assignment im Permissions-Endpoint (LOW).** `PUT /users/:id/permissions` validierte gegen ein Schema ohne `additionalProperties:false` -> beliebige `user_permission`-Spalten (u. a. `user_id`) landeten im DB-Patch/Insert. Schema abgedichtet.

---

## [1.3.25] - 2026-06-30

Behebt eine MASQUERADE-Fehlklasse in den hub-generierten Agent-PostUp/PostDown-Regeln: durch den literalen `%i` maskierten Standort-Gateways VPN-Verkehr auch dort, wo er nicht hingehört (u. a. Tunnel<->Tunnel). Zusätzlich neues, **standardmäßig ausgeschaltetes** Per-Agent-Flag, mit dem ein Site-Gateway die echte Client-IP ins lokale LAN durchreicht (damit am Standort Hinderlich VPN-Rechner im AD mit ihrer echten IP statt der Gateway-IP `192.168.210.7` erscheinen). Reiner Hub-seitiger Fix - das Agent-Skript (`buildLoopScript`) ist unverändert, `AGENT_SCRIPT_VERSION` bleibt auf 1.3.23; die neuen Regeln fließen über `config_text`/`config_hash` und werden beim normalen ~30-s-Poll übernommen. Health-Stack grün (Backend 111/111, Frontend tsc + Lints sauber, WireGuard-UI-Tests 11/11).

### Fixed

- **Literales `%i` aus den iptables-Regeln entfernt.** `buildHubPostUp`/`buildHubPostDown` schrieben den wg-quick-Platzhalter `%i` in die Regeln. Der Agent eval't diese aber auf dem Config-Update-Pfad in einer normalen Shell (nicht über wg-quick), wo `%i` literal bleibt -> `! -o %i` matcht jedes Paket -> **alles** wird maskiert, auch Tunnel<->Tunnel. Der echte Interface-Name (`agent.wg_interface`, validiert `^wg\d+$`) wird jetzt **pro Agent** eingebacken. Damit ist die Regel auch auf Gateways mit **mehreren** WG-Netzen (wg0 + wg1) korrekt - jedes Interface bekommt seine eigene gebackene Regel, keine geteilte/Blanket-Regel.

### Added

- **Neues Per-Agent-Flag `preserve_lan_source_ip` (Default AUS, opt-in).** Ist es an einem Site-Gateway AN, behält **nur Client-/Road-Warrior-Verkehr** (Quelle = Tunnel-Subnetz) die echte IP ins lokale LAN - per `-s <tunnel> -d <lokales-LAN> -j RETURN` vor dem MASQUERADE. **Site-to-Site bleibt bewusst maskiert.** Damit sieht z. B. der AD-Server die echte Client-IP statt der Gateway-IP. Gegated auf echte Site-Links (`type !== "client"`) - die `importedNetworks` eines Road-Warrior-Links sind eine *Reach-Liste*, kein lokales LAN. Setzt eine Rückroute ins Tunnel-Subnetz voraus; pro Gateway über UI-Toggle (de/en/fr) + API schaltbar. Migration backfillt bestehende Agents auf AUS -> der Rollout ändert **kein** LAN-Verhalten (nur der `%i`-Fix greift), die echten IPs schaltet man pro Standort bewusst frei.

## [1.3.24] - 2026-06-20

Schließt die wiederkehrende „Tunnel nach Reboot tot"-Fehlerklasse strukturell: Der WireGuard-Endpoint in Agent-Configs wird jetzt vom Hub propagiert, statt einmalig beim Install eingebacken zu bleiben. Entwickelt mit anschließendem Multi-Agent-Audit (Finden -> adversariale Verifikation -> Fix, vier Durchläufe). Health-Stack grün (Backend 106/106, Frontend tsc + beide Lints sauber). Reiner Hub-seitiger Fix - `AGENT_SCRIPT_VERSION` bewusst auf 1.3.23 gelassen (das Agent-Skript ist unverändert, kein Flotten-Restart nötig; Agents ziehen die neue `config_text` beim normalen Poll).

### Fixed

- **WG-Endpoint propagiert jetzt an bestehende Agents (Hub ist autoritativ).** Bisher setzte nur die Erst-Generierung den `[Peer] Endpoint` aus `WG_HUB_HOST`; `syncAgentConfigs` schrieb ausschließlich die `AllowedIPs` um. Ein Hub-Domain-Wechsel (z. B. `floppyguard.comnic.de` -> `hub.comnic.de` -> `proxy.comnic.de`) erreichte deshalb keine bereits installierte Agent-Config - die veraltete, dual-stack-aufgelöste Domain blieb eingebacken und führte nach jedem Reboot zum Blackhole, wenn der Standort kein funktionierendes IPv6 hat (3× live aufgetreten: PVE, Floppy Home, Daniel Home). `_syncOneAgent` schreibt die Endpoint-Zeile jetzt bei jedem Sync aus `WG_HUB_HOST` neu, sodass die Änderung beim nächsten ~30-s-Poll die ganze Flotte erreicht.

### Robustness

- **Endpoint-Rewrite ist konservativ und gezielt.** Nur der **erste** `[Peer]` (= Hub-Peer) wird angefasst - ein port-loser/fehlender Hub-Endpoint kann keinen späteren Peer in Multi-Peer-Configs überschreiben. **IP-Literale bleiben unberührt** (eine bewusst gepinnte robuste IPv4/IPv6 wird nie auf einen Dual-Stack-Namen herabgestuft - genau die AAAA-Blackhole-Ursache), außer bei einer echten IP->IP-Hub-Migration. Der Hostvergleich ist case-insensitiv, ein Trailing-Inline-Comment und Whitespace ums `:` werden toleriert, und eine gleichbleibende Host-Zeile wird byte-identisch belassen (kein unnötiger Flotten-`wg0`-Bounce).
- **`WG_HUB_HOST` wird vor dem Einbacken gesäubert.** `resolveHubHost()`/`configuredHubHost()` trimmen, lehnen Whitespace/Newline/Shell-Metazeichen ab (kein Fleet-weites Einschleusen über eine fehlkonfigurierte Env-Variable) und bracket-wrappen eine bare IPv6. Ist `WG_HUB_HOST` ungesetzt/ungültig, bleibt der eingebackene Endpoint unangetastet statt mit dem OS-Hostnamen-Fallback überschrieben zu werden.
- **Reconciler-Log unterscheidet** erwartete Endpoint-Propagation von echtem Konfig-Drift, damit ein Domain-Wechsel den „missed trigger"-Alarm nicht übertönt.
- 14 neue Regressionstests (`_rewriteHubPeerEndpoint`, `resolveHubHost`/`configuredHubHost`).

## [1.3.23] - 2026-06-13

Konsolidiertes Tagesrelease. Bündelt den großen Sicherheits- und Stabilitäts-Audit-Batch (siehe 1.3.22) mit einem Betriebs-Fix für die Log-Rotation. Health-Stack vollständig grün, in Produktion deployt und verifiziert (Live-API meldet die neue Version, Logrotate ohne Warnung).

### Fixed

- **Log-Rotation funktioniert wieder** - das Backend rief alle 2 Tage `logrotate /etc/logrotate.d/floppyguard` auf, aber die Datei wurde nie angelegt: Bei jedem Tick eine `cannot stat`-Warnung, und die Per-Host-nginx-Logs unter `/data/logs` wuchsen ungebremst (Fallback-Logs ~270 MB). Die Konfig liegt jetzt als Repo-Asset (`backend/config/logrotate.d/floppyguard`) bei, und `ensureLogrotateConfig()` installiert sie beim Start nach `/etc/logrotate.d/`, falls sie fehlt - ein frischer Deploy heilt sich selbst.

### Enthält (aus 1.3.22, gleicher Tag)

Das komplette Multi-Agent-Audit der App (Finden -> adversariale Verifikation -> Fix, drei Durchläufe): Privilege Escalation über `PUT /api/users/me`, zwei Root-RCE-Pfade derselben Newline-Injection-Klasse (`createInterface` address, `createPeer` peer name), config.env-Injection über Agent-Felder, SSRF-Eindämmung, DoS-Fix bei Key-Upload, `setting.js`-Crash, sowie die Zertifikats-Renewal-Bricking, WireGuard-Conf-Races/Locking, atomare Metadaten-Writes, Subnetz-Mathematik, Key-Rotation-Cache, Hub-Routen für Site-Peers, idempotente Agent-Registrierung, getrennte Rate-Limiter, speicherbare Hub-URL-Propagation, sqlite-portable Migration und reparierte Frontend<->Backend-Payload-Verträge. Vollständige Details unten unter 1.3.22.

## [1.3.22] - 2026-06-13

Sicherheits- und Stabilitäts-Release aus einem strukturierten Multi-Agent-Audit der gesamten App (Finden -> adversariale Verifikation -> Fix, drei Durchläufe). Behebt zwei kritische Privilege-Escalation-/Datenverlust-Fehler, zwei weitere Root-RCE-Pfade derselben Newline-Injection-Klasse wie v1.3.21, sowie eine Reihe von WireGuard-Races, Agent-Robustheitsproblemen und kaputten Frontend<->Backend-Verträgen. Health-Stack vollständig grün (Backend 87/87, Frontend 23/23, tsc + beide Lints sauber).

### Security

- **Privilege Escalation über `PUT /api/users/me` geschlossen** - ein normaler Benutzer konnte sich mit `{"roles":["admin"]}` selbst zum Admin machen (das Schema erlaubte `roles`, `update()` patchte es ungefiltert). Self-Updates dürfen `roles` jetzt nur noch ändern, wenn der Requester laut DB selbst Admin ist.
- **Root-RCE in `createInterface` geschlossen** - das `address`-Feld lief nur durch `String.trim()` und floss per Newline-Injection als `PostUp = <cmd>` in die wg-quick-Conf (root). Neuer strenger `isValidInterfaceAddress`-Validator (anchored IPv4/IPv6 + Prefix, lehnt Whitespace/Newline ab).
- **Root-RCE über Peer-Namen geschlossen** - derselbe Sink in `createPeer`: ein Peer-Name mit Newline schmuggelte eine `[Interface]`/`PostUp`-Sektion in `wg0.conf`. Namen laufen jetzt durch `stripLinkNameControlChars`.
- **Config.env-Injection über Agent-Felder geschlossen** - `mode`/`wg_interface` waren unvalidiert und landeten in der als root ge-`source`ten `config.env`. Neue Whitelists (`sanitizeAgentMode`, `sanitizeWgInterface`), auch am Sink in `getInstallScript` erneut erzwungen.
- **SSRF vom Hub eingedämmt** - agent-kontrollierte `hostname`/`lan_ip` aus dem Heartbeat trieben serverseitige Portscans + `curl`. Ziele sind jetzt auf RFC1918-Adressen beschränkt; `hostname`/`agent_version` werden längen-geklammert.
- **Remote-DoS bei Key-Upload behoben** - `checkPrivateKey()` warf aus einem `setTimeout`-Callback (unfangbar -> Prozess-Crash) beim Upload eines passwortgeschützten Private Keys.
- **Backend-Crash in `setting.js` behoben** - fehlendes `return` im Default-Site-Fehlerpfad führte zu einer unhandled Rejection (Prozess-Absturz) bei gleichzeitigem HTTP 200.

### Fixed

- **Zertifikats-Erneuerung bricked nginx nicht mehr** - die stündliche Auto-Renewal löschte gültige Zertifikate VOR dem certbot-Lauf; schlug certbot fehl (LE-Ausfall, Rate-Limit), war das Zertifikat weg und `nginx -t` scheiterte fleetweit. Löschung erfolgt jetzt erst nach erfolgreicher Erneuerung; Renewal lädt nginx neu.
- **WireGuard-Conf-Races serialisiert** - alle `<iface>.conf`-Read-Modify-Writes (`deletePeer`, `generatePeerConfig`, `syncHubConf`) laufen jetzt unter `withWriteLock`; `syncAgentConfigs` läuft im Lock mit frischen Metadaten (kein Last-Write-Wins mehr).
- **Atomare Metadaten-Writes** - Store wird via tmp+rename geschrieben; Lesefehler liefern keinen leeren Store mehr, der echte Daten überschreibt.
- **Korrekte Subnetz-Mathematik** - Tunnel-IP-Allokation respektiert die echte Prefix-Länge statt hartem /24.
- **Key-Rotation-Cache** - Download/QR rotieren den Peer-Key nicht mehr gegenseitig kaputt; Cache wird bei Edit/Delete invalidiert.
- **Hub-Routen für Site-Peers** - neue Site-Netzwerke bekommen live Kernel-Routen + persistente PostUp-Zeilen (überleben Reboot).
- **Eindeutige Link-Namen erzwungen** - Duplikat-Namen froren vorher den Agent-Sync ein.
- **Agent-Registrierung ist idempotent** - geht die HTTP-Antwort verloren, bricked der Agent nicht mehr; der `reg_token` wird erst nach nachgewiesenem Empfang zurückgezogen.
- **Rate-Limiter pro Bucket getrennt** - Login- und Agent-Limiter teilten einen per-IP-Zähler und sperrten sich gegenseitig aus (NAT).
- **Hub-URL-Propagation speicherbar** - das Settings-PUT-Schema lehnte das `agent-hub-url`-Payload ab (Feature aus v1.3.15/16 war ein No-op); jetzt conditional auf die Setting-ID validiert, ohne `default-site` zu lockern.
- **Migration läuft auf sqlite** - `agent_allowed_sites` nutzte MySQL-only `SHOW COLUMNS` und brach lokale Dev-DBs; jetzt portables `hasColumn`.
- **Frontend<->Backend-Verträge repariert** - Create-Peer/Restore-Metadata/Create-Interface sendeten snake_case bzw. falsche Keys, die das Backend (camelCase) still verwarf (`fullTunnel`, `importedNetworks`, `ifaceName`, `backupPath`, Listen-Port).
- **Client-Reach-List löst keinen falschen „AllowedIPs conflict" mehr aus** - Road-Warrior-Clients, die ein bestehendes Site-Netz erreichen, lassen sich wieder anlegen/bearbeiten.
- **Audit-Log-Suche** - fehlendes abschließendes `%` im LIKE-Muster matchte nur Einträge, die mit der Query endeten.

## [1.3.21] - 2026-06-07

Großes Härtungs-Release der gesamten Hub->Agent-WireGuard-Sync-Struktur (zwei vollständige Audit-Runden + Re-Audit an einem Tag, konsolidiert). Behebt eine ganze Familie von Fällen, in denen eine hub-seitige Änderung - vor allem REMOVE/DELETE/RENAME - nicht zuverlässig am Remote-Agent ankam, plus eine kritische RCE.

### Security

- **Root-Command-Injection im Install-Skript geschlossen** - `getInstallScript` validierte `public_url`/`tunnel_url` schwächer als `sanitizeHubUrl` und liess `"`/Whitespace durch; die URLs landen in der als **root** ge-`source`ten `config.env`. `https://a/x" <cmd>"` führte `<cmd>` als root aus (auch über den JWT-losen `/agent/install`). Beide Felder laufen jetzt durch `sanitizeHubUrl`.
- **UniFi-Credentials validiert** - `unifi_url/user/pass/site` mit Quotes/Newline/`$`/Backtick werden abgelehnt (config.env-Injection-Schutz).

### Changed

- **Netz-Entfernen propagiert jetzt zuverlässig** - der Hub ist autoritativ für die Hub-Peer-AllowedIPs (`_computeHubPeerAllowedIPs`); Client-Reichweiten-Listen verschmutzen die Site-Netz-Menge nicht mehr (`_collectSiteNetworks` schliesst `type:"client"` aus); leeres `importedNetworks` droppt das Subnetz autoritativ (hub- und agent-seitig).
- **Site-Netze strikt IPv4 + kanonisch** - `importedNetworks`/`exportedNetworks`/`allowed_networks` werden auf die Netzadresse maskiert (Host-Bits weg) und IPv6-CIDRs abgelehnt. IPv6-Routing in lokale LANs ist out-of-scope; die Hub/App-Erreichbarkeit über IPv6 ist davon unberührt (Proxy/Endpoint, kein geroutetes Site-Netz).
- **Hintergrund-Timer** (Service-Scan + Config-Reconciler) starten explizit über `internalAgent.startBackgroundTasks()` (Server-Entrypoint), nicht beim Import -> Testsuite läuft deterministisch ohne `--test-force-exit`.

### Fixed

- **deletePeer / deleteInterface / Link-Rename / createPeer / `wg_link_name`-Rebind triggern jetzt einen Agent-Resync** - vorher blieben gelöschte/umgezogene Site-Netze auf allen anderen Agents stehen (AllowedIPs + Route + MASQUERADE) bzw. neue Netze erreichten sie erst nach Minuten. Rename cascadet `wg_link_name`/`allowed_sites` (exakt-case) und lehnt Namens-Kollisionen ab.
- **Periodischer Reconciler (5 Min)** als Defense-in-Depth - heilt jeden künftig vergessenen Resync-Trigger; läuft unter demselben `withWriteLock` wie alle Metadaten-Store-Mutationen -> kein Lost-Write/Resurrect eines gelöschten Links mehr.
- **Per-Agent-Fehlerisolierung** - ein vergifteter Link (z.B. eine CIDR, die `assertCIDR` wirft) bricht den Fleet-Sync nicht mehr ab; alle übrigen Agents werden trotzdem reconciled.
- **Agent räumt MASQUERADE/FORWARD wieder korrekt ab** - `%i` wird vor dem `eval` durch `$iface` ersetzt (schlug vorher still fehl, MASQUERADE entfernter Netze blieb hängen); `sync_routes` nutzt echten CIDR-Overlap-Test (kein LAN-Hijack durch überlappende Remote-Subnetze).
- **Hub-seitiger Stale-Route-Prune** (`syncHubConf`) räumt Routen entfernter Netze ab - auch ohne Peer-Delta und in `deletePeer` (sonst Reboot-Blackhole).
- **`allowed_networks`-ACL** wird mit den real exportierten Netzen geschnitten (verwaiste/host-bits-Einträge blackholen nicht mehr).
- **`wg syncconf`-Fallback + Force-set repariert** - Whitespace-Toleranz im Strip-Fallback; der Force-set nimmt jetzt alle CIDRs (statt nur der ersten) und matcht einen literalen `[Peer]`-Header.
- **Upload-Config-Reinfektion** verhindert - ein Agent ohne `wg_link_name` kann keine längst entfernten Site-Netze mehr re-injizieren.
- **UniFi-Apply** prunt verwaiste `FG-WG-*`-Firewall-Regeln und deaktiviert den VPN-Client bei leeren `allowed_ips`.
- **Heartbeat** speichert die genutzte Hub-URL (`last_server_url`, neue Spalte) für Sichtbarkeit beim Domain/Endpoint-Move.

`AGENT_SCRIPT_VERSION` -> 1.3.21. 78 Backend-Tests (umfangreiche Regressionstests ergänzt). Offen (Backlog, latent): vollständige UniFi-Delete-Teardown-Orchestrierung (0 UniFi-Agenten produktiv), volles IPv6-Site-Routing (bewusst out-of-scope).

---

## [1.3.16] - 2026-06-02

### Changed

- **Zentrale Hub-URL-Einstellung statt pro Agent** - Der in v1.3.15 eingefuehrte Hub-URL-Editor (Primary + Fallback) lag im Panel jedes einzelnen Agents, obwohl `agent-hub-url` ein globales Setting ist - er erschien dadurch redundant einmal pro Agent und legte faelschlich nahe, die URL liesse sich je Agent unterschiedlich setzen. Der Editor ist jetzt ein einziges Steuerelement oben im WireGuard-Tab „Overview". Verhalten unveraendert: Er schreibt dasselbe `agent-hub-url`-Setting, das alle Agents beim naechsten Poll erreichbarkeitsgeprueft uebernehmen. Reine UI-Umstellung - das Agent-Loop-Skript ist unveraendert (`AGENT_SCRIPT_VERSION` bleibt 1.3.15, kein Flotten-Restart).

---

## [1.3.15] - 2026-06-02

### Added

- **Hub-URL-Propagation** - Die Hub-Adresse (Primary + Fallback) lebte bisher nur einmalig pro Agent in `/etc/floppyguard-agent/config.env`, eingebrannt beim Install aus der Browser-Origin des Admins. Ein Domain-Wechsel erreichte keinen laufenden Agent. Jetzt liefert `GET /api/agent/config` die URLs aus dem neuen Setting `agent-hub-url` mit; der Agent-Loop uebernimmt sie in seine `config.env` (analog zur Token-Rotation), aber erst nachdem er die neue URL als erreichbar verifiziert hat (`reach`) - so brickt ein Typo keinen Agent. Editierbar in der Web-UI (Agent-Panel, „Hub (global)").
- **Agent-Netzwerk-ACL in der UI** - `allowed_networks` (welche Remote-Subnetze ein Agent ueber den Hub routen darf) ist jetzt pro Agent im WireGuard-Tab editierbar. Aenderungen loesen automatisch `syncAgentConfigs` aus, der Agent zieht die neue `config_text` beim naechsten Poll (~30 s).

### Fixed

- **Register-Retry im Agent-Loop** - Schlug die einmalige Install-Registrierung fehl, blieb der Agent fuer immer stumm (`FGTOKEN` blieb der `reg_token`, `/config` lehnte ab, kein erneuter `/register`-Versuch). Der Loop versucht jetzt die Registrierung erneut, wenn der Hub erreichbar ist aber `/config` ablehnt - gedrosselt auf max. 1×/5 min, damit das geteilte IP-Rate-Limit von `/register` nicht ausgereizt wird.
- **`config.env`-Upsert** - Fehlt einem aelteren Agent die `PRIMARY_URL=`/`FALLBACK_URL=`-Zeile, wird sie jetzt angehaengt statt vom `sed` still uebergangen.
- **Latenter `logger`-Bug** - `uploadConfig` referenzierte ein nicht importiertes `logger`-Objekt (haette beim ersten Aufruf geworfen); Logger wird jetzt korrekt importiert.

### Security

- **ACL-Netzwerke werden am Eingang strikt CIDR-validiert** - `allowed_networks` flossen ungeprueft in `syncAgentConfigs` -> `ip route add <net> dev wgN` (als root auf dem Agent). `update()` validiert jetzt jeden Eintrag streng (Oktett ≤255, Prefix ≤32) und lehnt jedes `/0` ab (`0.0.0.0/0` und Aliase wie `0.0.0.0/00` haetten die Default-Route des Agents gekapert). Ein leeres Array wird als „keine Einschraenkung" (null) gespeichert, nie als `"[]"`. Konsistent mit `[[project_wg_network_validation]]`.
- **Hub-URL-Validierung** - `sanitizeHubUrl` erzwingt http(s) und verwirft sed-/Shell-Metazeichen, bevor eine URL an Agents propagiert und dort via `sed`/`curl` als root verwendet wird. Die UI sperrt das Speichern ungueltiger URLs.

---

## [1.3.14] - 2026-05-31

### Security

- **Command-Injection in WireGuard-Netzwerkfeldern geschlossen** - `importedNetworks`, `exportedNetworks` und `routeTargets` wurden bisher nur als Strings getrimmt/dedupliziert, aber nicht als CIDR validiert. Diese Werte fliessen in `ip route add <net> dev wgN`-Befehle, die als `PostUp`/`PostDown` in die wg-quick-Config geschrieben und als root ausgefuehrt werden. Ein Wert wie `10.0.0.0/24; <befehl>` haette beim Anwenden der Config beliebigen Code als root ausgefuehrt. Alle Netzwerkfelder werden jetzt am Eingang (`createPeer`, `updatePeer`, Metadata-Sanitizer) und an der Sink-Seite (`syncHubConf`) strikt als IPv4/IPv6-Adresse oder -CIDR validiert; alles andere wird verworfen. Neuer Regressionstest in `wireguard.test.js`.
- **Rate-Limit auf `GET /api/agent/install`** - Der Endpoint akzeptierte ein `reg_token` ohne Rate-Limit, waehrend das gleichwertige `POST /api/agent/register` bereits limitiert war. Jetzt gilt fuer beide dasselbe Limit (10 Requests / 15 min).

---

## [1.3.13] - 2026-05-31

### Fixed

- **Road-Warrior-Peers erhalten jetzt alle exportierten Netze** - Laptop-/Mobile-Peers erben automatisch alle `exportedNetworks` der anderen Peers in den AllowedIPs, statt nur das Tunnel-Subnet zu bekommen.
- **Endpoint nutzt die konfigurierte Domain** - Peer- und Agent-Configs verwenden `WG_HUB_HOST` statt eines Platzhalters; neue `resolveHubHost()` mit OS-Hostname-Fallback. `install.sh` schreibt `WG_HUB_HOST` aus der beim Setup eingegebenen Domain.
- **Key-Rotation verliert keine Metadaten mehr** - Die Metadata-Migration nach einer Key-Rotation laeuft nur noch bei tatsaechlich erfolgreicher Rotation, sodass DNS, fullTunnel und platform bei fehlgeschlagener Rotation nicht verloren gehen.
- **DNS-Feld in API-Responses** - Link- und Interface-Responses enthalten jetzt das DNS-Feld, sodass die Web-UI gespeicherte DNS-Server beim Bearbeiten eines Peers anzeigt.

---

## [1.3.12] - 2026-05-27

### Fixed

- **AllowedIPs-Konflikte werden jetzt blockiert** - `applyMetadata` und `PUT /wireguard/metadata` pruefen vor dem Speichern, ob zwei non-client Peers das gleiche Subnetz in `importedNetworks` beanspruchen. Doppelte Subnet-Zuweisungen fuehrten bisher dazu, dass WireGuard Traffic nur an einen der Peers routete und der andere die Verbindung verlor.
- **Metadata-Aenderungen werden sofort live angewendet** - `PUT /wireguard/metadata` rief bisher weder `syncHubConf` noch `syncAgentConfigs` auf. Aenderungen an `importedNetworks` im Metadata-Editor wirkten erst beim naechsten `apply-metadata`. Jetzt werden Hub-Config und Agent-Configs automatisch nach jedem Metadata-Save gesynct.
- **`syncHubConf` synct alle Interfaces** - `applyMetadata` rief `syncHubConf` nur fuer `wg0` auf. Aenderungen an Peers auf anderen Interfaces (wg1, wg2, ...) wurden nie in die conf-Datei uebernommen. Jetzt werden alle erkannten WG-Interfaces gesynct.
- **Agent `wg syncconf` verschluckte AllowedIPs-Aenderungen** - Wenn sich nur die AllowedIPs eines bestehenden Peers aenderten (gleicher PublicKey), ignorierte `wg syncconf` die Aenderung manchmal. Der Agent-Loop setzt AllowedIPs jetzt zusaetzlich explizit per `wg set peer ... allowed-ips ...` nach jedem `syncconf`.
- **Stale wg0-Routen blockierten lokale Netze** - `sync_routes()` im Agent fugte Kernel-Routen fuer AllowedIPs hinzu, raeumte aber nie veraltete Routen auf. Wenn ein Subnetz aus den AllowedIPs entfernt wurde, blieb die alte `ip route ... dev wg0` bestehen und ueberschrieb die lokale LAN-Route. Border-Router konnten dadurch eigene VLANs (z.B. 192.168.11.0/24) nicht mehr erreichen. `sync_routes()` entfernt jetzt stale Routen und ueberspringt Netze die bereits auf physischen Interfaces liegen. Gleiches Filtering auch auf der Hub-Seite in `syncHubConf`.

---

## [1.3.11] - 2026-05-27

### Fixed

- **WG-Peers konnten Hub-LAN nicht erreichen** - `syncHubConf` generierte MASQUERADE-Regeln nur fuer die Source-CIDR der physischen Schnittstelle (`-s 10.10.10.0/24 -o eth1`), aber nicht fuer Traffic aus dem WG-Tunnel-Subnet (`-s 10.10.0.0/24 -o eth1`). PVE-Hosts sahen Pakete mit unbekannter Source-IP und verwarfen die Antwort. Jetzt werden pro physischer Schnittstelle automatisch zwei MASQUERADE-Regeln generiert - eine fuer das lokale Subnet und eine fuer das Tunnel-Subnet.
- **MASQUERADE-Regex erkannte Regel-Varianten nicht** - `masqRe` in `_rewriteHubConf` matchte nur `-o ... -s ...` Reihenfolge. Manuell oder von aelteren Versionen gesetzte Regeln mit `-s ... -o ...` wurden beim Sync nicht gestripped und fuehrten zu Duplikaten. Regex akzeptiert jetzt beide Reihenfolgen.

---

## [1.3.10] - 2026-05-20

### Fixed

- **WireGuard Routen nach Agent-Neustart** - Agent-Configs mit `Table = off` verloren nach einem CT/VM-Neustart alle Routen, weil `PostUp` nur iptables-Regeln enthielt aber keine `ip route add`-Befehle. `buildHubPostUp`/`buildHubPostDown` generieren jetzt automatisch `ip route add/del`-Eintraege fuer alle AllowedIPs aus dem `[Peer]`-Block. Alle bestehenden Agents wurden via `syncAgentConfigs` aktualisiert.

---

## [1.3.9] - 2026-05-20

### Fixed

- **Client-Peers bekamen falsche Hub-AllowedIPs** - `_buildPeerUpdates` und `createPeer` schrieben `importedNetworks` als Hub-seitige AllowedIPs auch fuer Client-Type Links. Client-Peers erhalten jetzt nur ihre eigene `/32`-Adresse.
- **updatePeer loeste keinen Agent-Sync aus** - Aenderungen an AllowedIPs ueber die GUI wurden nicht an Agents weitergegeben. `updatePeer` ruft jetzt `syncAgentConfigs` auf.

### Changed

- **Interface- und Proxy-Host-Editoren redesignt** - Grouped Card Layout, Full-Width Sections, Monospace CIDR-Felder, responsive unter 768px.
- **CI: Node.js 20 -> 22** - Node 20 EOL Juni 2026; `--test-force-exit` und `timeout-minutes: 10` verhindern haengende Tests.

---

## [1.3.8] - 2026-05-17

### Added

- **Auto-MASQUERADE fuer Cross-Site-Traffic** - Agent-Configs enthalten jetzt automatisch MASQUERADE-Regeln fuer alle Remote-Site-Netze die ueber den WG-Tunnel ans lokale LAN weitergeleitet werden. Keine manuellen iptables/nft-Regeln mehr noetig - alles wird ueber die App gesteuert und bei Plan-Apply an die Agents gepusht.

### Fixed

- **PBS-Erreichbarkeit von Remote-Sites** - Remote-Peers (z.B. Daniel Home) konnten lokale LAN-Geraete (z.B. PBS 192.168.10.19) nicht erreichen, weil MASQUERADE-Regeln auf dem Ziel-Gateway fehlten. Wird jetzt automatisch durch syncAgentConfigs generiert.

---

## [1.3.7] - 2026-05-10

### Added

- **Netz-Auswahl beim Tunnel erstellen** - Checkbox-Karten pro Site mit einzeln waehlbaren Subnetzen statt manueller CIDR-Eingabe; Clients werden aus der Auswahl ausgeblendet
- **Platform-Badge auf Link-Karten** - zeigt Desktop/Mobile Badge in der WireGuard-Uebersicht
- **Type/Platform/FullTunnel im Metadata-Editor** - Verbindungstyp, Platform und Full-Tunnel nachtraeglich aenderbar; Platform und Full-Tunnel nur bei Client-Type sichtbar

### Fixed

- **Client-Links erzeugen keine falschen Warnungen mehr** - `remote-management-mode-undefined` und `link-not-currently-active` werden fuer Client-Type uebersprungen
- **delete-peer/update-peer akzeptiert camelCase und snake_case** - Frontend sendet `link_id`, Backend las nur `linkId`; jetzt werden beide Formate akzeptiert
- **AllowedIPs Konfliktpruefung** - `createPeer` und `updatePeer` verhindern doppelte Subnet-Zuweisungen mit Fehlermeldung
- **Agent Script-Update vor Config-Apply** - verhindert Crash-Loop wenn der Agent ein Script-Update braucht um einen Config-Bug zu fixen

---

## [1.3.6] - 2026-05-10

### Added

- **Agent config auto-upload** - agents upload their local WG config (with masked PrivateKey) to the hub when the server has no config stored; enables `syncAgentConfigs` for agents that were registered without providing their config; new endpoint `POST /api/agent/upload-config` (rate-limited)
- **Per-agent network access control** - new `allowed_sites` and `allowed_networks` JSON columns on the agent table; `allowed_networks` (explicit CIDRs) takes priority over `allowed_sites` (link-name whitelist) over full-mesh (null = all networks); deny-by-default when configured
- **Hub-managed firewall rules** - all agent PostUp/PostDown rules are generated by the hub via `normalizeAgentConfig()`; no local firewall configuration needed on VPN gateways; tunnel subnet derived automatically from Address field
- **Agent PostUp/PostDown live apply** - agent detects PostUp/PostDown changes from hub, runs old PostDown to clean up, then applies new PostUp rules without tunnel restart
- **Agent PrivateKey preservation** - agent restores local PrivateKey from `/etc/wireguard/*.conf` when hub sends `(hidden)` placeholder; prevents tunnel breakage on config push

### Fixed

- **WireGuard interfaces fail to start after reboot** - `wg-quick` auto-route injection collides with existing kernel routes (e.g. `10.10.10.0/24` on `eth1`), tearing down the entire interface; `createInterface()` now sets `Table = off` so route management is handled exclusively by PostUp/PostDown with error suppression
- **Backend hangs indefinitely when database is unreachable** - startup retry loop had no limit (1 s interval forever, no useful log); now retries up to 30 times with exponential backoff (1 s to 15 s), logs a clear "Database unreachable - check `systemctl status mariadb`" message, and exits with code 1 so systemd marks the service as failed
- **Missing migration file** - `20260503150000_agent_wg_link.js` was recorded in the DB but absent from disk, causing knex migration errors on fresh `migrateUp()`; file restored

### Changed

- **Install script MariaDB support** - `install_systemd()` detects MariaDB/MySQL, adds `After=mariadb.service` + `Wants=mariadb.service` to the systemd unit, and installs a `mariadb-rundir.service` safety net that creates `/run/mysqld/` before MariaDB starts (fixes LXC containers where `systemd-tmpfiles` fails due to UID mapping)
- **Agent script version** bumped to 1.3.6 (auto-update via hub)

---

## [1.3.4] - 2026-05-09

### Added

- **Agent version display** - agent script version shown as badge on link cards and in agent panel; agents report their version via heartbeat; new `agent_version` DB column with auto-migration
- **WCAG focus-visible** - keyboard focus ring on all SiteMenu nav items (was: `outline: none` with no replacement)
- **WireGuard responsive layout** - link cards and tabs now usable on mobile (768px breakpoint, scrollable tabs, single-column grid)
- **Dark mode SVG colors** - topology map type colors defined as CSS variables with light/dark mode variants
- **Auto-MASQUERADE for cross-interface routing** - `syncHubConf()` discovers non-WG interfaces and adds NAT rules so WireGuard peers can reach hosts on eth1/etc

### Security

- **Shell injection prevented** - `publicUrl`/`tunnelUrl` in agent install scripts validated against URL format; shell-unsafe characters rejected

### Fixed

- **Race condition in `createPeer`** - serialized via in-process write mutex; prevents duplicate tunnel IP assignment
- **Write ordering in `createPeer`** - conf file written BEFORE live `wg set`; rolls back on failure
- **Metadata write mutex** - `applyMetadataPatch` serialized; prevents last-write-wins data loss
- **Bandwidth NaN** - `__ts__` sentinel skipped in polling loop
- **`generatePeerConfig` stale linkId** - uses new link ID after key rotation for metadata lookup
- **`_rewriteHubConf` missing PostUp** - injects PostUp/PostDown when none exist in original conf
- **`revokeObjectURL` wrong variable** - blob URLs now correctly revoked after config download (was: memory leak)
- **`processResponse` crash on non-JSON** - gracefully handles nginx 502, HTML error pages
- **`download()` missing error check** - non-2xx responses now throw instead of downloading garbage
- **AuthContext `refresh` not memoized** - wrapped in `useCallback` to prevent interval churn
- **AuthContext `logout` not clearing 2FA** - `twoFactorChallenge` now reset on logout
- **`data.routes` not null-guarded** - optional chaining prevents crash if backend omits routes
- **Active peers table `colSpan`** - empty state now spans all 7 columns (was: 6)
- **Hardcoded German placeholder** - tunnel name placeholder and AllowedIPs hint now use i18n
- **Login form fields** - added `required` attribute to email and password inputs
- **Dead CSS** - removed stray `:host` selector, fixed monospace font stacks to use Tabler tokens
- **Toast component** - converted px to rem for accessibility (respects browser font-size)

---

## [1.3.3] - 2026-05-09

### Added

- **AllowedIPs conflict detection** - WireGuard status API now detects and warns when multiple peers claim the same subnet; shown as a prominent alert in the UI with affected peers listed
- **Auto-MASQUERADE for cross-interface routing** - `syncHubConf()` automatically discovers non-WireGuard interfaces with private IPs and adds MASQUERADE rules so WireGuard peers can reach hosts on those LANs (e.g., VMs on eth1)
- **Full i18n coverage** - all hardcoded German strings in the tunnel creation form (15 strings), routing matrix (5 keys), Login page (3 strings), and misc WireGuard labels translated to EN/DE/FR

### Fixed

- **Unhandled promise rejections** - replaced all 8 bare `mutateAsync()` calls in onClick handlers with the `mutate()` callback form; prevents crashes in strict environments
- **TypeScript type safety** - added `dns` and `fullTunnel` fields to `WireGuardLink` and `WireGuardInterface` types; removed 5 `as any` casts
- **useEffect loop risk** - AgentSection auto-create effect now uses a ref guard instead of unstable mutation dependencies
- **Clipboard error handling** - `navigator.clipboard.writeText()` now catches rejections
- **Redundant middleware** - removed duplicate `requireAdmin()` on PUT /wireguard/metadata

### Changed

- **README badge** - version updated to 1.3.3

---

## [1.3.2] - 2026-05-09

### Security

- **Broken access control fixes** - added `requireAdmin()` to all `/api/agents` CRUD routes, `/api/wireguard/status`, `/metadata` (GET), `/bandwidth`, `/apply-state`, `/link-config`, `/link-config-qr`, `GET /api/users`, and `GET /api/security/fail2ban`; previously any authenticated user could access these admin-only endpoints
- **Unauthenticated file upload closed** - `POST /api/design/screenshot` now requires JWT + admin role; added magic-bytes validation to reject files whose content doesn't match the declared extension
- **Bulk user delete removed** - `DELETE /api/users` (previously guarded only by `CI=true && DEBUG=true` env vars) now always returns 404; eliminates unauthenticated account-wipe risk
- **Agent self-update signed** - server computes HMAC-SHA256 of the loop script using the agent token as key; agents verify the signature before accepting a self-update, preventing server-compromise-to-RCE escalation
- **JWT expiry capped** - token expiry now limited to 30 days maximum; prevents long-lived tokens that survive password changes
- **Rate limiter persistent** - replaced in-memory rate limiter with SQLite-backed storage; survives process restarts and is shared across cluster workers
- **CORS hardened** - disallowed cross-origin requests now receive 403 instead of silently proceeding without CORS headers
- **CSP header added** - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; object-src 'none'; frame-ancestors 'none'`
- **GitHub Actions SHA-pinned** - all `actions/checkout`, `actions/setup-node`, and `actions/stale` references pinned to immutable commit SHAs
- **CODEOWNERS added** - `.github/workflows/` now requires review from `@floppy007`
- **Shell injection mitigated** - converted 3 of 4 `utils.exec()` calls (shell-based) to `utils.execFile()` (argument array, no shell)
- **Dockerfile hardened** - Cypress test image now explicitly sets `USER 1000` before CMD

### Fixed

- **Frontend test drift** - fixed 10 failing WireGuard tests (missing `useAgents` mock export + stale text assertions), 1 failing Platform test (missing `useFail2BanStatus` mock), 1 failing Gateway test (untranslated key assertions)
- **Backend lint warnings** - removed 2 unused parameters in `buildApplyContract()`, renamed unused `err` to `_err` in `require-admin.js`
- **Frontend dependency vulnerabilities** - resolved 6 high-severity npm audit findings (vite path traversal, lodash prototype pollution, picomatch ReDoS, postcss XSS)

### Changed

- **`.gitignore` updated** - added `.env`, `.env.*`, `.gstack/` to prevent accidental secret commits
- **Default DB credentials** - `backend/config/default.json` now uses `changeme` placeholder instead of `npm`/`npm`
- **Agent script version bumped** - `AGENT_SCRIPT_VERSION` incremented to `1.3.0` to trigger self-update on all connected agents

---

## [1.3.1] - 2026-05-09

### Added

- **WireGuard Peer CRUD** - delete button on every link card with confirmation modal; removes peer from live interface, config file and metadata; creates safety backup before deletion; `POST /api/wireguard/update-peer` for live AllowedIPs changes with automatic hub sync
- **WireGuard Interface CRUD** - create new interfaces (wg2, wg3, …) with auto-generated keypair, address and listen port; delete non-hub interfaces with confirmation modal; `wg-quick up/down` and `systemctl enable/disable` handled automatically
- **Interface selector** - tunnel creation form and header now show an interface dropdown when multiple interfaces exist (was hardcoded to wg0)
- **Live-vs-conf drift detection** - `syncHubConf` now compares the running WireGuard interface against the config file and corrects any discrepancies automatically

### Fixed

- **AllowedIPs stripped on sync** - `_buildPeerUpdates` removed non-host networks from peers when `importedNetworks` was empty in metadata; now preserves existing AllowedIPs from the config file when metadata has no override
- **WireGuard nav icon** - replaced wide text logo SVG (1874×333) with shield-only icon; nav item now renders at correct 16×16 size
- **Interface card layout** - consistent vertical layout with fixed button position at bottom, all info rows always visible
- **CI lint errors** - fixed all `useOptionalChain` and `noParameterAssign` errors across backend

---

## [1.3.0] - 2026-05-06

### Added

- **WireGuard tunnel creation** - new "Neuer Tunnel" button on WireGuard page; creates peer with keypair, auto-assigns tunnel IP, generates downloadable client config
- **Tunnel configuration options** - name, type (client/site-to-site/hub-link), DNS servers, platform (desktop/mobile), full tunnel toggle, custom AllowedIPs
- **Platform-aware AllowedIPs** - desktop uses `/1`-split routing (no routing loop), mobile uses `0.0.0.0/0` (OS VPN tunnel flag)
- **DNS/nameserver config** - configurable per interface and per link; falls back to `WG_DNS` env variable; written into `[Interface] DNS =` of generated peer configs
- **DonutGauge component** - SVG ring gauge for stat cards showing ratios (e.g. 10/12 active)
- **PeerSparkline component** - mini bandwidth sparkline chart per peer connection
- **Chart legends** - bandwidth charts show peer name + color + current rate

### Changed

- **Dashboard redesign** - stat cards with donut gauges, peer link preview with sparklines and scroll, higher bandwidth charts
- **Traffic page redesign** - donut stat cards, per-peer sparkline column in link table
- **Header redesign** - compact 56px glassmorphism header, pill-style nav links, Light/Dark pill toggle, avatar with initials
- **CSS simplification** - removed heavy body gradients, grid overlays, pseudo-element decorations; cards use `backdrop-filter: blur` and `color-mix`

### Fixed

- Bandwidth charts starting in the middle when history is incomplete (left-padded with zeros)
- Nav link active state not visible (Tabler CSS specificity override)

---

## [1.2.4] - 2026-05-05

### Added

- **WireGuard peer config export** - download client config files with auto-generated keypair; `GET /api/wireguard/link-config` returns the full `.conf` file as attachment
- **QR code modal** - `GET /api/wireguard/link-config-qr` generates a PNG QR code for mobile enrollment; shown in a modal on the link card
- **Routing matrix** - visual matrix showing which peers export which networks; displayed in the Routing tab
- **Active peer names** - peer names from metadata shown in status cards and link headers instead of raw public keys

### Fixed

- CI test failures from upstream dependency updates

---

## [1.2.3] - 2026-05-04

### Fixed

- **Certificate renewal (HTTP challenge)** - `certbot renew` replaced with `certonly --force-renewal`; added missing `--webroot-path` and `--non-interactive` flags; uses virtualenv certbot at `/opt/certbot/bin/certbot` instead of system binary (which lacks DNS plugins)
- **Certificate renewal (DNS challenge)** - fixed "unrecognized arguments" error by switching from `--authenticator dns-cloudflare` to `--dns-cloudflare`; credentials are now fetched directly from the database (bypassing the `omissions()` security filter that strips them from API responses)
- **Certbot versioned lineage** - added `clearCertDirsForRenewal()` helper that removes `archive/`, `live/` and `renewal/` entries for a certificate before `certonly`, preventing certbot from creating suffixed lineages like `npm-116-0001` instead of `npm-116`
- **New certificate request (DNS challenge)** - fixed same `--authenticator` -> `--<plugin>` flag for initial issuance
- **Modal header alignment** - fixed tab nav being pushed down in Redirection Host, Proxy Host, Dead Host and Stream modals; adjusted card-header padding and removed double-rendered `<Alert>` (replaced `show={!!errorMsg}` with conditional rendering)

### Changed

- Scripts (`check-production-routes`, `start-production`, `status-production`) - replaced hardcoded external URL default with `http://127.0.0.1:81`

### Added

- `ROADMAP.md` - documents planned DNS auto-provisioning feature (Cloudflare + IPv64)

---

## [1.2.2] - 2026-05-04

### Added

- **WireGuard routing automation** - `syncHubConf()` rewrites hub `wg0.conf` AllowedIPs and
  PostUp/PostDown ip-route commands from metadata on every UI apply; applies live via `wg set` +
  `ip route add` without restarting wg0
- **Agent config sync** - `syncAgentConfigs()` updates every connected agent's WireGuard peer
  AllowedIPs so all sites can reach each other through the hub; agents pick up changes on their
  next 30 s poll; both syncs fire automatically on `metadata-with-config-intent` apply
- **Agent self-update** - `AGENT_SCRIPT_VERSION` constant tracks the loop-script version; agents
  compare their local version on every config poll and self-update automatically via
  `GET /api/agent/loop-script` + `exec` - no token reset or manual reinstall required
- **`sync_routes()` in agent loop script** - adds missing kernel ip routes after `wg syncconf`
  (which updates WireGuard peer tables but never touches the kernel routing table); runs on every
  config change and once at startup
- **Full multilanguage UI (EN / DE / FR)** - all user-visible strings in WireGuard, Dashboard,
  Platform, Gateway and Fail2Ban sections are now translated; topology labels, badge labels,
  table headers, editors, planners, stat cards, empty states and backend warning codes all go
  through the i18n system
- **Agent duplicate-link guard** - `create` and `update` reject `wg_link_name` when more than one
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

## [1.2.1] - 2026-05-03

First public release of FloppyGuard, forked from nginx-proxy-manager v2.14.0.

### Added

- **WireGuard management** - interface, peer and link CRUD with live status polling; visual
  topology map (hub / site / client nodes, link edges); planning layer with discover -> shape ->
  validate -> ready stages; dry-run plan preview; one-step apply and restore
- **Remote agent system** - native Linux agent with curl-based install one-liner and automatic
  token registration; UniFi-compatible mode; service discovery across registered agents
- **Platform dashboard** - combined home page with proxy stats, WireGuard summary, gateway
  overview and Fail2Ban status; Fail2Ban UI with jail list, banned IPs and one-click unban
- **Gateway page** - reachability map, private route inventory, peer network inventory, routing
  hints (missing return routes, NAT candidates, observations)
- **Security hardening** - nftables firewall with strict INPUT policy; fail2ban jails for API
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

## [1.2.0] - 2026-02-17

### Added

- **WireGuard management page** - visual topology map showing hub, site and client nodes with
  link edges; interface and peer status from live `wg show` output; link metadata editor and
  planner

---

## [1.1.0] - 2025-11-11

### Added

- **Remote agent system** - agent registration with token-based authentication; install
  one-liner generator; token reset and agent management UI

---

## [1.0.0] - 2025-10-14

Initial fork of nginx-proxy-manager v2.14.0.

---

*nginx-proxy-manager v2.14.0 by [Jamie Curnow](https://github.com/jc21) - MIT License*
