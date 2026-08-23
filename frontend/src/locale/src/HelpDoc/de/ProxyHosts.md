## Was ist ein Proxy-Host?

Ein Proxy-Host ist der eingehende Endpunkt für einen Webdienst, den Sie weiterleiten möchten.

Er bietet optionale SSL-Terminierung für Ihren Dienst, der möglicherweise keine integrierte SSL-Unterstützung hat.

Proxy-Hosts sind die häufigste Verwendung für den Nginx Proxy Manager.

## Erweiterte Nginx-Konfiguration

Öffnen Sie einen Proxy-Host und wählen Sie oben rechts das Zahnrad, um die **Custom Nginx Configuration** zu bearbeiten. Die Eingabe wird beim Speichern mit dem Proxy-Host übernommen und in dessen Nginx-Konfiguration gerendert.

Der Editor zeigt den eingegebenen Text sowie Zeilennummern an. Ergänzen Sie dort nur Direktiven, die im `server`-Block gültig sind; sicherheitskritische Direktiven werden beim Speichern abgewiesen.

## Cloudflare DNS

Im Advanced-Tab kann FloppyGuard für jeden Proxy Host gezielte A- und AAAA-Records anlegen und bei Domain- oder Proxy-Änderungen aktualisieren. Aktivieren Sie **Manage DNS records automatically** und wählen Sie bei Bedarf **Proxy through Cloudflare**.

Der Token wird bevorzugt aus dem ausgewählten Let's-Encrypt-Zertifikat mit Cloudflare-DNS-Challenge verwendet; tragen Sie ihn beim Anlegen dieses Zertifikats unter **Zertifikate → Let's Encrypt via DNS → Cloudflare → Zugangsdaten** ein. Alternativ kann ein globaler `CLOUDFLARE_API_TOKEN` gesetzt werden. Nur von FloppyGuard angelegte Records werden aktualisiert. Bestehende Wildcard- und manuell angelegte Records bleiben unangetastet. In der Proxy-Host-Tabelle kennzeichnet das grüne Cloudflare-Logo aktive DNS-Synchronisierung ohne Cloudflare-Proxy; orange steht für aktivierten Proxy.
