## Hilfe zu Zertifikaten

### HTTP-Zertifikat

Ein HTTP-validiertes Zertifikat bedeutet, dass Let's Encrypt-Server
versuchen, Ihre Domains über HTTP (nicht HTTPS!) zu erreichen, und wenn dies erfolgreich ist,
stellen sie Ihr Zertifikat aus.

Für diese Methode müssen Sie einen _Proxy-Host_ für Ihre Domain(s) erstellen, der
über HTTP zugänglich ist und auf diese Nginx-Installation verweist. Nachdem ein Zertifikat
ausgestellt wurde, können Sie den _Proxy-Host_ so ändern, dass dieses Zertifikat auch für HTTPS-Verbindungen
verwendet wird. Der _Proxy-Host_ muss jedoch weiterhin für den HTTP-Zugriff konfiguriert sein,
 damit das Zertifikat erneuert werden kann.

Dieser Prozess unterstützt keine Wildcard-Domains.

### DNS-Zertifikat

Für ein DNS-validiertes Zertifikat müssen Sie ein DNS-Provider-Plugin verwenden. Dieser DNS-
Provider wird verwendet, um temporäre Einträge auf Ihrer Domain zu erstellen. Anschließend fragt Let's
Encrypt diese Einträge ab, um sicherzustellen, dass Sie der Eigentümer sind. Bei Erfolg wird
Ihr Zertifikat ausgestellt.

Sie müssen vor der Beantragung dieser Art von Zertifikat keinen _Proxy-Host_ erstellen.
Sie müssen Ihren _Proxy-Host_ auch nicht für den HTTP-Zugriff konfigurieren.

Dieser Prozess unterstützt Wildcard-Domains.

#### Cloudflare-API-Token für Proxy-Host-DNS

Wählen Sie beim Anlegen eines DNS-Zertifikats den DNS-Provider **Cloudflare** und tragen Sie im Feld **Zugangsdaten** einen API-Token im folgenden Format ein:

```ini
dns_cloudflare_api_token = IHR_CLOUDFLARE_TOKEN
```

Der Token gehört zu diesem Zertifikat. Wählen Sie das Zertifikat anschließend im SSL-Tab eines Proxy Hosts aus; dessen aktivierte Cloudflare-DNS-Automatik verwendet dann genau diesen Token. Für getrennte Berechtigungen erstellen Sie je Domain oder Zertifikatsgruppe ein eigenes DNS-Zertifikat. Der Token benötigt mindestens die Cloudflare-Berechtigungen **Zone:Read** und **DNS:Edit** für die jeweilige Zone.

### Benutzerdefiniertes Zertifikat

Verwenden Sie diese Option, um Ihr eigenes SSL-Zertifikat hochzuladen, das Ihnen von Ihrer eigenen
Zertifizierungsstelle bereitgestellt wurde.
