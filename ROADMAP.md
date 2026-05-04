# FloppyGuard Roadmap

This document tracks planned features and improvements. Items are not in strict priority order — implementation depends on available time and community interest.

---

## Planned Features

### DNS Auto-Provisioning (Cloudflare & IPv64)

**Goal:** When a Proxy Host (or Redirection Host) is created or updated, FloppyGuard automatically creates or updates the corresponding DNS record (A/CNAME) via the provider's API — no manual DNS management needed.

**Scope:**
- Supported providers: **Cloudflare** (via API token + Zones API), **IPv64** (via API key)
- Records created: A record pointing to the server's public IP, or CNAME to a base domain
- Optional per-host toggle: "Auto-provision DNS" in the Proxy Host form
- Provider credentials stored per-zone in the Settings page
- Cleanup option: delete DNS record when host is deleted

**Backend:**
- New `dns-provisioning` module in `backend/internal/`
- Cloudflare: `POST /zones/{zone_id}/dns_records`, `PUT` for updates, `DELETE` for cleanup
- IPv64: IPv64 REST API for subdomain management
- Triggered as a post-save hook in `proxy-host.js` / `redirection-host.js`

**Frontend:**
- Optional "Auto DNS" toggle in Proxy Host / Redirection Host form
- DNS provider selection (Cloudflare / IPv64)
- Zone / base domain selector (loaded from provider API)
- Record type selection (A / CNAME)
- Settings page: manage provider API credentials

**Related issue:** [#1 — DNS Auto-Provisioning](https://github.com/floppy007/floppyguard/issues/1)

---

### Docker Support

Docker Compose stack for FloppyGuard (backend + frontend + nginx), usable as a self-contained alternative to the host-based install.

---

### Access List Improvements

- Per-host IP allowlist/denylist beyond what nginx `allow`/`deny` provides
- Sync access lists to WireGuard peer filter rules

---

### WireGuard Agent Auto-Update

Allow the WireGuard agent script on remote nodes to update itself to the latest version from the FloppyGuard server without manual SSH.

---

### Notification System

- Webhook support (Discord, Slack, generic HTTP)
- Alerts for: certificate expiry, WireGuard peer disconnect, Fail2Ban ban events

---

## Recently Shipped

| Version | Highlights |
|---------|-----------|
| v1.2.2  | i18n (DE/FR/EN), WireGuard routing automation, agent self-update, Fail2Ban dashboard, CI workflow |
| v1.2.1  | Install script, German translations, compiled locales |
| v1.2.0  | WireGuard hub/spoke topology, link management, route planning |
| v1.1.0  | WireGuard VPN management (initial), peer tracking |
| v1.0.0  | Fork of nginx-proxy-manager v2.14.0, FloppyGuard rebranding |
