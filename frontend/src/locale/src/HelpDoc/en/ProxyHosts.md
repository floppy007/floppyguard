## What is a Proxy Host?

A Proxy Host is the incoming endpoint for a web service that you want to forward.

It provides optional SSL termination for your service that might not have SSL support built in.

Proxy Hosts are the most common use for the Nginx Proxy Manager.

## Advanced Nginx Configuration

Open a Proxy Host and select the gear icon in the upper-right corner to edit the **Custom Nginx Configuration**. The value is saved with the Proxy Host and rendered into its Nginx configuration.

The editor displays the entered text and line numbers. Add only directives that are valid in a `server` block; security-sensitive directives are rejected when the host is saved.

## Cloudflare DNS

The Advanced tab can create explicit A and AAAA records for each Proxy Host and update them whenever its domains or proxy setting changes. Enable **Manage DNS records automatically** and optionally select **Proxy through Cloudflare**.

The token is taken from the selected Let's Encrypt certificate with a Cloudflare DNS challenge; enter it while creating that certificate under **Certificates → Let's Encrypt via DNS → Cloudflare → Credentials**. `CLOUDFLARE_API_TOKEN` is an optional global fallback. Only records created by FloppyGuard are updated; wildcard and manually managed records are left unchanged. In the Proxy Hosts table, a green Cloudflare icon marks active DNS synchronization without the Cloudflare proxy; orange means the proxy is enabled.
