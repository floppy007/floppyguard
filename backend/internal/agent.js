import { execFile } from "node:child_process";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { createConnection } from "node:net";
import error from "../lib/error.js";
import Agent from "../models/agent.js";
import internalWireGuard from "./wireguard.js";

/**
 * Generate a random hex token of `byteLength` bytes (returns 2*byteLength hex chars).
 *
 * @param {number} byteLength
 * @returns {string}
 */
const randomToken = (byteLength = 32) => randomBytes(byteLength).toString("hex");

/**
 * Compute SHA-256 hex digest of a string. Returns null if input is falsy.
 *
 * @param {string|null|undefined} text
 * @returns {string|null}
 */
const hashConfig = (text) => {
	if (!text) return null;
	return createHash("sha256").update(text).digest("hex");
};

const AGENT_SCRIPT_VERSION = "1.3.8";

/**
 * Compute HMAC-SHA256 of the script using the agent_token as key.
 * The agent verifies this signature before accepting a self-update.
 *
 * @param {string} script
 * @param {string} agentToken
 * @returns {string}
 */
const signScript = (script, agentToken) =>
	createHmac("sha256", agentToken).update(script).digest("hex");

/**
 * Parse agent.services JSON string into array. Returns [] on failure.
 * @param {Object} agent
 * @returns {Object}
 */
const parseAgentServices = (agent) => {
	if (!agent.services) {
		agent.services = [];
	} else if (typeof agent.services === "string") {
		try {
			agent.services = JSON.parse(agent.services);
		} catch {
			agent.services = [];
		}
	}
	return agent;
};

// Known port → default label
const KNOWN_PORTS = [
	{ port: 8080, label: "Web UI" },
	{ port: 8443, label: "Web UI", https: true },
	{ port: 9000, label: "Portainer" },
	{ port: 9443, label: "Portainer", https: true },
	{ port: 8888, label: "Management UI" },
	{ port: 3000, label: "Grafana" },
	{ port: 9090, label: "Prometheus" },
	{ port: 1880, label: "Node-RED" },
	{ port: 10000, label: "Webmin" },
	{ port: 8000, label: "Web UI" },
];

/**
 * Check if a TCP port is open on a host. Resolves true/false in ~1s.
 */
const tcpProbe = (host, port) =>
	new Promise((resolve) => {
		const sock = createConnection({ host, port, timeout: 1000 });
		sock.once("connect", () => {
			sock.destroy();
			resolve(true);
		});
		sock.once("timeout", () => {
			sock.destroy();
			resolve(false);
		});
		sock.once("error", () => resolve(false));
	});

/**
 * Try to fetch the <title> from a URL. Returns null on failure.
 */
/**
 * Fetch a URL via curl (handles self-signed certs, redirects, timeouts reliably).
 * Returns { title, finalUrl } or null on failure/404.
 */
const fetchTitle = (url) =>
	new Promise((resolve) => {
		const args = [
			"-skL",
			"--max-time", "4",
			"--write-out", "\n__FINALURL__%{url_effective}",
			url,
		];
		execFile("curl", args, { timeout: 5000 }, (err, stdout) => {
			if (err) {
				resolve(null);
				return;
			}
			const sep = stdout.lastIndexOf("\n__FINALURL__");
			const body = sep >= 0 ? stdout.slice(0, sep) : stdout;
			const finalUrl = sep >= 0 ? stdout.slice(sep + 13).trim() : url;
			if (!body.includes("<title") || /not found|404/i.test(body.slice(0, 200))) {
				resolve(null);
				return;
			}
			const m = body.match(/<title[^>]*>([^<]{1,80})<\/title>/i);
			resolve({ title: m ? m[1].trim() : null, finalUrl });
		});
	});

/**
 * Strict CIDR validation — prevents shell injection via malicious network values.
 * Only allows valid IPv4 CIDR notation (e.g. "192.168.1.0/24").
 */
const CIDR_RE = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;
function assertCIDR(value) {
	if (!CIDR_RE.test(value)) {
		throw new Error(`Invalid CIDR: ${value}`);
	}
}

/**
 * Build hub-managed PostUp/PostDown rules from the config's tunnel subnet.
 * %i is replaced by wg-quick with the interface name at runtime.
 *
 * @param {string} tunnelSubnet  e.g. "10.10.0.0/24"
 * @param {string[]} remoteSiteNets  networks from other sites that need MASQUERADE
 *   when exiting through the local LAN (e.g. ["192.168.111.0/24", "192.168.112.0/24"])
 */
function buildHubPostUp(tunnelSubnet, remoteSiteNets = [], peerNets = []) {
	assertCIDR(tunnelSubnet);
	let rules = `sysctl -w net.ipv4.ip_forward=1; iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING ! -o %i -s ${tunnelSubnet} -j MASQUERADE`;
	for (const net of remoteSiteNets) {
		assertCIDR(net);
		rules += `; iptables -t nat -A POSTROUTING ! -o %i -s ${net} -j MASQUERADE`;
	}
	for (const net of peerNets) {
		assertCIDR(net);
		rules += `; ip route add ${net} dev %i 2>/dev/null || true`;
	}
	return rules;
}
function buildHubPostDown(tunnelSubnet, remoteSiteNets = [], peerNets = []) {
	assertCIDR(tunnelSubnet);
	let rules = `iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING ! -o %i -s ${tunnelSubnet} -j MASQUERADE`;
	for (const net of remoteSiteNets) {
		assertCIDR(net);
		rules += `; iptables -t nat -D POSTROUTING ! -o %i -s ${net} -j MASQUERADE`;
	}
	for (const net of peerNets) {
		assertCIDR(net);
		rules += `; ip route del ${net} dev %i 2>/dev/null || true`;
	}
	return rules;
}

/**
 * Extract the tunnel subnet from an Address line (e.g. "10.10.0.5/24" -> "10.10.0.0/24").
 * Falls back to "10.10.0.0/24" if not parseable.
 */
function deriveTunnelSubnet(configText) {
	const m = (configText || "").match(/^\s*Address\s*=\s*([\d.]+)\/([\d]+)/im);
	if (!m) return "10.10.0.0/24";
	const parts = m[1].split(".");
	const mask = Number.parseInt(m[2], 10);
	if (mask <= 8) return `${parts[0]}.0.0.0/${mask}`;
	if (mask <= 16) return `${parts[0]}.${parts[1]}.0.0/${mask}`;
	// For /32 host addresses, derive the enclosing /24 (the tunnel subnet)
	if (mask > 24) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
	return `${parts[0]}.${parts[1]}.${parts[2]}.0/${mask}`;
}

/**
 * @param {string} configText  raw wg-quick config
 * @param {string[]} remoteSiteNets  networks from other sites needing LAN MASQUERADE
 */
function normalizeAgentConfig(configText, remoteSiteNets = []) {
	if (!configText) return configText;
	const lines = configText.split(/\r?\n/);
	const out = [];
	let inInterface = false;
	let hasTable = false;

	// Single pass: detect Table, mask PrivateKey, strip PostUp/PostDown
	for (const raw of lines) {
		const t = raw.trim();
		if (t === "[Interface]") inInterface = true;
		else if (t.startsWith("[")) inInterface = false;

		if (inInterface && t.startsWith("Table")) {
			hasTable = true;
		}

		// Mask PrivateKey for DB storage
		if (inInterface && t.startsWith("PrivateKey") && !t.includes("(hidden)")) {
			out.push("PrivateKey = (hidden)");
			continue;
		}

		// Strip all PostUp/PostDown — hub regenerates them
		if (t.startsWith("PostUp") || t.startsWith("PostDown")) continue;

		out.push(raw);
	}

	// Derive tunnel subnet from Address field
	const tunnelSubnet = deriveTunnelSubnet(configText);

	// Insert Table = off + hub-managed PostUp/PostDown before first [Peer]
	const peerIdx = out.findIndex((l) => l.trim() === "[Peer]");
	const insertAt = peerIdx > 0 ? peerIdx : out.length;

	const toInsert = [];
	if (!hasTable) toInsert.push("Table = off");
	const peerNets = _parseHubPeerAllowedIPs(configText).filter(
		(c) => !c.endsWith("/32") && !c.endsWith("/128"),
	);
	toInsert.push(`PostUp = ${buildHubPostUp(tunnelSubnet, remoteSiteNets, peerNets)}`);
	toInsert.push(`PostDown = ${buildHubPostDown(tunnelSubnet, remoteSiteNets, peerNets)}`);

	out.splice(insertAt, 0, ...toInsert);

	return out.join("\n");
}

/**
 * Extract the first Address IP from a wg-quick config string.
 * e.g. "Address = 10.10.0.2/32" → "10.10.0.2"
 */
const extractWgIp = (configText) => {
	if (!configText) return null;
	const m = configText.match(/^\s*Address\s*=\s*([\d.]+)/im);
	return m ? m[1] : null;
};

/**
 * Scan known management ports on `ip` and return [{name, url}].
 */
const scanIp = async (ip) => {
	const found = [];
	const seenUrls = new Set();

	for (const { port, label, https: useHttps } of KNOWN_PORTS) {
		const open = await tcpProbe(ip, port);
		if (!open) continue;
		const scheme = useHttps ? "https" : "http";
		const probeUrl = `${scheme}://${ip}:${port}`;
		const result = await fetchTitle(probeUrl);
		if (result === null) continue;
		// Store the clean base URL (scheme + host + port), not the redirect destination path
		const parsed = new URL(result.finalUrl || probeUrl);
		const storeUrl = `${parsed.protocol}//${parsed.hostname}:${parsed.port || (parsed.protocol === "https:" ? "443" : "80")}`;
		const key = storeUrl;
		if (seenUrls.has(key)) continue;
		seenUrls.add(key);
		seenUrls.add(probeUrl.replace(/\/$/, ""));
		const name = result.title ?? label;
		found.push({ name, url: storeUrl });
	}
	return found;
};

/**
 * Extract a dotted-decimal IP from a string (e.g. agent name "VM-Docker (192.168.10.7)").
 * Returns null if none found.
 */
const extractIpFromText = (text) => {
	if (!text) return null;
	const m = text.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
	return m ? m[1] : null;
};

/**
 * Scan all active agents and update their services field.
 * Called on startup and once daily.
 */
const scanAllAgentServices = async () => {
	const agents = await Agent.query().where("is_deleted", 0).where("status", "active");
	for (const agent of agents) {
		// Prefer LAN IP (from hostname or name) — browser-clickable.
		// Only use WireGuard IP as fallback if no LAN IP found.
		const lanIp = extractIpFromText(agent.hostname) || extractIpFromText(agent.name);
		const wgIp = extractWgIp(agent.config_text);
		const scanIps = lanIp ? [lanIp] : wgIp ? [wgIp] : [];
		if (scanIps.length === 0) continue;
		try {
			// Scan all candidate IPs, merge results (prefer LAN IP URLs)
			const services = [];
			for (const ip of scanIps) {
				const found = await scanIp(ip);
				for (const svc of found) {
					if (!services.some((s) => s.url === svc.url)) {
						services.push(svc);
					}
				}
			}
			await Agent.query().patchAndFetchById(agent.id, {
				services: JSON.stringify(services),
			});
		} catch {
			// ignore per-agent errors
		}
	}
};

// Run once on startup (after a short delay) then once a day
setTimeout(() => {
	scanAllAgentServices().catch(() => {});
	setInterval(() => scanAllAgentServices().catch(() => {}), 24 * 60 * 60 * 1000);
}, 5000);

/**
 * Build the agent loop script (the bash daemon that runs on the remote machine).
 *
 * @param {string} mode  "native" or "unifi"
 * @returns {string}  Complete bash script starting with #!/bin/bash
 */
function buildLoopScript(mode) {
	// ── apply_config function: mode-specific ──────────────────────────────────────
	// native: write wg-quick config file and apply via wg syncconf / wg-quick
	// unifi:  push peer config to UniFi Network Application API
	const applyFunctionNative = `\
# Ensure kernel ip routes exist for all non-host AllowedIPs on a WireGuard interface.
# wg syncconf updates WireGuard peer tables but does NOT touch the kernel routing table.
# This must be called after syncconf and also once on startup to recover from missed syncs.
sync_routes() {
  local iface="$1"
  ip link show "$iface" > /dev/null 2>&1 || return 0
  local wg_nets
  wg_nets=$(wg show "$iface" allowed-ips 2>/dev/null | awk '{for(i=2;i<=NF;i++) print $i}' || echo "")
  [ -z "$wg_nets" ] && return 0
  while IFS= read -r net; do
    [ -z "$net" ] && continue
    case "$net" in */32|*/128|0.0.0.0/0|::/0) continue ;; esac
    ip route add "$net" dev "$iface" 2>/dev/null && log "Added route $net dev $iface" || true
  done <<< "$wg_nets"
}

apply_config() {
  local cfg="$1" iface="$2"
  printf '%s' "$cfg" > /tmp/fg_new_wg.conf
  local old_conf="/etc/wireguard/$iface.conf"

  # ── Preserve local PrivateKey when hub sends "(hidden)" ──
  if grep -q 'PrivateKey = (hidden)' /tmp/fg_new_wg.conf && [ -f "$old_conf" ]; then
    local real_key
    real_key=$(grep '^PrivateKey' "$old_conf" | head -1 | sed 's/^PrivateKey *= *//')
    if [ -n "$real_key" ] && [ "$real_key" != "(hidden)" ]; then
      python3 -c "
import sys
key=sys.argv[1]
with open('/tmp/fg_new_wg.conf','r') as f: c=f.read()
with open('/tmp/fg_new_wg.conf','w') as f: f.write(c.replace('PrivateKey = (hidden)','PrivateKey = '+key,1))
" "$real_key"
    fi
  fi

  if ip link show "$iface" > /dev/null 2>&1; then
    # ── Apply PostUp/PostDown changes from hub ──
    local old_postup="" old_postdown="" new_postup="" new_postdown=""
    [ -f "$old_conf" ] && old_postup=$(grep '^PostUp' "$old_conf" | sed 's/^PostUp *= *//' || true)
    [ -f "$old_conf" ] && old_postdown=$(grep '^PostDown' "$old_conf" | sed 's/^PostDown *= *//' || true)
    new_postup=$(grep '^PostUp' /tmp/fg_new_wg.conf | sed 's/^PostUp *= *//' || true)
    if [ "$old_postup" != "$new_postup" ]; then
      if [ -n "$old_postdown" ]; then
        log "Running old PostDown before applying new rules..."
        eval "$old_postdown" 2>/dev/null || true
      fi
      if [ -n "$new_postup" ]; then
        log "Applying new PostUp rules from hub..."
        eval "$new_postup" 2>/dev/null || true
      fi
    fi
    wg syncconf "$iface" <(wg-quick strip /tmp/fg_new_wg.conf 2>/dev/null || grep -vE "^(Address|PostUp|PostDown|DNS|MTU|Table|PreUp|PreDown)=" /tmp/fg_new_wg.conf)
    # wg syncconf sometimes silently ignores AllowedIPs changes for existing peers.
    # Force-set AllowedIPs per peer from the new config to ensure they match.
    while IFS= read -r line; do
      local pk ai
      pk=$(echo "$line" | awk '{print $1}')
      ai=$(echo "$line" | awk '{for(i=2;i<=NF;i++) printf "%s,", $i}' | sed 's/,$//')
      [ -z "$pk" ] || [ -z "$ai" ] && continue
      wg set "$iface" peer "$pk" allowed-ips "$ai" 2>/dev/null || true
    done < <(wg-quick strip /tmp/fg_new_wg.conf 2>/dev/null | awk '/^\[Peer\]/{pk="";ai=""} /^PublicKey/{pk=$3} /^AllowedIPs/{ai=$3} pk && ai{print pk, ai; pk=""; ai=""}')
    cp /tmp/fg_new_wg.conf "/etc/wireguard/$iface.conf"
    sync_routes "$iface"
    log "Applied config update to $iface (syncconf + AllowedIPs force-set, no downtime)"
  else
    cp /tmp/fg_new_wg.conf "/etc/wireguard/$iface.conf"
    wg-quick up "$iface" && log "Brought up $iface with new config"
  fi
}

# Sync routes once at agent startup to recover any routes missed by previous syncconf calls
sync_routes "$WG_INTERFACE"`;

	// For UniFi mode, config_text is a JSON blob:
	// { "server_public_key": "...", "endpoint": "host:port",
	//   "local_address": "10.x.x.x/32", "allowed_ips": ["..."],
	//   "persistent_keepalive": 25, "private_key": "..." }
	// The agent authenticates with UniFi controller and creates/updates the
	// WireGuard VPN client entry. It also adds firewall rules for the allowed_ips.
	const applyFunctionUnifi = `\
# UniFi helper: authenticate and get session cookie
unifi_login() {
  curl -sk -c /tmp/fg_unifi_cookie -b /tmp/fg_unifi_cookie \\
    -X POST -H "Content-Type: application/json" \\
    -d "{\\"username\\":\\"$UNIFI_USER\\",\\"password\\":\\"$UNIFI_PASS\\"}" \\
    "$UNIFI_URL/api/auth/login" > /dev/null 2>&1
}

# UniFi helper: find existing VPN client by name, returns ID or empty
unifi_find_vpn() {
  local name="$1"
  curl -sk -b /tmp/fg_unifi_cookie \\
    "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/vpnclient" 2>/dev/null |
    python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('data', [])
for item in items:
    if item.get('name') == sys.argv[1]:
        print(item.get('_id',''))
        sys.exit(0)
" "$name" 2>/dev/null || echo ""
}

apply_config() {
  local cfg="$1"  # JSON blob from FloppyGuard
  # Parse peer config from JSON
  SERVER_PUB=$(python3 -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('server_public_key',''))" "$cfg" 2>/dev/null || echo "")
  ENDPOINT=$(python3   -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('endpoint',''))" "$cfg" 2>/dev/null || echo "")
  LOCAL_ADDR=$(python3 -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('local_address',''))" "$cfg" 2>/dev/null || echo "")
  PRIV_KEY=$(python3   -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('private_key',''))" "$cfg" 2>/dev/null || echo "")
  ALLOWED=$(python3    -c "import sys,json; d=json.loads(sys.argv[1]); print(','.join(d.get('allowed_ips',[])))" "$cfg" 2>/dev/null || echo "")
  KEEPALIVE=$(python3  -c "import sys,json; d=json.loads(sys.argv[1]); print(d.get('persistent_keepalive',25))" "$cfg" 2>/dev/null || echo "25")

  if [ -z "$SERVER_PUB" ] || [ -z "$ENDPOINT" ]; then
    log "UniFi apply: missing server_public_key or endpoint in config, skipping"
    return 1
  fi

  unifi_login

  local payload
  payload=$(python3 -c "
import json, sys
d = {
  'name': 'FloppyGuard',
  'vpn_type': 'wireguard-client',
  'private_key': sys.argv[1],
  'server_public_key': sys.argv[2],
  'server_address': sys.argv[3],
  'local_wg_address': sys.argv[4],
  'allowed_ips': sys.argv[5].split(',') if sys.argv[5] else [],
  'persistent_keepalive': int(sys.argv[6]),
  'enabled': True
}
print(json.dumps(d))
" "$PRIV_KEY" "$SERVER_PUB" "$ENDPOINT" "$LOCAL_ADDR" "$ALLOWED" "$KEEPALIVE" 2>/dev/null)

  # Check if a FloppyGuard VPN entry already exists
  VPN_ID=$(unifi_find_vpn "FloppyGuard")

  if [ -n "$VPN_ID" ]; then
    # Update existing entry
    curl -sk -b /tmp/fg_unifi_cookie -X PUT \\
      -H "Content-Type: application/json" \\
      -d "$payload" \\
      "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/vpnclient/$VPN_ID" > /dev/null 2>&1 && \\
      log "Updated UniFi WireGuard VPN client (id: $VPN_ID)" || \\
      log "Warning: UniFi VPN update failed"
  else
    # Create new entry
    curl -sk -b /tmp/fg_unifi_cookie -X POST \\
      -H "Content-Type: application/json" \\
      -d "$payload" \\
      "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/vpnclient" > /dev/null 2>&1 && \\
      log "Created UniFi WireGuard VPN client" || \\
      log "Warning: UniFi VPN create failed"
  fi

  # Add firewall rules for each allowed_ip network (traffic policy: accept on WAN_IN)
  # This ensures return traffic from the WireGuard networks is allowed through the firewall
  if [ -n "$ALLOWED" ]; then
    IFS=',' read -ra NETS <<< "$ALLOWED"
    for net in "\${NETS[@]}"; do
      net=$(echo "$net" | tr -d ' ')
      # Check if rule already exists
      EXISTING_RULE=$(curl -sk -b /tmp/fg_unifi_cookie \\
        "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/firewallrule" 2>/dev/null |
        python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('data', [])
for item in items:
    if item.get('name') == 'FG-WG-' + sys.argv[1]:
        print(item.get('_id',''))
        sys.exit(0)
" "$net" 2>/dev/null || echo "")

      if [ -z "$EXISTING_RULE" ]; then
        FW_PAYLOAD=$(python3 -c "
import json, sys
d = {
  'name': 'FG-WG-' + sys.argv[1],
  'ruleset': 'WAN_IN',
  'rule_index': 4100,
  'action': 'accept',
  'enabled': True,
  'protocol': 'all',
  'src_firewallgroup_ids': [],
  'dst_firewallgroup_ids': [],
  'src_address': sys.argv[1],
  'dst_address': '',
  'state_new': True,
  'state_established': True,
  'state_related': True,
  'icmp_typename': ''
}
print(json.dumps(d))
" "$net" 2>/dev/null)
        curl -sk -b /tmp/fg_unifi_cookie -X POST \\
          -H "Content-Type: application/json" \\
          -d "$FW_PAYLOAD" \\
          "$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/firewallrule" > /dev/null 2>&1 && \\
          log "Added firewall rule for WireGuard network $net" || \\
          log "Warning: firewall rule for $net could not be added"
      fi
    done
  fi
}`;

	const applyFunction = mode === "unifi" ? applyFunctionUnifi : applyFunctionNative;

	// For UniFi mode, config applies using JSON; no wg_interface needed in apply call
	const applyCallNative = `apply_config "$CFG" "$IFACE"`;
	const applyCallUnifi = `apply_config "$CFG"`;
	const applyCall = mode === "unifi" ? applyCallUnifi : applyCallNative;

	return `#!/bin/bash
set -euo pipefail
source /etc/floppyguard-agent/config.env

SCRIPT_VERSION="${AGENT_SCRIPT_VERSION}"
HASH_FILE="/var/lib/floppyguard-agent/last_hash"
mkdir -p /var/lib/floppyguard-agent

log() { echo "[$(date -Iseconds)] floppyguard-agent[$AGENT_MODE]: $*" >&2; }
reach() { curl -sf --max-time 5 "$1/api" > /dev/null 2>&1; }
get_server() {
  if reach "$PRIMARY_URL"; then echo "$PRIMARY_URL"; return; fi
  if reach "$FALLBACK_URL"; then echo "$FALLBACK_URL"; return; fi
  echo ""
}
rotate_token() {
  local new_token="$1"
  FGTOKEN="$new_token"
  sed -i "s|^FGTOKEN=.*|FGTOKEN=\\"$new_token\\"|" /etc/floppyguard-agent/config.env
  log "Token rotated to permanent agent_token"
}

${applyFunction}

# ── Service discovery ────────────────────────────────────────────────────────
# port:scheme:fallback_name  (https ports use https scheme)
SCAN_PORTS="80:http:Web 443:https:Web 3000:http:Grafana 8080:http:UniFi Network 8443:https:UniFi Network 8888:http:Management UI 9000:http:Portainer 9443:https:Portainer 9090:http:Prometheus 1880:http:Node-RED 10000:http:Webmin 8000:http:Web UI"

SERVICES_JSON="[]"
SERVICES_SCAN_INTERVAL=86400  # scan once a day
LAST_SCAN=0

scan_services() {
  # Use only LAN IP (default route src) — browser-clickable, not WireGuard IP
  local host_ip
  host_ip=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \\K\\S+' | head -1 || true)
  [ -z "$host_ip" ] && { log "Service scan: no LAN IP found, skipping"; return; }

  local found="[]"
  for entry in $SCAN_PORTS; do
    local port scheme fallback_name
    port=$(echo "$entry" | cut -d: -f1)
    scheme=$(echo "$entry" | cut -d: -f2)
    fallback_name=$(echo "$entry" | cut -d: -f3- | tr ':' ' ')
    # Quick TCP check via curl timeout
    code=$(curl -sk --max-time 2 -o /dev/null -w "%{http_code}" "$scheme://$host_ip:$port/" 2>/dev/null || echo "000")
    [ "$code" = "000" ] && continue
    # Fetch page title — skip if empty or 404-like
    title=$(curl -skL --max-time 4 "$scheme://$host_ip:$port/" 2>/dev/null \\
      | grep -oP '(?<=<title>)[^<]+' | head -1 | tr -d '\\r\\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | cut -c1-60 || true)
    [ -z "$title" ] && continue
    echo "$title" | grep -qiE '^(404|not found|error|default page)' && continue
    url="$scheme://$host_ip:$port"
    found=$(python3 -c "
import sys, json
arr = json.loads(sys.argv[1])
url, name = sys.argv[2], sys.argv[3]
if not any(s['url'] == url for s in arr):
    arr.append({'name': name, 'url': url})
print(json.dumps(arr))
" "$found" "$url" "$title" 2>/dev/null || echo "$found")
  done
  SERVICES_JSON="$found"
  log "Service scan: $(echo "$found" | python3 -c 'import sys,json; a=json.load(sys.stdin); print(len(a))' 2>/dev/null || echo 0) services found on $host_ip"
}

while true; do
  # Periodic service scan
  NOW=$(date +%s)
  if [ $((NOW - LAST_SCAN)) -ge $SERVICES_SCAN_INTERVAL ]; then
    scan_services
    LAST_SCAN=$(date +%s)
  fi

  SERVER=$(get_server)
  if [ -n "$SERVER" ]; then
    RESPONSE=$(curl -sf --max-time 10 \\
      -H "Authorization: Bearer $FGTOKEN" \\
      "$SERVER/api/agent/config" 2>/dev/null) || true

    if [ -n "$RESPONSE" ]; then
      NEW_HASH=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('config_hash') or '')" "$RESPONSE" 2>/dev/null || echo "")
      CURRENT_HASH=$(cat "$HASH_FILE" 2>/dev/null || echo "")
      NEW_TOKEN=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('agent_token') or '')" "$RESPONSE" 2>/dev/null || echo "")

      [ -n "$NEW_TOKEN" ] && [ "$NEW_TOKEN" != "$FGTOKEN" ] && rotate_token "$NEW_TOKEN"

      # ── Script self-update FIRST (before config apply) ─────────────────────────
      # Must run before config apply so agents get bug fixes (like PrivateKey
      # preservation) before attempting to apply a new config.
      SCRIPT_VERSION_SERVER=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('script_version') or '')" "$RESPONSE" 2>/dev/null || echo "")
      if [ -n "$SCRIPT_VERSION_SERVER" ] && [ "$SCRIPT_VERSION_SERVER" != "$SCRIPT_VERSION" ]; then
        log "Script update available ($SCRIPT_VERSION → $SCRIPT_VERSION_SERVER), downloading..."
        HEADERS_FILE=$(mktemp /tmp/fg_headers.XXXXXX)
        NEW_SCRIPT=$(curl -sf --max-time 30 -D "$HEADERS_FILE" \\
          -H "Authorization: Bearer $FGTOKEN" \\
          "$SERVER/api/agent/loop-script" 2>/dev/null) || NEW_SCRIPT=""
        SERVER_SIG=$(grep -i '^X-Script-Signature:' "$HEADERS_FILE" 2>/dev/null | sed 's/^[^:]*: *//' | tr -d '\\r\\n' || echo "")
        rm -f "$HEADERS_FILE"
        if [ -n "$NEW_SCRIPT" ] && echo "$NEW_SCRIPT" | head -1 | grep -q '^#!'; then
          LOCAL_SIG=$(printf '%s' "$NEW_SCRIPT" | openssl dgst -sha256 -hmac "$FGTOKEN" 2>/dev/null | awk '{print $NF}')
          if [ -n "$SERVER_SIG" ] && [ "$LOCAL_SIG" = "$SERVER_SIG" ]; then
            printf '%s\\n' "$NEW_SCRIPT" > /tmp/fg_loop_update
            chmod +x /tmp/fg_loop_update
            cp /tmp/fg_loop_update /usr/local/sbin/floppyguard-agent
            rm -f /tmp/fg_loop_update
            log "Script updated to version $SCRIPT_VERSION_SERVER (signature verified), restarting..."
            exec /usr/local/sbin/floppyguard-agent
          else
            log "Script signature verification failed, rejecting update (expected=$SERVER_SIG got=$LOCAL_SIG)"
          fi
        else
          log "Script update download failed or invalid, skipping"
        fi
      fi

      if [ -n "$NEW_HASH" ] && [ "$NEW_HASH" != "$CURRENT_HASH" ]; then
        CFG=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('config_text') or '')" "$RESPONSE" 2>/dev/null || echo "")
        IFACE=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('wg_interface','wg0'))" "$RESPONSE" 2>/dev/null || echo "wg0")
        if [ -n "$CFG" ]; then
          ${applyCall}
          echo "$NEW_HASH" > "$HASH_FILE"
        fi
      fi

      # ── Upload local config if server has none ──────────────────────────────────
      if [ -z "$NEW_HASH" ]; then
        IFACE=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('wg_interface','wg0'))" "$RESPONSE" 2>/dev/null || echo "wg0")
        CONF_FILE="/etc/wireguard/$IFACE.conf"
        if [ -f "$CONF_FILE" ]; then
          LOCAL_CFG=$(cat "$CONF_FILE" 2>/dev/null | sed 's/PrivateKey = .*/PrivateKey = (hidden)/')
          if [ -n "$LOCAL_CFG" ]; then
            UPLOAD=$(python3 -c "import sys,json; print(json.dumps({'config_text': sys.argv[1]}))" "$LOCAL_CFG" 2>/dev/null || echo "")
            if [ -n "$UPLOAD" ]; then
              curl -sf --max-time 10 -X POST \\
                -H "Authorization: Bearer $FGTOKEN" \\
                -H "Content-Type: application/json" \\
                -d "$UPLOAD" \\
                "$SERVER/api/agent/upload-config" > /dev/null 2>&1 && \\
                log "Uploaded local $IFACE config to hub" || true
            fi
          fi
        fi
      fi

      MY_HOSTNAME=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo "")
      MY_LAN_IP=$(ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \\K\\S+' | head -1 || echo "")
      HEARTBEAT=$(python3 -c "
import sys, json
print(json.dumps({'hash': sys.argv[1], 'server': sys.argv[2], 'services': json.loads(sys.argv[3]), 'hostname': sys.argv[4], 'lan_ip': sys.argv[5], 'script_version': sys.argv[6]}))
" "$NEW_HASH" "$SERVER" "$SERVICES_JSON" "$MY_HOSTNAME" "$MY_LAN_IP" "$SCRIPT_VERSION" 2>/dev/null || echo "{\\"hash\\":\\"$NEW_HASH\\",\\"server\\":\\"$SERVER\\"}")

      curl -sf --max-time 5 -X POST \\
        -H "Authorization: Bearer $FGTOKEN" \\
        -H "Content-Type: application/json" \\
        -d "$HEARTBEAT" \\
        "$SERVER/api/agent/heartbeat" > /dev/null 2>&1 || true
    fi
  else
    log "No server reachable (primary: $PRIMARY_URL, fallback: $FALLBACK_URL)"
  fi
  sleep "$POLL_INTERVAL"
done`;
}

const internalAgent = {
	// ─── Admin methods (JWT-authenticated) ──────────────────────────────────────

	/**
	 * Returns all non-deleted agents (without agent_token for security).
	 *
	 * @returns {Promise<Agent[]>}
	 */
	async getAll() {
		const agents = await Agent.query()
			.where("is_deleted", 0)
			.select(
				"id",
				"name",
				"hostname",
				"wg_interface",
				"config_text",
				"config_hash",
				"mgmt_url",
				"services",
				"wg_link_name",
				"reg_token",
				"last_seen",
				"status",
				"agent_version",
				"allowed_sites",
				"allowed_networks",
				"created_on",
				"modified_on",
			)
			.orderBy("created_on", "asc");
		return agents.map(parseAgentServices);
	},

	/**
	 * Returns a single agent by id (without agent_token).
	 *
	 * @param {number} id
	 * @returns {Promise<Agent>}
	 */
	async getById(id) {
		const agent = await Agent.query()
			.where("id", id)
			.where("is_deleted", 0)
			.select(
				"id",
				"name",
				"hostname",
				"wg_interface",
				"config_text",
				"config_hash",
				"mgmt_url",
				"services",
				"wg_link_name",
				"reg_token",
				"last_seen",
				"status",
				"agent_version",
				"allowed_sites",
				"allowed_networks",
				"created_on",
				"modified_on",
			)
			.first();

		if (!agent) {
			throw new error.ItemNotFoundError(id);
		}

		return parseAgentServices(agent);
	},

	/**
	 * Creates a new agent with a fresh reg_token. Returns the full record
	 * including reg_token (shown once).
	 *
	 * @param {Object} data
	 * @returns {Promise<Agent>}
	 */
	async create(data) {
		if (data.wg_link_name) {
			const metadata = await internalWireGuard.readMetadataStore();
			const matches = Object.values(metadata.links || {}).filter((l) => l.name === data.wg_link_name);
			if (matches.length > 1) {
				throw new error.ValidationError(
					`wg_link_name "${data.wg_link_name}" matches ${matches.length} links — resolve duplicate link names before assigning`,
				);
			}
		}

		const reg_token = randomToken(32);
		const config_hash = hashConfig(data.config_text);

		const agent = await Agent.query().insertAndFetch({
			name: data.name,
			mode: data.mode || "native",
			reg_token,
			agent_token: null,
			hostname: data.hostname || null,
			wg_interface: data.wg_interface || "wg0",
			config_text: data.config_text || null,
			config_hash,
			mgmt_url: data.mgmt_url || null,
			wg_link_name: data.wg_link_name || null,
			unifi_url: data.unifi_url || null,
			unifi_user: data.unifi_user || null,
			unifi_pass: data.unifi_pass || null,
			unifi_site: data.unifi_site || "default",
			last_seen: null,
			status: "pending",
			is_deleted: false,
		});

		return agent;
	},

	/**
	 * Updates name, wg_interface, and/or config_text. Recalculates config_hash
	 * when config_text changes.
	 *
	 * @param {number}  id
	 * @param {Object}  data
	 * @returns {Promise<Agent>}
	 */
	async update(id, data) {
		const existing = await Agent.query().where("id", id).where("is_deleted", 0).first();

		if (!existing) {
			throw new error.ItemNotFoundError(id);
		}

		if (data.wg_link_name && data.wg_link_name !== existing.wg_link_name) {
			const metadata = await internalWireGuard.readMetadataStore();
			const matches = Object.values(metadata.links || {}).filter((l) => l.name === data.wg_link_name);
			if (matches.length > 1) {
				throw new error.ValidationError(
					`wg_link_name "${data.wg_link_name}" matches ${matches.length} links — resolve duplicate link names before assigning`,
				);
			}
		}

		const patch = {};

		if (typeof data.name !== "undefined") {
			patch.name = data.name;
		}
		if (typeof data.wg_interface !== "undefined") {
			patch.wg_interface = data.wg_interface;
		}
		if (typeof data.mode !== "undefined") patch.mode = data.mode;
		if (typeof data.config_text !== "undefined") {
			patch.config_text = data.config_text;
			patch.config_hash = hashConfig(data.config_text);
		}
		if (typeof data.mgmt_url !== "undefined") patch.mgmt_url = data.mgmt_url || null;
		if (typeof data.wg_link_name !== "undefined") patch.wg_link_name = data.wg_link_name || null;
		if (typeof data.unifi_url !== "undefined") patch.unifi_url = data.unifi_url;
		if (typeof data.unifi_user !== "undefined") patch.unifi_user = data.unifi_user;
		if (typeof data.unifi_pass !== "undefined") patch.unifi_pass = data.unifi_pass;
		if (typeof data.unifi_site !== "undefined") patch.unifi_site = data.unifi_site;
		if (typeof data.allowed_sites !== "undefined") {
			patch.allowed_sites = Array.isArray(data.allowed_sites) ? JSON.stringify(data.allowed_sites) : null;
		}
		if (typeof data.allowed_networks !== "undefined") {
			patch.allowed_networks = Array.isArray(data.allowed_networks) ? JSON.stringify(data.allowed_networks) : null;
		}

		await Agent.query().patchAndFetchById(id, patch);

		return this.getById(id);
	},

	/**
	 * Soft-deletes an agent.
	 *
	 * @param {number} id
	 * @returns {Promise<boolean>}
	 */
	async delete(id) {
		const existing = await Agent.query().where("id", id).where("is_deleted", 0).first();

		if (!existing) {
			throw new error.ItemNotFoundError(id);
		}

		await Agent.query().patchAndFetchById(id, { is_deleted: true });
		return true;
	},

	/**
	 * Generates a fresh reg_token for an existing agent so it can be reinstalled.
	 * Clears agent_token and resets status to pending.
	 *
	 * @param {number} id
	 * @returns {Promise<{ reg_token: string }>}
	 */
	async resetToken(id) {
		const existing = await Agent.query().where("id", id).where("is_deleted", 0).first();

		if (!existing) {
			throw new error.ItemNotFoundError(id);
		}

		const reg_token = randomToken(32);
		await Agent.query().patchAndFetchById(id, {
			reg_token,
			agent_token: null,
			status: "pending",
		});

		return this.getById(id);
	},

	/**
	 * Returns a bash install script for the agent as a plain-text string.
	 *
	 * @param {number} id
	 * @param {string} publicUrl   e.g. "https://proxy.example.com"
	 * @param {string} tunnelUrl   e.g. "http://10.8.0.1:3300"
	 * @returns {Promise<string>}
	 */
	async getInstallScript(id, publicUrl, tunnelUrl) {
		// Validate URLs to prevent shell injection in the generated bash script.
		// publicUrl and tunnelUrl are interpolated into double-quoted strings in the
		// install script; characters like $, `, ; would be evaluated by bash.
		for (const [label, url] of [["public_url", publicUrl], ["tunnel_url", tunnelUrl]]) {
			if (!url) continue;
			try {
				const parsed = new URL(url);
				if (!["http:", "https:"].includes(parsed.protocol)) {
					throw new error.ValidationError(`${label} must use http or https protocol`);
				}
			} catch (err) {
				if (err instanceof error.ValidationError) throw err;
				throw new error.ValidationError(`${label} is not a valid URL`);
			}
			if (/[$`\\;|&(){}<>!#]/.test(url)) {
				throw new error.ValidationError(`${label} contains characters unsafe for shell interpolation`);
			}
		}

		const agent = await Agent.query().where("id", id).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.ItemNotFoundError(id);
		}

		const regToken = agent.reg_token || "";
		const wgInterface = agent.wg_interface || "wg0";
		const mode = agent.mode || "native";
		const unifiUrl = agent.unifi_url || "";
		const unifiUser = agent.unifi_user || "";
		const unifiPass = agent.unifi_pass || "";
		const unifiSite = agent.unifi_site || "default";

		// Extra env vars for UniFi mode
		const unifiEnvLines =
			mode === "unifi"
				? `UNIFI_URL="${unifiUrl}"\nUNIFI_USER="${unifiUser}"\nUNIFI_PASS="${unifiPass}"\nUNIFI_SITE="${unifiSite}"\n`
				: "";

		const loopScript = buildLoopScript(mode);

		const installScript = `#!/bin/bash
set -euo pipefail

echo "[floppyguard-agent] Installing FloppyGuard agent (mode: ${mode}, ID: ${id})..."

# ── 1. Directories ──────────────────────────────────────────────────────────────
mkdir -p /etc/floppyguard-agent /var/lib/floppyguard-agent

# ── 2. config.env ───────────────────────────────────────────────────────────────
cat > /etc/floppyguard-agent/config.env << 'ENVEOF'
FGTOKEN="${regToken}"
PRIMARY_URL="${tunnelUrl}"
FALLBACK_URL="${publicUrl}"
FGAGENT_ID="${id}"
AGENT_MODE="${mode}"
WG_INTERFACE="${wgInterface}"
POLL_INTERVAL=30
${unifiEnvLines}ENVEOF
chmod 600 /etc/floppyguard-agent/config.env

# ── 3. Initial registration ─────────────────────────────────────────────────────
echo "[floppyguard-agent] Registering with FloppyGuard..."
REGISTER_RESPONSE=$(curl -sf --max-time 15 \\
  -X POST -H "Content-Type: application/json" \\
  -d '{"reg_token":"${regToken}"}' \\
  "${publicUrl}/api/agent/register" 2>/dev/null) || true

if [ -n "$REGISTER_RESPONSE" ]; then
  AGENT_TOKEN=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('agent_token',''))" "$REGISTER_RESPONSE" 2>/dev/null || echo "")
  if [ -n "$AGENT_TOKEN" ]; then
    sed -i "s|^FGTOKEN=.*|FGTOKEN=\\"$AGENT_TOKEN\\"|" /etc/floppyguard-agent/config.env
    echo "[floppyguard-agent] Registration successful."
  else
    echo "[floppyguard-agent] Warning: no agent_token in response; will retry on first poll."
  fi
else
  echo "[floppyguard-agent] Warning: registration unreachable; will retry on first poll."
fi

# ── 4. Agent loop script ────────────────────────────────────────────────────────
cat > /usr/local/sbin/floppyguard-agent << 'SCRIPTEOF'
${loopScript}
SCRIPTEOF
chmod +x /usr/local/sbin/floppyguard-agent

# ── 5. Systemd unit ─────────────────────────────────────────────────────────────
cat > /etc/systemd/system/floppyguard-agent.service << 'UNITEOF'
[Unit]
Description=FloppyGuard Remote Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/sbin/floppyguard-agent
Restart=always
RestartSec=15
StandardOutput=journal
StandardError=journal
SyslogIdentifier=floppyguard-agent

[Install]
WantedBy=multi-user.target
UNITEOF

# ── 6. Enable + start ───────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now floppyguard-agent

echo ""
echo "[floppyguard-agent] Done. Mode: ${mode}"
echo "[floppyguard-agent]   systemctl status floppyguard-agent"
echo "[floppyguard-agent]   journalctl -u floppyguard-agent -f"
`;

		return installScript;
	},

	/**
	 * Same as getInstallScript but looks up the agent by reg_token (no JWT needed).
	 *
	 * @param {string} regToken
	 * @param {string} publicUrl
	 * @param {string} tunnelUrl
	 * @returns {Promise<string>}
	 */
	async getInstallScriptByToken(regToken, publicUrl, tunnelUrl) {
		const agent = await Agent.query().where("reg_token", regToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid registration token", "error.auth");
		}

		return this.getInstallScript(agent.id, publicUrl, tunnelUrl);
	},

	// ─── Agent methods (agent-token-authenticated) ──────────────────────────────

	/**
	 * Exchanges a reg_token for a permanent agent_token. Nulls reg_token after use.
	 * Returns { agent_token, config_hash }.
	 *
	 * @param {string} regToken
	 * @returns {Promise<{ agent_token: string, config_hash: string|null }>}
	 */
	async register(regToken) {
		const agent = await Agent.query().where("reg_token", regToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid registration token", "error.auth");
		}

		const agent_token = randomToken(32);

		await Agent.query().patchAndFetchById(agent.id, {
			agent_token,
			reg_token: null,
			status: "active",
		});

		return {
			agent_token,
			agent_id: agent.id,
			config_hash: agent.config_hash || null,
		};
	},

	/**
	 * Returns config for the agent identified by agent_token.
	 *
	 * @param {string} agentToken
	 * @returns {Promise<{ config_text: string|null, config_hash: string|null, wg_interface: string, poll_interval: number }>}
	 */
	async getConfig(agentToken) {
		const agent = await Agent.query().where("agent_token", agentToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid agent token", "error.auth");
		}

		return {
			config_text: agent.config_text || null,
			config_hash: agent.config_hash || null,
			wg_interface: agent.wg_interface || "wg0",
			poll_interval: 30,
			script_version: AGENT_SCRIPT_VERSION,
		};
	},

	/**
	 * Returns the loop script for the agent identified by agent_token.
	 *
	 * @param {string} agentToken
	 * @returns {Promise<string>}
	 */
	async getLoopScript(agentToken) {
		const agent = await Agent.query().where("agent_token", agentToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid agent token", "error.auth");
		}

		const script = buildLoopScript(agent.mode || "native");
		const signature = signScript(script, agentToken);
		return { script, signature };
	},

	/**
	 * Updates last_seen and status for the agent.
	 *
	 * @param {string} agentToken
	 * @param {Object} data  — { hash, server }
	 * @returns {Promise<{ ok: boolean }>}
	 */
	async heartbeat(agentToken, data) {
		const agent = await Agent.query().where("agent_token", agentToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid agent token", "error.auth");
		}

		const patch = {
			last_seen: Math.floor(Date.now() / 1000),
			status: "active",
		};

		if (data?.hostname) {
			// Include LAN IP in hostname field if available (used for service discovery)
			const lanIp = data.lan_ip ? ` (${data.lan_ip})` : "";
			patch.hostname = `${data.hostname}${lanIp}`;
		}

		if (data && Array.isArray(data.services)) {
			patch.services = JSON.stringify(data.services);
		}

		if (data?.script_version) {
			patch.agent_version = String(data.script_version);
		}

		await Agent.query().patchAndFetchById(agent.id, patch);

		return { ok: true };
	},

	/**
	 * Accepts a config_text upload from an agent. Only stores it if the server
	 * has no config_text for this agent yet (prevents agents from overwriting
	 * server-managed configs).
	 *
	 * @param {string} agentToken
	 * @param {Object} data  — { config_text: string }
	 * @returns {Promise<{ ok: boolean, stored: boolean }>}
	 */
	async uploadConfig(agentToken, data) {
		const agent = await Agent.query().where("agent_token", agentToken).where("is_deleted", 0).first();

		if (!agent) {
			throw new error.AuthError("Invalid agent token", "error.auth");
		}

		if (agent.config_text) {
			return { ok: true, stored: false, reason: "config-already-exists" };
		}

		if (!data?.config_text?.trim()) {
			return { ok: true, stored: false, reason: "empty-config" };
		}

		const normalized = normalizeAgentConfig(data.config_text);
		const config_hash = hashConfig(normalized);
		await Agent.query().patchAndFetchById(agent.id, {
			config_text: normalized,
			config_hash,
		});

		logger.info(`Agent ${agent.name} (id=${agent.id}) uploaded initial config (normalized)`);
		return { ok: true, stored: true };
	},

	/**
	 * Syncs the hub-peer AllowedIPs in each agent's config_text from WireGuard metadata.
	 *
	 * For every agent that has a wg_link_name:
	 *   - Find the matching link in metadata by name
	 *   - Compute new AllowedIPs for the hub peer:
	 *       = (WG-specific entries currently in the config, i.e. not tracked by any link's importedNetworks)
	 *       + (importedNetworks of ALL OTHER links except this agent's own link)
	 *   - If AllowedIPs changed: update config_text + config_hash in DB
	 *
	 * Agents pick up the change automatically on their next poll (every 30 s).
	 *
	 * @param {Object} metadata  — { interfaces, links } from wireguard-metadata.json
	 * @returns {Promise<Array<{ agentId: number, name: string, changed: boolean, newAllowedIPs?: string[] }>>}
	 */
	async syncAgentConfigs(metadata) {
		const agents = await Agent.query().where("is_deleted", 0).whereNotNull("wg_link_name");

		// Detect duplicate link names — if two links share a name, any agent with that
		// wg_link_name is ambiguous and must not receive a potentially wrong config update.
		const nameCount = new Map();
		for (const linkMeta of Object.values(metadata.links || {})) {
			if (linkMeta.name) nameCount.set(linkMeta.name, (nameCount.get(linkMeta.name) || 0) + 1);
		}
		const ambiguousLinkNames = new Set([...nameCount.entries()].filter(([, c]) => c > 1).map(([n]) => n));

		// Index links by name → linkMeta (only for unambiguous names)
		const linksByName = new Map();
		for (const linkMeta of Object.values(metadata.links || {})) {
			if (linkMeta.name && !ambiguousLinkNames.has(linkMeta.name)) {
				linksByName.set(linkMeta.name, linkMeta);
			}
		}

		// Union of ALL importedNetworks across all links — used to identify "site networks"
		const allSiteNets = new Set(Object.values(metadata.links || {}).flatMap((l) => l.importedNetworks || []));

		const results = [];

		for (const agent of agents) {
			if (ambiguousLinkNames.has(agent.wg_link_name)) {
				results.push({ agentId: agent.id, name: agent.name, changed: false, reason: "ambiguous-link-name" });
				continue;
			}
			const linkMeta = linksByName.get(agent.wg_link_name);
			if (!linkMeta || !agent.config_text) {
				results.push({ agentId: agent.id, name: agent.name, changed: false, reason: "no-link-or-config" });
				continue;
			}

			// Networks belonging to THIS agent's own site (don't route these through hub)
			const ownNets = new Set(linkMeta.importedNetworks || []);

			// ── Network access control (deny-by-default when configured) ──
			// Priority: allowed_networks > allowed_sites > full-mesh
			// 1. allowed_networks: explicit list of CIDRs this agent may route
			//    (most granular, e.g. ["192.168.10.0/24"] — only that subnet)
			// 2. allowed_sites: whitelist of link names whose networks are allowed
			//    (site-level, e.g. ["Floppy Home"] — all of that link's networks)
			// 3. Neither set: full-mesh (all other links' networks)
			const allowedNetworks = _parseAllowedSites(agent.allowed_networks);
			const allowedSites = _parseAllowedSites(agent.allowed_sites);

			let otherSiteNets;
			if (allowedNetworks) {
				// Explicit network list — use directly, skip own networks
				otherSiteNets = [...allowedNetworks].filter((n) => !ownNets.has(n));
			} else {
				// Site-level or full-mesh filtering
				otherSiteNets = [...allSiteNets].filter((n) => {
					if (ownNets.has(n)) return false;
					if (!allowedSites) return true; // no whitelist = full mesh
					for (const [, lm] of linksByName) {
						if (allowedSites.has(lm.name) && (lm.importedNetworks || []).includes(n)) return true;
					}
					return false;
				});
			}

			// Parse current AllowedIPs from the hub peer in config_text
			const currentAllowedIPs = _parseHubPeerAllowedIPs(agent.config_text);

			// The tunnel subnet (derived from this agent's Address) must ALWAYS remain
			// in AllowedIPs — without it the agent can't communicate with the hub or
			// other peers and the tunnel collapses.
			const agentTunnelSubnet = deriveTunnelSubnet(agent.config_text);

			// Preserve WG-specific entries not covered by any link's metadata or the tunnel subnet
			const wgSpecific = currentAllowedIPs.filter((ip) => !allSiteNets.has(ip) && ip !== agentTunnelSubnet);

			const newAllowedIPs = [...new Set([agentTunnelSubnet, ...wgSpecific, ...otherSiteNets])];
			newAllowedIPs.sort();
			const newSorted = newAllowedIPs.join(",");
			const currentSorted = [...currentAllowedIPs].sort().join(",");

			// Compute which remote networks need MASQUERADE on this agent's LAN.
			// These are all networks routed TO this agent (i.e. from other sites)
			// that arrive via wg and exit to the local LAN — without MASQUERADE the
			// local devices can't reply (they don't know the route back).
			const masqueradeNets = otherSiteNets.filter((n) => !ownNets.has(n));
			masqueradeNets.sort();

			// Re-normalize config even if AllowedIPs didn't change — PostUp rules
			// (MASQUERADE for remote site networks) may have changed.
			const rewritten = newSorted !== currentSorted
				? _rewriteHubPeerAllowedIPs(agent.config_text, newAllowedIPs)
				: agent.config_text;
			const newConfigText = normalizeAgentConfig(rewritten, masqueradeNets);
			const newHash = hashConfig(newConfigText);

			if (newHash === agent.config_hash) {
				results.push({ agentId: agent.id, name: agent.name, changed: false });
				continue;
			}

			await Agent.query().patchAndFetchById(agent.id, {
				config_text: newConfigText,
				config_hash: newHash,
			});

			results.push({ agentId: agent.id, name: agent.name, changed: true, newAllowedIPs, masqueradeNets });
		}

		return results;
	},
};

/**
 * Returns the AllowedIPs of the hub peer (first [Peer] section) from a wg-quick config string.
 */
function _parseHubPeerAllowedIPs(configText) {
	let inPeer = false;
	for (const raw of configText.split(/\r?\n/)) {
		const t = raw.trim();
		if (t === "[Peer]") {
			inPeer = true;
			continue;
		}
		if (t.startsWith("[")) {
			inPeer = false;
			continue;
		}
		if (inPeer && t.startsWith("AllowedIPs")) {
			return t
				.slice(t.indexOf("=") + 1)
				.trim()
				.split(",")
				.map((s) => s.trim())
				.filter(Boolean);
		}
	}
	return [];
}

/**
 * Rewrites the AllowedIPs of the first [Peer] section in a wg-quick config string.
 */
function _rewriteHubPeerAllowedIPs(configText, newAllowedIPs) {
	let inPeer = false;
	let replaced = false;
	return configText
		.split(/\r?\n/)
		.map((raw) => {
			const t = raw.trim();
			if (t === "[Peer]") {
				inPeer = true;
				return raw;
			}
			if (t.startsWith("[")) {
				inPeer = false;
				return raw;
			}
			if (inPeer && !replaced && t.startsWith("AllowedIPs")) {
				replaced = true;
				return `AllowedIPs = ${newAllowedIPs.join(", ")}`;
			}
			return raw;
		})
		.join("\n");
}

/**
 * Parses the allowed_sites JSON column. Returns a Set of link names,
 * or null if the field is empty/unset (meaning full-mesh, all sites allowed).
 */
function _parseAllowedSites(raw) {
	if (!raw) return null;
	try {
		const parsed = JSON.parse(raw);
		if (!Array.isArray(parsed) || parsed.length === 0) return null;
		return new Set(parsed.map((s) => String(s).trim()).filter(Boolean));
	} catch {
		return null;
	}
}

export default internalAgent;

// Exported for unit testing only
export const _testExports = {
	buildHubPostUp,
	buildHubPostDown,
	deriveTunnelSubnet,
	normalizeAgentConfig,
	_parseHubPeerAllowedIPs,
	_rewriteHubPeerAllowedIPs,
	_parseAllowedSites,
	assertCIDR,
};
