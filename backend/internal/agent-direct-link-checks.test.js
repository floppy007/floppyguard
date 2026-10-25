import assert from "node:assert/strict";
import test from "node:test";
import {
	endpointIpv4,
	evaluateDirectChecks,
	sanitizePublicHost,
	siteRouterSettings,
} from "./agent-direct-link-rules.js";

const okSide = { stale: false, public_key_known: true, up: true, path: "direct", handshake_age: 30, rtt_ms: 61.2 };
const view = (over = {}) => ({
	id: 1,
	name: "Floppy Home <-> Hinderlich",
	agent_a_id: 2,
	agent_b_id: 1,
	enabled: true,
	blocked: null,
	endpoint_host: "178.15.234.18",
	listen_port: 51830,
	status_a: { ...okSide },
	status_b: { ...okSide },
	...over,
});
const byCode = (r) => Object.fromEntries(r.checks.map((c) => [c.code, c]));

test("sanitizePublicHost: DynDNS name, fixed IPv4, empty → null, garbage rejected", () => {
	assert.equal(sanitizePublicHost(" Dyn-Daniel.Comnic.de "), "dyn-daniel.comnic.de");
	assert.equal(sanitizePublicHost("178.15.234.18"), "178.15.234.18");
	assert.equal(sanitizePublicHost(""), null);
	assert.equal(sanitizePublicHost(null), null);
	assert.equal(sanitizePublicHost(undefined), null);
	assert.throws(() => sanitizePublicHost("1.2.3.999"));
	assert.throws(() => sanitizePublicHost("evil host;rm"));
	assert.throws(() => sanitizePublicHost(42));
});

test("endpointIpv4: wg endpoint with port; IPv6 / none → null", () => {
	assert.equal(endpointIpv4("77.12.40.232:51820"), "77.12.40.232");
	assert.equal(endpointIpv4("[2a00::1]:51820"), null);
	assert.equal(endpointIpv4(null), null);
	assert.equal(endpointIpv4("300.1.1.1:5"), null);
});

test("all good: fixed IP endpoint, hub sees the same IP, fresh handshake, both direct", () => {
	const r = evaluateDirectChecks({
		link: view(),
		publicIpA: "178.15.234.18",
		resolved: ["178.15.234.18"],
		publicHostA: null,
	});
	assert.equal(r.state, "ok");
	const c = byCode(r);
	assert.equal(c.dns.state, "skip");
	assert.equal(c["public-ip"].state, "ok");
	assert.equal(c["port-forward"].state, "ok");
	assert.equal(c.path.state, "ok");
});

test("DynDNS stale: name resolves to an old IP → public-ip fails", () => {
	const r = evaluateDirectChecks({
		link: view({ endpoint_host: "dyn-daniel.comnic.de" }),
		publicIpA: "77.12.40.232",
		resolved: ["78.51.246.72"],
		publicHostA: "dyn-daniel.comnic.de",
	});
	const c = byCode(r);
	assert.equal(c.dns.state, "ok");
	assert.equal(c["public-ip"].state, "fail");
	assert.equal(c["public-ip"].values.seen, "77.12.40.232");
	assert.equal(r.state, "fail");
});

test("DNS lookup failed → dns fails", () => {
	const r = evaluateDirectChecks({
		link: view({ endpoint_host: "nix.example" }),
		publicIpA: null,
		resolved: null,
		publicHostA: null,
	});
	assert.equal(byCode(r).dns.state, "fail");
	assert.equal(byCode(r)["public-ip"].state, "skip");
});

test("no handshake on the direct tunnel → port forward fails, path fails", () => {
	const down = { stale: false, public_key_known: true, up: false, path: "hub", handshake_age: null };
	const r = evaluateDirectChecks({
		link: view({ status_a: down, status_b: down }),
		publicIpA: "178.15.234.18",
		resolved: null,
		publicHostA: null,
	});
	const c = byCode(r);
	assert.equal(c["port-forward"].state, "fail");
	assert.equal(c["port-forward"].values.port, 51830);
	assert.equal(c.path.state, "fail");
});

test("old handshake (> 180 s) does not count as working", () => {
	const old = { ...okSide, handshake_age: 600, path: "hub" };
	const r = evaluateDirectChecks({
		link: view({ status_a: old, status_b: old }),
		publicIpA: null,
		resolved: null,
		publicHostA: null,
	});
	assert.equal(byCode(r)["port-forward"].state, "fail");
});

test("disabled link: warn, port forward / path skipped", () => {
	const r = evaluateDirectChecks({
		link: view({ enabled: false }),
		publicIpA: "178.15.234.18",
		resolved: null,
		publicHostA: null,
	});
	const c = byCode(r);
	assert.equal(c.enabled.state, "warn");
	assert.equal(c["port-forward"].state, "skip");
	assert.equal(c.path.state, "skip");
});

test("endpoint differs from the site's stored public address → warn", () => {
	const r = evaluateDirectChecks({
		link: view(),
		publicIpA: "178.15.234.18",
		resolved: null,
		publicHostA: "hinderlich.example.de",
	});
	assert.equal(byCode(r)["endpoint-differs"].state, "warn");
});

test("siteRouterSettings: side A needs a port forward, side B dials out", () => {
	const links = [
		view(),
		view({
			id: 2,
			name: "Floppy <-> Daniel",
			agent_a_id: 5,
			agent_b_id: 1,
			endpoint_host: "dyn-daniel.comnic.de",
			listen_port: 51831,
		}),
	];
	const hinderlich = siteRouterSettings(2, links);
	assert.deepEqual(
		hinderlich.forwards.map((f) => f.port),
		[51830],
	);
	assert.equal(hinderlich.outgoing.length, 0);
	const floppy = siteRouterSettings(1, links);
	assert.equal(floppy.forwards.length, 0);
	assert.deepEqual(
		floppy.outgoing.map((o) => o.endpoint),
		["178.15.234.18:51830", "dyn-daniel.comnic.de:51831"],
	);
});
