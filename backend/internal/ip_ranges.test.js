// The 6-hourly IP-ranges refresh must not reload nginx when nothing changed:
// each reload strands old workers until their websocket clients disconnect.
import assert from "node:assert/strict";
import fs from "node:fs";
import { describe, it } from "node:test";

const { default: internalIpRanges } = await import("./ip_ranges.js");
const { default: internalNginx } = await import("./nginx.js");

const CONF = "/etc/nginx/conf.d/include/ip_ranges.conf";

function setup(t, currentConf) {
	const state = { written: null, reloads: 0 };
	t.mock.method(internalIpRanges, "fetchUrl", async (url) => {
		if (url.includes("amazonaws")) {
			return JSON.stringify({
				prefixes: [{ service: "CLOUDFRONT", ip_prefix: "13.32.0.0/15" }],
				ipv6_prefixes: [{ service: "CLOUDFRONT", ipv6_prefix: "2600:9000::/28" }],
			});
		}
		return url.endsWith("v4") ? "173.245.48.0/20\n" : "2400:cb00::/32\n";
	});
	t.mock.method(internalNginx, "reload", async () => {
		state.reloads++;
	});
	const realRead = fs.readFileSync;
	t.mock.method(fs, "readFileSync", (file, ...rest) => {
		if (file === CONF) {
			if (currentConf === null) throw Object.assign(new Error("ENOENT"), { code: "ENOENT" });
			return currentConf;
		}
		return realRead(file, ...rest);
	});
	t.mock.method(fs, "writeFileSync", (file, text) => {
		assert.equal(file, CONF);
		state.written = text;
	});
	internalIpRanges.iteration_count = 1;
	internalIpRanges.interval_processing = false;
	return state;
}

describe("ip_ranges fetch", () => {
	let rendered = null;

	it("writes and reloads when the ranges changed", async (t) => {
		const state = setup(t, "# old\n");
		await internalIpRanges.fetch();
		assert.match(state.written, /173\.245\.48\.0\/20/);
		assert.match(state.written, /2600:9000::\/28/);
		assert.equal(state.reloads, 1);
		rendered = state.written;
	});

	it("writes (no reload on first iteration) when the file is missing", async (t) => {
		const state = setup(t, null);
		internalIpRanges.iteration_count = 0;
		await internalIpRanges.fetch();
		assert.equal(state.written, rendered);
		assert.equal(state.reloads, 0);
	});

	it("skips write and reload when the rendered conf is unchanged", async (t) => {
		const state = setup(t, rendered);
		await internalIpRanges.fetch();
		assert.equal(state.written, null);
		assert.equal(state.reloads, 0);
		assert.equal(internalIpRanges.interval_processing, false);
	});
});
