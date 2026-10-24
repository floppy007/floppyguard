import assert from "node:assert/strict";
import { describe, it } from "node:test";
import cloudflareDns from "./cloudflare-dns.js";

describe("cloudflare findZone", () => {
	const mockZones = (t) => {
		const requested = [];
		t.mock.method(globalThis, "fetch", async (url) => {
			const name = new URL(url).searchParams.get("name");
			requested.push(name);
			return {
				ok: true,
				status: 200,
				json: async () => ({
					success: true,
					result: name === "example.com" ? [{ id: "z", name: "example.com" }] : [],
				}),
			};
		});
		return requested;
	};

	it("finds the zone of an apex domain", async (t) => {
		const requested = mockZones(t);
		const zone = await cloudflareDns._findZone("tok", "example.com");
		assert.equal(zone.name, "example.com");
		assert.deepEqual(requested, ["example.com"]);
	});

	it("tries the longest candidate first", async (t) => {
		const requested = mockZones(t);
		const zone = await cloudflareDns._findZone("tok", "www.example.com");
		assert.equal(zone.name, "example.com");
		assert.deepEqual(requested, ["www.example.com", "example.com"]);
	});

	it("reuses zone lookups across the domains of one sync", async (t) => {
		const requested = mockZones(t);
		const cache = new Map();
		await cloudflareDns._findZone("tok", "a.example.com", cache);
		const zone = await cloudflareDns._findZone("tok", "b.example.com", cache);
		assert.equal(zone.name, "example.com");
		assert.deepEqual(requested, ["a.example.com", "example.com", "b.example.com"]);
	});

	it("never queries a bare TLD", async (t) => {
		const requested = mockZones(t);
		await assert.rejects(() => cloudflareDns._findZone("tok", "com"), /No Cloudflare zone is available/);
		await assert.rejects(() => cloudflareDns._findZone("tok", "nozone.test"), /No Cloudflare zone is available/);
		assert.deepEqual(requested, ["nozone.test"]);
	});
});
