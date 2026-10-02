// Regression tests for the 2026-10 audit fixes (OIDC flow binding, token
// refresh, rate limiter cleanup, debug flag, updater status, bandwidth history).
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, it } from "node:test";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fg-audit-"));
// Never touch the live /data rate-limit DB or OIDC config from tests.
process.env.DATA_DIR = tmp;
process.env.OIDC_CONFIG_PATH = path.join(tmp, "oidc.json");

const { _testExports: oidcInternals } = await import("./oidc.js");
const { readCookie, sanitizeProviderError } = await import("../routes/oidc.js");
const { default: rateLimit } = await import("../lib/express/rate-limit.js");
const { isDebugMode } = await import("../lib/config.js");
const { default: internalToken } = await import("./token.js");
const { _testExports: appUpdateInternals } = await import("./app-update.js");
const { bandwidthBucketStart, counterDelta } = await import("./wireguard.js");

after(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe("OIDC flow sealing", () => {
	const { seal, unseal } = oidcInternals;

	it("round-trips a sealed payload of the same kind", () => {
		const v = seal("flow", { state: "abc", verifier: "xyz" });
		const out = unseal("flow", v, 60_000);
		assert.equal(out.state, "abc");
		assert.equal(out.verifier, "xyz");
	});

	it("rejects another kind, tampering, garbage and expiry", () => {
		const v = seal("flow", { state: "abc" });
		assert.equal(unseal("result", v, 60_000), null);
		const flipped = `${v.slice(0, -2)}${v.at(-2) === "A" ? "B" : "A"}${v.at(-1)}`;
		assert.equal(unseal("flow", flipped, 60_000), null);
		assert.equal(unseal("flow", "not-a-cookie", 60_000), null);
		assert.equal(unseal("flow", "", 60_000), null);
		assert.equal(unseal("flow", undefined, 60_000), null);
		assert.equal(unseal("flow", v, -1), null);
	});
});

describe("OIDC route helpers", () => {
	it("reads a cookie by exact name", () => {
		const req = { headers: { cookie: "a=1; fg_oidc_flow=abc%2Bdef; fg_oidc_flowx=no" } };
		assert.equal(readCookie(req, "fg_oidc_flow"), "abc+def");
		assert.equal(readCookie(req, "missing"), "");
		assert.equal(readCookie({ headers: {} }, "a"), "");
	});

	it("strips CR/LF and non-code characters from provider errors", () => {
		assert.equal(sanitizeProviderError("access_denied"), "access_denied");
		assert.equal(
			sanitizeProviderError("x\n[Express] info OIDC: admin@corp angemeldet"),
			"xExpressinfoOIDCadmincorpangemeldet",
		);
		assert.equal(sanitizeProviderError(["a\r\nb", "c"]), "ab");
		assert.ok(sanitizeProviderError("a".repeat(500)).length <= 64);
	});
});

describe("rate limiter", () => {
	const call = (limiter, ip) =>
		new Promise((resolve) => {
			const res = {
				statusCode: 200,
				set() {},
				status(code) {
					this.statusCode = code;
					return this;
				},
				json() {
					resolve(this.statusCode);
				},
			};
			limiter({ ip }, res, () => resolve(200));
		});

	it("a short-window limiter's cleanup does not wipe other buckets", async () => {
		rateLimit({ windowMs: 40, max: 1000, bucket: "short-window" });
		const login = rateLimit({ windowMs: 60 * 60 * 1000, max: 2, bucket: "long-window" });
		assert.equal(await call(login, "198.51.100.7"), 200);
		await new Promise((r) => setTimeout(r, 150)); // several short-window cleanups
		assert.equal(await call(login, "198.51.100.7"), 200);
		assert.equal(await call(login, "198.51.100.7"), 429);
	});
});

describe("debug flag", () => {
	it("DEBUG=false does not enable debug mode", () => {
		const before = process.env.DEBUG;
		try {
			for (const off of ["false", "0", "no", "", "off"]) {
				process.env.DEBUG = off;
				assert.equal(isDebugMode(), false, off);
			}
			for (const on of ["true", "1", "yes", "TRUE"]) {
				process.env.DEBUG = on;
				assert.equal(isDebugMode(), true, on);
			}
		} finally {
			if (before === undefined) delete process.env.DEBUG;
			else process.env.DEBUG = before;
		}
	});
});

describe("token refresh", () => {
	const fakeAccess = (payload) => ({
		token: {
			getUserId: (d) => payload.attrs?.id || d,
			get: (k) => payload[k] ?? null,
			hasScope: (s) => (payload.scope || []).includes(s),
		},
	});

	it("refuses to refresh a 2FA challenge token", async () => {
		await assert.rejects(
			() =>
				internalToken.getFreshToken(fakeAccess({ attrs: { id: 1 }, scope: ["2fa-challenge"] }), {
					expiry: "29d",
				}),
			/Invalid token/,
		);
	});

	it("refuses tokens without a user/admin scope", async () => {
		await assert.rejects(
			() => internalToken.getFreshToken(fakeAccess({ attrs: { id: 1 }, scope: ["worker"] }), {}),
			/Invalid token/,
		);
	});
});

describe("update status reconciliation", () => {
	const { reconcileStale } = appUpdateInternals;
	const now = Date.parse("2026-10-02T12:00:00Z");
	const deps = (active) => ({ isUpdateUnitActive: async () => active, now: () => now });

	it("marks an old running status as failed when the unit is gone", async () => {
		const out = await reconcileStale(
			{ state: "running", step: "frontend-build", message: "x", updatedAt: "2026-10-02T11:50:00Z" },
			deps(false),
		);
		assert.equal(out.state, "failed");
		assert.equal(out.step, "frontend-build");
	});

	it("keeps a status while the unit runs, within the grace period, or when not active", async () => {
		assert.equal(
			await reconcileStale({ state: "running", message: "x", updatedAt: "2026-10-02T11:00:00Z" }, deps(true)),
			null,
		);
		assert.equal(
			await reconcileStale({ state: "queued", message: "x", startedAt: "2026-10-02T11:59:50Z" }, deps(false)),
			null,
		);
		assert.equal(
			await reconcileStale({ state: "completed", message: "x", updatedAt: "2026-10-01T00:00:00Z" }, deps(false)),
			null,
		);
		// systemd unknown: only give up after the hard limit
		assert.equal(
			await reconcileStale({ state: "running", message: "x", updatedAt: "2026-10-02T11:00:00Z" }, deps(null)),
			null,
		);
		assert.equal(
			(await reconcileStale({ state: "running", message: "x", updatedAt: "2026-10-02T06:00:00Z" }, deps(null)))
				.state,
			"failed",
		);
	});
});

describe("bandwidth accounting", () => {
	it("counts post-reset traffic instead of dropping it", () => {
		assert.equal(counterDelta(1500, 1000), 500);
		assert.equal(counterDelta(300, 1_000_000), 300);
		assert.equal(counterDelta(0, 0), 0);
	});

	it("aligns daily buckets to local midnight", () => {
		const ts = new Date(2026, 5, 15, 13, 45, 10).getTime();
		const start = bandwidthBucketStart({ resolution: "1d", seconds: 86400 }, ts);
		const d = new Date(start * 1000);
		assert.deepEqual(
			[d.getFullYear(), d.getMonth(), d.getDate(), d.getHours(), d.getMinutes()],
			[2026, 5, 15, 0, 0],
		);
		assert.equal(bandwidthBucketStart({ resolution: "1m", seconds: 60 }, 125_000), 120);
	});
});
