// Shared route helper (lib/express/route.js) used by routes/agent.js and
// routes/site-isolation.js.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import express from "express";

const { default: createRoute } = await import("../lib/express/route.js");

describe("createRoute", () => {
	let server;
	let base;
	const seen = [];

	before(async () => {
		const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });
		const route = createRoute(router);
		const limiter = (req, _res, next) => {
			seen.push(`limit ${req.method}`);
			next();
		};
		const audit = (req, _res, next) => {
			seen.push(`audit ${req.method}`);
			next();
		};
		route("/open", { get: () => ({ ok: true }), post: (req) => ({ got: req.body }) }, { admin: false, limiter });
		route("/verdict", { post: () => ({ allowed: true }) }, { admin: false, status: { post: 200 }, audit });
		route("/script", { get: () => "#!/bin/sh\n" }, { admin: false, type: "text/plain" });
		route(
			"/boom",
			{
				get: () => {
					throw Object.assign(new Error("nope"), { status: 418 });
				},
			},
			{ admin: false },
		);
		route("/admin", { get: () => ({ secret: true }) });

		const app = express();
		app.use(express.json());
		app.use(router);
		app.use((err, _req, res, _next) => res.status(err.status || 500).send({ error: err.message }));
		await new Promise((resolve) => {
			server = app.listen(0, "127.0.0.1", resolve);
		});
		base = `http://127.0.0.1:${server.address().port}`;
	});

	after(() => new Promise((resolve) => server.close(resolve)));

	it("answers OPTIONS with 204 without running the limiter", async () => {
		seen.length = 0;
		const res = await fetch(`${base}/open`, { method: "OPTIONS" });
		assert.equal(res.status, 204);
		assert.deepEqual(seen, []);
	});

	it("sends GET as 200 and POST as 201 by default, limiter per method", async () => {
		seen.length = 0;
		const get = await fetch(`${base}/open`);
		assert.equal(get.status, 200);
		assert.deepEqual(await get.json(), { ok: true });
		const post = await fetch(`${base}/open`, {
			method: "POST",
			headers: { "Content-Type": "application/json" },
			body: JSON.stringify({ a: 1 }),
		});
		assert.equal(post.status, 201);
		assert.deepEqual(await post.json(), { got: { a: 1 } });
		assert.deepEqual(seen, ["limit GET", "limit POST"]);
	});

	it("honours a status override and runs the audit middleware", async () => {
		seen.length = 0;
		const res = await fetch(`${base}/verdict`, { method: "POST" });
		assert.equal(res.status, 200);
		assert.deepEqual(seen, ["audit POST"]);
	});

	it("sets the content type", async () => {
		const res = await fetch(`${base}/script`);
		assert.match(res.headers.get("content-type"), /^text\/plain/);
		assert.equal(await res.text(), "#!/bin/sh\n");
	});

	it("passes handler errors to the error middleware", async () => {
		const res = await fetch(`${base}/boom`);
		assert.equal(res.status, 418);
	});

	it("rejects an admin route without a token", async () => {
		const res = await fetch(`${base}/admin`);
		// anonymous access loads fine, requireAdmin refuses it
		assert.equal(res.status, 403);
		assert.equal((await res.json()).secret, undefined);
	});
});
