import assert from "node:assert/strict";
import { describe, it } from "node:test";
import errs from "../lib/error.js";
import deadHostModel from "../models/dead_host.js";
import proxyHostModel from "../models/proxy_host.js";
import redirectionHostModel from "../models/redirection_host.js";
import internalHost from "./host.js";

describe("_findTakenHostname", () => {
	const rows = [
		{ id: 1, domain_names: ["App.Example.com", "www.example.com"] },
		{ id: 2, domain_names: ["other.example"] },
	];

	it("matches case-insensitively", () => {
		assert.equal(internalHost._findTakenHostname(["app.example.COM"], rows, 0), "app.example.COM");
	});

	it("ignores the row being updated", () => {
		assert.equal(internalHost._findTakenHostname(["app.example.com"], rows, 1), null);
		assert.equal(internalHost._findTakenHostname(["other.example"], rows, 1), "other.example");
	});

	it("returns the first colliding name in input order", () => {
		assert.equal(
			internalHost._findTakenHostname(["free.example", "other.example", "www.example.com"], rows, 0),
			"other.example",
		);
	});

	it("returns null when every name is free and ignores a LIKE substring hit", () => {
		assert.equal(internalHost._findTakenHostname(["example.com", "free.example"], rows, 0), null);
		assert.equal(internalHost._findTakenHostname(["x.example"], [], 0), null);
	});
});

describe("assertHostnamesFree", () => {
	const withModels = async (rowsByType, fn) => {
		const calls = [];
		const stub = (type) => () => {
			const qb = {
				where: () => qb,
				andWhere: (cb) => {
					const sub = { orWhere: (...args) => calls.push([type, ...args]) };
					cb(sub);
					return qb;
				},
				// biome-ignore lint/suspicious/noThenProperty: mimics the awaitable query builder
				then: (resolve, reject) => Promise.resolve(rowsByType[type] || []).then(resolve, reject),
			};
			return qb;
		};
		const orig = [proxyHostModel.query, redirectionHostModel.query, deadHostModel.query];
		proxyHostModel.query = stub("proxy");
		redirectionHostModel.query = stub("redirection");
		deadHostModel.query = stub("dead");
		try {
			await fn(calls);
		} finally {
			[proxyHostModel.query, redirectionHostModel.query, deadHostModel.query] = orig;
		}
	};

	it("runs one query per host type for all names", async () => {
		await withModels({}, async (calls) => {
			await internalHost.assertHostnamesFree(["a.example", "b.example"]);
			assert.equal(calls.length, 6);
			assert.deepEqual(
				calls.filter((c) => c[0] === "proxy").map((c) => c[3]),
				["%a.example%", "%b.example%"],
			);
		});
	});

	it("throws '<name> is already in use' for a taken name", async () => {
		await withModels({ redirection: [{ id: 9, domain_names: ["b.example"] }] }, async () => {
			await assert.rejects(
				() => internalHost.assertHostnamesFree(["a.example", "b.example"], "proxy", 9),
				(err) => err instanceof errs.ValidationError && err.message === "b.example is already in use",
			);
		});
	});

	it("ignores the record being updated only for its own type", async () => {
		await withModels({ dead: [{ id: 4, domain_names: ["a.example"] }] }, async () => {
			await internalHost.assertHostnamesFree(["a.example"], "dead", 4);
			await assert.rejects(() => internalHost.assertHostnamesFree(["a.example"], "proxy", 4), /already in use/);
		});
	});

	it("is a no-op without domain names", async () => {
		await withModels({}, async (calls) => {
			await internalHost.assertHostnamesFree(undefined, "proxy", 1);
			await internalHost.assertHostnamesFree([]);
			assert.equal(calls.length, 0);
		});
	});
});

describe("host CRUD guards", () => {
	it("stream update with certificate_id 'new' and no domain_names is a ValidationError", async () => {
		const { default: internalStream } = await import("./stream.js");
		const access = { can: async () => ({ permission_visibility: "all" }) };
		await assert.rejects(
			() => internalStream.update(access, { id: 1, certificate_id: "new" }),
			(err) => err instanceof errs.ValidationError && /domain_names are required/.test(err.message),
		);
	});

	it("stream create/update reject another user's certificate", async (t) => {
		const { default: internalStream } = await import("./stream.js");
		const { default: certificateModel } = await import("../models/certificate.js");
		const { default: streamModel } = await import("../models/stream.js");
		const qb = {
			where: () => qb,
			andWhere: () => qb,
			first: () => qb,
			// biome-ignore lint/suspicious/noThenProperty: mimics the awaitable query builder
			then: (resolve, reject) => Promise.resolve(undefined).then(resolve, reject),
		};
		t.mock.method(certificateModel, "query", () => qb);
		const streamQuery = t.mock.method(streamModel, "query", () => {
			throw new Error("stream row must not be written");
		});
		t.mock.method(internalStream, "get", async () => ({ id: 1, certificate_id: 0, meta: {} }));
		const access = { can: async () => ({ permission_visibility: "user" }), token: { getUserId: () => 2 } };
		const notAccessible = (err) => err instanceof errs.ValidationError && /not accessible/.test(err.message);
		await assert.rejects(() => internalStream.update(access, { id: 1, certificate_id: 5 }), notAccessible);
		await assert.rejects(
			() =>
				internalStream.create(access, { incoming_port: 4443, forwarding_host: "10.0.0.1", certificate_id: 5 }),
			notAccessible,
		);
		assert.equal(streamQuery.mock.callCount(), 0);
	});

	it("dead-host get never returns the certificate meta (private key / DNS credentials)", async () => {
		const { default: internalDeadHost } = await import("./dead-host.js");
		const row = {
			id: 3,
			domain_names: ["d.example"],
			certificate: { id: 1, meta: { certificate_key: "PRIVATE", dns_provider_credentials: "secret" } },
		};
		const qb = {
			where: () => qb,
			andWhere: () => qb,
			allowGraph: () => qb,
			first: () => qb,
			withGraphFetched: () => qb,
			// biome-ignore lint/suspicious/noThenProperty: mimics the awaitable query builder
			then: (resolve, reject) => Promise.resolve(row).then(resolve, reject),
		};
		const orig = deadHostModel.query;
		deadHostModel.query = () => qb;
		try {
			const access = { can: async () => ({ permission_visibility: "all" }) };
			const res = await internalDeadHost.get(access, { id: 3, expand: ["certificate"] });
			assert.deepEqual(res.certificate.meta, {});
		} finally {
			deadHostModel.query = orig;
		}
	});
});
