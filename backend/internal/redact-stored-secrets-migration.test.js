import assert from "node:assert/strict";
import test from "node:test";
import knexFactory from "knex";
import { up } from "../migrations/20261127120000_redact_stored_secrets.js";

test("migration strips DNS credentials from hosts and redacts audit-log secrets", async () => {
	const knex = knexFactory({ client: "sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
	try {
		for (const t of ["proxy_host", "redirection_host", "dead_host", "audit_log"]) {
			await knex.schema.createTable(t, (tb) => {
				tb.increments("id");
				tb.text("meta");
			});
		}
		await knex("proxy_host").insert([
			{ meta: JSON.stringify({ dns_challenge: true, dns_provider_credentials: "tok", geo_filter: true }) },
			{ meta: JSON.stringify({ geo_filter: false }) },
		]);
		await knex("audit_log").insert([
			{ meta: JSON.stringify({ meta: { dns_provider_credentials: "tok" }, nice_name: "x" }) },
			{ meta: JSON.stringify({ items: [{ username: "u", password: "p" }] }) },
			{ meta: JSON.stringify({ password_changed: true }) },
		]);
		await up(knex);
		await up(knex); // idempotent
		const hosts = (await knex("proxy_host").orderBy("id")).map((r) => JSON.parse(r.meta));
		assert.deepEqual(hosts[0], { dns_challenge: true, geo_filter: true });
		assert.deepEqual(hosts[1], { geo_filter: false });
		const audit = (await knex("audit_log").orderBy("id")).map((r) => JSON.parse(r.meta));
		assert.equal(audit[0].meta.dns_provider_credentials, "[redacted]");
		assert.equal(audit[0].nice_name, "x");
		assert.equal(audit[1].items[0].password, "[redacted]");
		assert.deepEqual(audit[2], { password_changed: true });
	} finally {
		await knex.destroy();
	}
});
