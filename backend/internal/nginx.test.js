import assert from "node:assert/strict";
import test from "node:test";
import internalNginx, { _testExports } from "./nginx.js";
import errs from "../lib/error.js";

const { assertSafeAdvancedConfig, assertSafeForwardField, assertSafeLocationPath } = _testExports;

// ─── assertSafeAdvancedConfig ────────────────────────────────────────────────
// Regression guard for the advanced_config nginx-directive injection vuln:
// advanced_config is rendered verbatim into a root-loaded/reloaded nginx config,
// so dangerous directives (file read / SSRF / lua RCE / key theft) must be
// rejected before the config is ever generated.

test("assertSafeAdvancedConfig allows empty / undefined / benign config", () => {
	assert.doesNotThrow(() => assertSafeAdvancedConfig(""));
	assert.doesNotThrow(() => assertSafeAdvancedConfig(undefined));
	assert.doesNotThrow(() => assertSafeAdvancedConfig(null));
	assert.doesNotThrow(() => assertSafeAdvancedConfig("add_header X-Test 1;"));
	assert.doesNotThrow(() => assertSafeAdvancedConfig("client_max_body_size 100m;"));
	// proxy_pass is a legitimate advanced_config primitive and must NOT be blocked.
	assert.doesNotThrow(() => assertSafeAdvancedConfig("location /api { proxy_pass http://backend:8080; }"));
});

test("assertSafeAdvancedConfig rejects arbitrary filesystem read via alias/root", () => {
	assert.throws(
		() => assertSafeAdvancedConfig("location /leak { alias /; autoindex on; }"),
		/forbidden nginx directive: alias/,
	);
	assert.throws(() => assertSafeAdvancedConfig("location /leak { root /etc; }"), /forbidden nginx directive: root/);
});

test("assertSafeAdvancedConfig rejects lua/perl code execution primitives", () => {
	assert.throws(
		() => assertSafeAdvancedConfig("access_by_lua_block { os.execute('id > /tmp/x') }"),
		/forbidden nginx directive/,
	);
	assert.throws(() => assertSafeAdvancedConfig("content_by_lua_file /tmp/x.lua;"), /forbidden nginx directive/);
	assert.throws(() => assertSafeAdvancedConfig("lua_shared_dict foo 10m;"), /forbidden nginx directive/);
	assert.throws(() => assertSafeAdvancedConfig("perl_set $x 'sub { }';"), /forbidden nginx directive/);
	assert.throws(() => assertSafeAdvancedConfig("perl 'sub { }';"), /forbidden nginx directive/);
});

test("assertSafeAdvancedConfig rejects include / load_module / ssl key directives", () => {
	assert.throws(() => assertSafeAdvancedConfig("include /etc/passwd;"), /forbidden nginx directive: include/);
	assert.throws(
		() => assertSafeAdvancedConfig("load_module /tmp/evil.so;"),
		/forbidden nginx directive: load_module/,
	);
	assert.throws(
		() => assertSafeAdvancedConfig("ssl_certificate_key /etc/letsencrypt/live/x/privkey.pem;"),
		/forbidden nginx directive/,
	);
	assert.throws(() => assertSafeAdvancedConfig("ssl_password_file /tmp/pw;"), /forbidden nginx directive/);
});

test("assertSafeAdvancedConfig detects a forbidden directive after another statement on the same line", () => {
	// Attacker chains directives with `;` or nests inside a block to evade a
	// naive start-of-string check.
	assert.throws(() => assertSafeAdvancedConfig("add_header X 1; alias /;"), /forbidden nginx directive: alias/);
	assert.throws(
		() => assertSafeAdvancedConfig("server_tokens off;\n  include /etc/nginx/secret;"),
		/forbidden nginx directive: include/,
	);
});

test("assertSafeAdvancedConfig is case-insensitive and ignores comments", () => {
	assert.throws(() => assertSafeAdvancedConfig("ALIAS /;"), /forbidden nginx directive: alias/);
	// A directive name mentioned only inside a comment must not trigger.
	assert.doesNotThrow(() => assertSafeAdvancedConfig("# alias is not allowed here\nadd_header X 1;"));
});

test("assertSafeForwardField rejects newline-injected redirection forward_domain_name", () => {
	// redirection_host.conf renders `return ... {{ forward_domain_name }};` unquoted.
	// The schema domain pattern accepts interior newlines, so generateConfig gates it.
	assert.throws(
		() => assertSafeForwardField('evil.com\n  return 200 "pwned";\n  #', "forward_domain_name"),
		/forward_domain_name/,
	);
	assert.doesNotThrow(() => assertSafeForwardField("target.example.com", "forward_domain_name"));
});

test("assertSafeForwardField rejects newline-injected stream forwarding_host but allows host/IP", () => {
	// stream.conf renders `proxy_pass {{ forwarding_host }}:{{ forwarding_port }};` unquoted.
	assert.throws(() => assertSafeForwardField("1.2.3.4\n  deny all;", "forwarding_host"), /forwarding_host/);
	assert.doesNotThrow(() => assertSafeForwardField("10.0.0.1", "forwarding_host"));
	assert.doesNotThrow(() => assertSafeForwardField("backend.internal", "forwarding_host"));
});

// ─── nginx-tokenizer parity (quoted names, mid-token #) ──────────────────────

test("assertSafeAdvancedConfig rejects quoted or escaped directive names", () => {
	assert.throws(() => assertSafeAdvancedConfig('"include" /etc/shadow;'), /quoted or escaped/);
	assert.throws(() => assertSafeAdvancedConfig('location /q { "alias" /etc/; }'), /quoted or escaped/);
	assert.throws(() => assertSafeAdvancedConfig("'content_by_lua_block' { os.execute('id') }"), /quoted or escaped/);
	assert.throws(() => assertSafeAdvancedConfig("ali\\as /etc/;"), /quoted or escaped/);
});

test("assertSafeAdvancedConfig treats # as a comment only at token start", () => {
	assert.throws(() => assertSafeAdvancedConfig("add_header X-A a#b; root /etc;"), /forbidden nginx directive: root/);
	assert.throws(() => assertSafeAdvancedConfig('set $a "#"; alias /etc/;'), /forbidden nginx directive: alias/);
	// A real comment still hides its content.
	assert.doesNotThrow(() => assertSafeAdvancedConfig("add_header X 1; # root /etc;"));
	// Quoted arguments containing ; { } are not statement boundaries.
	assert.doesNotThrow(() => assertSafeAdvancedConfig('add_header X-T "a; b { c }";'));
});

test("assertSafeAdvancedConfig rejects file-writing and file-reading directives", () => {
	assert.throws(() => assertSafeAdvancedConfig("access_log /etc/profile.d/x.sh;"), /access_log/);
	assert.throws(() => assertSafeAdvancedConfig("error_log /tmp/x;"), /error_log/);
	assert.throws(() => assertSafeAdvancedConfig("client_body_temp_path /etc/x;"), /forbidden/);
	assert.throws(() => assertSafeAdvancedConfig("ssl_trusted_certificate /root/x;"), /forbidden/);
	assert.throws(() => assertSafeAdvancedConfig("auth_basic_user_file /etc/shadow;"), /forbidden/);
	assert.throws(() => assertSafeAdvancedConfig("proxy_ssl_certificate_key /data/keys.json;"), /forbidden/);
	assert.throws(() => assertSafeAdvancedConfig("proxy_store /etc/x;"), /forbidden/);
	assert.doesNotThrow(() => assertSafeAdvancedConfig("access_log off;"));
	assert.doesNotThrow(() =>
		assertSafeAdvancedConfig(
			"proxy_set_header X-Real-IP $remote_addr;\nproxy_read_timeout 300s;\nlocation ~* \\.(js|css)$ { expires 7d; }",
		),
	);
});

// ─── custom location path ────────────────────────────────────────────────────

test("assertSafeLocationPath blocks directive injection through locations[].path", () => {
	assert.throws(() => assertSafeLocationPath("/x { alias /etc/; autoindex on; }\n  location /y"), /location path/);
	assert.throws(() => assertSafeLocationPath("/x;"), /location path/);
	assert.throws(() => assertSafeLocationPath("/a b"), /location path/);
	assert.throws(() => assertSafeLocationPath("/a#"), /location path/);
	assert.throws(() => assertSafeLocationPath('"/a"'), /location path/);
	assert.throws(() => assertSafeLocationPath("/a\\"), /location path/);
	assert.throws(() => assertSafeLocationPath(""), /location path/);
	assert.throws(() => assertSafeLocationPath(undefined), /location path/);
});

test("assertSafeLocationPath allows prefix, exact and regex locations", () => {
	for (const p of [
		"/",
		"/api",
		"/api/v1/",
		"= /exact",
		"^~ /static/",
		"~ \\.php$",
		"~* \\.(jpg|png|gif)$",
		"~ ^/(a|b)/[0-9]+$",
	]) {
		assert.doesNotThrow(() => assertSafeLocationPath(p), p);
	}
});

// ─── assertSafeHostFields / configure ordering ───────────────────────────────
// A rejected value must fail BEFORE the DB write and before the live conf is
// deleted; otherwise the host silently vanished on the next nginx reload.

test("assertSafeHostFields gates advanced_config, host-level forwards and locations", () => {
	assert.doesNotThrow(() => internalNginx.assertSafeHostFields("proxy_host", { id: 1 }));
	assert.doesNotThrow(() =>
		internalNginx.assertSafeHostFields("proxy_host", {
			advanced_config: "client_max_body_size 1g;",
			locations: [{ path: "/api", forward_host: "10.0.0.1", forward_path: "/x" }],
		}),
	);
	assert.throws(() => internalNginx.assertSafeHostFields("proxy_host", { advanced_config: "root /var/www/x;" }));
	assert.throws(() =>
		internalNginx.assertSafeHostFields("proxy_host", { locations: [{ path: "/a; }", forward_host: "h" }] }),
	);
	assert.throws(() =>
		internalNginx.assertSafeHostFields("redirection_host", { forward_domain_name: "a.de;\ninclude /x;" }),
	);
	assert.throws(() => internalNginx.assertSafeHostFields("stream", { forwarding_host: "h;\nfoo" }));
});

test("configure rejects an unsafe host before deleting the live config", async () => {
	const orig = {
		test: internalNginx.test,
		deleteConfig: internalNginx.deleteConfig,
		generateConfig: internalNginx.generateConfig,
		reload: internalNginx.reload,
	};
	const calls = [];
	internalNginx.test = async () => calls.push("test");
	internalNginx.deleteConfig = async () => calls.push("delete");
	internalNginx.generateConfig = async () => calls.push("generate");
	internalNginx.reload = async () => calls.push("reload");
	try {
		await assert.rejects(
			() => internalNginx.configure({}, "proxy_host", { id: 5, meta: {}, advanced_config: "include /etc/x;" }),
			/forbidden nginx directive/,
		);
		assert.deepEqual(calls, ["test"]);
	} finally {
		Object.assign(internalNginx, orig);
	}
});

// ─── configure: a conf that passes the gates but fails `nginx -t` ────────────

async function withFakeNginx(fn) {
	const fs = await import("node:fs");
	const os = await import("node:os");
	const path = await import("node:path");
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fg-nginx-configure-"));
	const orig = {
		test: internalNginx.test,
		generateConfig: internalNginx.generateConfig,
		reload: internalNginx.reload,
		getConfigName: internalNginx.getConfigName,
		markHostsRejected: internalNginx.markHostsRejected,
		clearHostErrors: internalNginx.clearHostErrors,
	};
	const marked = [];
	const cleared = [];
	internalNginx.markHostsRejected = async (_t, rejected) => marked.push(...rejected);
	internalNginx.clearHostErrors = async (_t, hosts) => cleared.push(...hosts.map((h) => h.id));
	let testCalls = 0;
	const patches = [];
	const model = { query: () => ({ where: () => ({ patch: async (p) => patches.push(p) }) }) };
	internalNginx.getConfigName = (_t, id) => path.join(dir, `${id}.conf`);
	// Simulated `nginx -t`: fails whenever a live *.conf contains a bad directive.
	internalNginx.test = async () => {
		testCalls++;
		for (const f of fs.readdirSync(dir).filter((n) => n.endsWith(".conf"))) {
			if (fs.readFileSync(path.join(dir, f), "utf8").includes("bogus_directive")) {
				throw new Error('nginx: [emerg] unknown directive "bogus_directive"');
			}
		}
	};
	internalNginx.generateConfig = async (_t, host) => {
		fs.writeFileSync(
			internalNginx.getConfigName("proxy_host", host.id),
			`server { ${host.advanced_config || ""} }\n`,
		);
	};
	internalNginx.reload = async () => internalNginx.test();
	try {
		await fn({ dir, fs, path, model, patches, marked, cleared, testCalls: () => testCalls });
	} finally {
		Object.assign(internalNginx, orig);
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

test("configure keeps the working conf when the new one fails nginx -t", async () => {
	await withFakeNginx(async ({ dir, fs, path, model, patches }) => {
		const conf = path.join(dir, "7.conf");
		fs.writeFileSync(conf, "server { working }\n");
		// The save must visibly fail (4xx with the nginx -t output) instead of
		// returning success while nginx keeps serving the old conf.
		await assert.rejects(
			() =>
				internalNginx.configure(model, "proxy_host", {
					id: 7,
					meta: {},
					advanced_config: "bogus_directive on;",
				}),
			(err) => {
				// lib/error.js errors all report name "Error"; check the type instead.
				assert.ok(err instanceof errs.ValidationError);
				assert.equal(err.status, 400);
				assert.equal(err.public, true);
				assert.match(err.message, /changes are not active/);
				assert.match(err.message, /bogus_directive/);
				return true;
			},
		);
		assert.equal(fs.readFileSync(conf, "utf8"), "server { working }\n", "previous conf restored");
		assert.match(fs.readFileSync(`${conf}.err`, "utf8"), /bogus_directive/, "rejected conf kept as .err");
		assert.ok(!fs.existsSync(`${conf}.bak`), "no .bak left behind");
		const meta = patches.at(-1).meta;
		assert.equal(meta.nginx_online, true, "host still served by the previous conf");
		assert.match(meta.nginx_err, /previous config is still active/);
	});
});

test("configure marks a NEW host offline when its first conf fails nginx -t", async () => {
	await withFakeNginx(async ({ dir, fs, path, model }) => {
		const meta = await internalNginx.configure(model, "proxy_host", {
			id: 8,
			meta: {},
			advanced_config: "bogus_directive on;",
		});
		assert.ok(!fs.existsSync(path.join(dir, "8.conf")), "no live conf");
		assert.ok(fs.existsSync(path.join(dir, "8.conf.err")));
		assert.equal(meta.nginx_online, false);
	});
});

test("configure replaces the conf and drops the backup on success", async () => {
	await withFakeNginx(async ({ dir, fs, path, model }) => {
		const conf = path.join(dir, "9.conf");
		fs.writeFileSync(conf, "server { old }\n");
		const meta = await internalNginx.configure(model, "proxy_host", {
			id: 9,
			meta: {},
			advanced_config: "client_max_body_size 1g;",
		});
		assert.match(fs.readFileSync(conf, "utf8"), /client_max_body_size/);
		assert.ok(!fs.existsSync(`${conf}.bak`));
		assert.equal(meta.nginx_online, true);
		assert.equal(meta.nginx_err, null);
	});
});

test("configure restores the working conf when rendering fails", async () => {
	await withFakeNginx(async ({ dir, fs, path, model }) => {
		const conf = path.join(dir, "10.conf");
		fs.writeFileSync(conf, "server { working }\n");
		internalNginx.generateConfig = async () => {
			throw new Error("render failed");
		};
		await assert.rejects(() => internalNginx.configure(model, "proxy_host", { id: 10, meta: {} }), /render failed/);
		assert.equal(fs.readFileSync(conf, "utf8"), "server { working }\n");
	});
});

// ─── bulkGenerateConfigs: regenerating from DB rows must not go live unchecked ─

test("bulkGenerateConfigs isolates the bad host, keeps the good confs and names the offender", async () => {
	await withFakeNginx(async ({ dir, fs, path, marked, cleared }) => {
		const good = path.join(dir, "11.conf");
		const bad = path.join(dir, "12.conf");
		fs.writeFileSync(good, "server { old11 }\n");
		fs.writeFileSync(bad, "server { old12 }\n");
		await assert.rejects(
			() =>
				internalNginx.bulkGenerateConfigs("proxy_host", [
					{ id: 11, advanced_config: "client_max_body_size 1g;" },
					// A row still holding settings nginx -t rejected earlier.
					{ id: 12, advanced_config: "bogus_directive on;" },
					// A host without a conf yet: it is valid and must go live.
					{ id: 13, advanced_config: "" },
				]),
			(err) =>
				err instanceof errs.ValidationError &&
				err.status === 400 &&
				/proxy_host #12: rejected, its previous configuration is still active/.test(err.message) &&
				!/#11|#13/.test(err.message) &&
				/bogus_directive/.test(err.message),
		);
		assert.match(fs.readFileSync(good, "utf8"), /client_max_body_size/, "good host got its new conf");
		assert.equal(fs.readFileSync(bad, "utf8"), "server { old12 }\n", "bad host keeps its previous conf");
		assert.match(fs.readFileSync(`${bad}.err`, "utf8"), /bogus_directive/, "rejected conf kept as .err");
		assert.ok(fs.existsSync(path.join(dir, "13.conf")), "new valid host is live");
		assert.deepEqual(
			fs.readdirSync(dir).filter((n) => n.endsWith(".bak")),
			[],
			"no .bak left behind",
		);
		assert.deepEqual(
			marked.map((r) => [r.host.id, r.kept]),
			[[12, true]],
		);
		assert.deepEqual(cleared.sort(), [11, 13]);
		await internalNginx.test();
	});
});

test("bulkGenerateConfigs restores confs stashed for certificate issuance and only drops the bad host", async () => {
	await withFakeNginx(async ({ dir, fs, path, marked }) => {
		// disableInUseHosts -> stash: the live confs move to .disabled.
		fs.writeFileSync(path.join(dir, "21.conf"), "server { old21 }\n");
		fs.writeFileSync(path.join(dir, "22.conf"), "server { old22 }\n");
		await internalNginx.bulkStashConfigs("proxy_host", [{ id: 21 }, { id: 22 }, { id: 23 }]);
		assert.ok(!fs.existsSync(path.join(dir, "21.conf")));
		assert.ok(fs.existsSync(path.join(dir, "21.conf.disabled")));
		await assert.rejects(
			() =>
				internalNginx.bulkGenerateConfigs("proxy_host", [
					{ id: 21, advanced_config: "client_max_body_size 1g;" },
					{ id: 22, advanced_config: "bogus_directive on;" },
					{ id: 23, advanced_config: "bogus_directive on;" },
				]),
			(err) =>
				/#22: rejected, its previous configuration is still active/.test(err.message) &&
				/#23: rejected and it had no previous configuration, so it is OFFLINE/.test(err.message) &&
				!/previous configuration was kept/.test(err.message),
		);
		assert.match(fs.readFileSync(path.join(dir, "21.conf"), "utf8"), /client_max_body_size/);
		assert.equal(fs.readFileSync(path.join(dir, "22.conf"), "utf8"), "server { old22 }\n", "stashed conf restored");
		assert.ok(!fs.existsSync(path.join(dir, "23.conf")));
		assert.deepEqual(
			fs.readdirSync(dir).filter((n) => n.endsWith(".bak") || n.endsWith(".disabled")),
			[],
		);
		assert.deepEqual(
			marked.map((r) => [r.host.id, r.kept]),
			[
				[22, true],
				[23, false],
			],
		);
		await internalNginx.test();
	});
});

test("bulkGenerateConfigs changes nothing when nginx -t already fails without the batch", async () => {
	await withFakeNginx(async ({ dir, fs, path, marked }) => {
		fs.writeFileSync(path.join(dir, "31.conf"), "server { old31 }\n");
		fs.writeFileSync(path.join(dir, "99.conf"), "server { bogus_directive on; }\n");
		await assert.rejects(
			() => internalNginx.bulkGenerateConfigs("proxy_host", [{ id: 31, advanced_config: "client_max_body_size 1g;" }]),
			(err) => err instanceof errs.ValidationError && /even with the previous/.test(err.message),
		);
		assert.equal(fs.readFileSync(path.join(dir, "31.conf"), "utf8"), "server { old31 }\n");
		assert.ok(!fs.existsSync(path.join(dir, "31.conf.bak")));
		assert.deepEqual(marked, []);
	});
});

test("enableInUseHosts runs all host types and does not throw when one type has a bad host", async () => {
	const { default: internalCertificate } = await import("./certificate.js");
	const orig = internalNginx.bulkGenerateConfigs;
	const seen = [];
	internalNginx.bulkGenerateConfigs = async (type) => {
		seen.push(type);
		if (type === "proxy_host") throw new errs.ValidationError("bad host");
	};
	try {
		const errors = await internalCertificate.enableInUseHosts({
			total_count: 3,
			proxy_hosts: [{ id: 1 }],
			redirection_hosts: [{ id: 2 }],
			dead_hosts: [{ id: 3 }],
		});
		assert.deepEqual(seen, ["proxy_host", "redirection_host", "dead_host"]);
		assert.equal(errors.length, 1);
	} finally {
		internalNginx.bulkGenerateConfigs = orig;
	}
});

test("bulkGenerateConfigs writes all confs and drops the backups when nginx -t passes", async () => {
	await withFakeNginx(async ({ dir, fs, path }) => {
		fs.writeFileSync(path.join(dir, "14.conf"), "server { old }\n");
		await internalNginx.bulkGenerateConfigs("proxy_host", [
			{ id: 14, advanced_config: "client_max_body_size 1g;" },
			{ id: 15, advanced_config: "" },
		]);
		assert.match(fs.readFileSync(path.join(dir, "14.conf"), "utf8"), /client_max_body_size/);
		assert.ok(fs.existsSync(path.join(dir, "15.conf")));
		assert.deepEqual(
			fs.readdirSync(dir).filter((n) => n.endsWith(".bak")),
			[],
		);
	});
});

// ─── config lock: overlapping saves must not share <conf>.bak ────────────────

test("two overlapping configure() calls with a bad conf keep the working conf", async () => {
	await withFakeNginx(async ({ dir, fs, path, model }) => {
		const conf = path.join(dir, "42.conf");
		fs.writeFileSync(conf, "server { working }\n");
		const bad = { id: 42, meta: {}, advanced_config: "bogus_directive on;" };
		// Double submit / retry: both start before either finishes.
		const results = await Promise.allSettled([
			internalNginx.configure(model, "proxy_host", bad),
			internalNginx.configure(model, "proxy_host", bad),
		]);
		assert.deepEqual(
			results.map((r) => r.status),
			["rejected", "rejected"],
		);
		assert.equal(fs.readFileSync(conf, "utf8"), "server { working }\n", "working conf still live");
		assert.ok(!fs.existsSync(`${conf}.bak`), "no .bak left behind");
	});
});

test("a save of another host never sees a concurrent call's untested conf", async () => {
	await withFakeNginx(async ({ dir, fs, path, model }) => {
		fs.writeFileSync(path.join(dir, "1.conf"), "server { one }\n");
		fs.writeFileSync(path.join(dir, "2.conf"), "server { two }\n");
		const [bad, good] = await Promise.allSettled([
			internalNginx.configure(model, "proxy_host", { id: 1, meta: {}, advanced_config: "bogus_directive on;" }),
			internalNginx.configure(model, "proxy_host", { id: 2, meta: {}, advanced_config: "gzip on;" }),
		]);
		assert.equal(bad.status, "rejected");
		assert.equal(good.status, "fulfilled", "valid save is not rolled back by the other host's error");
		assert.match(fs.readFileSync(path.join(dir, "2.conf"), "utf8"), /gzip on/);
		assert.equal(fs.readFileSync(path.join(dir, "1.conf"), "utf8"), "server { one }\n");
	});
});

test("withConfigLock serializes callers, is re-entrant and survives errors", async () => {
	const { withConfigLock } = _testExports;
	const order = [];
	const tick = () => new Promise((r) => setImmediate(r));
	const job = (name, fail) =>
		withConfigLock(async () => {
			order.push(`${name}:start`);
			await tick();
			// Nested call inside the lock must not deadlock.
			await withConfigLock(async () => order.push(`${name}:nested`));
			order.push(`${name}:end`);
			if (fail) throw new Error(name);
		});
	const res = await Promise.allSettled([job("a", true), job("b"), job("c")]);
	assert.deepEqual(
		res.map((r) => r.status),
		["rejected", "fulfilled", "fulfilled"],
	);
	assert.deepEqual(order, [
		"a:start",
		"a:nested",
		"a:end",
		"b:start",
		"b:nested",
		"b:end",
		"c:start",
		"c:nested",
		"c:end",
	]);
});
