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
		reloadTested: internalNginx.reloadTested,
	};
	const calls = [];
	internalNginx.test = async () => calls.push("test");
	internalNginx.deleteConfig = async () => calls.push("delete");
	internalNginx.generateConfig = async () => calls.push("generate");
	internalNginx.reload = async () => calls.push("reload");
	internalNginx.reloadTested = async () => calls.push("reload");
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
		reloadTested: internalNginx.reloadTested,
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
	let reloads = 0;
	internalNginx.reload = async () => {
		await internalNginx.test();
		reloads++;
	};
	internalNginx.reloadTested = async () => {
		reloads++;
	};
	try {
		await fn({
			dir,
			fs,
			path,
			model,
			patches,
			marked,
			cleared,
			testCalls: () => testCalls,
			reloads: () => reloads,
		});
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
	await withFakeNginx(async ({ dir, fs, path, model, testCalls, reloads }) => {
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
		// baseline + new conf; the reload itself does not run a third `nginx -t`
		assert.equal(testCalls(), 2);
		assert.equal(reloads(), 1);
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

test("bulkGenerateConfigs waits for every render before putting the previous confs back", async () => {
	await withFakeNginx(async ({ dir, fs, path }) => {
		const conf41 = path.join(dir, "41.conf");
		fs.writeFileSync(conf41, "server { old41 }\n");
		const fakeTest = internalNginx.test;
		// A slow `nginx -t`: with Promise.all the late render of #41 landed while
		// the base state was being tested, after its .bak had been put back.
		internalNginx.test = async () => {
			await new Promise((r) => setTimeout(r, 20));
			return fakeTest();
		};
		internalNginx.generateConfig = async (_t, host) => {
			if (host.id === 40) throw new Error("forbidden legacy advanced_config");
			await new Promise((r) => setTimeout(r, 5));
			fs.writeFileSync(internalNginx.getConfigName("proxy_host", host.id), "server { bogus_directive on; }\n");
		};
		await assert.rejects(
			() => internalNginx.bulkGenerateConfigs("proxy_host", [{ id: 40 }, { id: 41 }]),
			(err) => !/even with the previous/.test(err.message),
		);
		assert.equal(fs.readFileSync(conf41, "utf8"), "server { old41 }\n");
		assert.ok(!fs.existsSync(`${conf41}.bak`));
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

// ─── host rows must carry their relations before they are rendered ──────────
// getHostsWithDomains() fed raw rows into bulkGenerateConfigs(): the templates
// then dropped `listen 443`/ssl and rendered `deny all;` without auth_basic,
// which passes nginx -t and silently went live.

const renderProxyHost = async (row) => {
	const { default: utils } = await import("../lib/utils.js");
	const fsMod = await import("node:fs");
	const template = fsMod.readFileSync(new URL("../templates/proxy_host.conf", import.meta.url), "utf8");
	return utils.getRenderEngine().parseAndRender(template, {
		id: 1,
		domain_names: ["app.example.com"],
		forward_scheme: "http",
		forward_host: "10.0.0.5",
		forward_port: 8080,
		advanced_config: "",
		locations: [],
		use_default_location: true,
		ipv6: false,
		enabled: 1,
		ssl_forced: 1,
		...row,
	});
};

test("proxy_host.conf rendered from a raw row (no relations) loses SSL and auth", async () => {
	const out = await renderProxyHost({ certificate_id: 3, access_list_id: 5 });
	assert.doesNotMatch(out, /listen 443/);
	assert.match(out, /deny all;/);
	assert.doesNotMatch(out, /auth_basic_user_file/);
});

test("proxy_host.conf rendered with loaded relations keeps SSL, auth and allow rules", async () => {
	const out = await renderProxyHost({
		certificate_id: 3,
		certificate: { id: 3, provider: "letsencrypt" },
		access_list_id: 5,
		access_list: {
			id: 5,
			pass_auth: 0,
			satisfy_any: 1,
			items: [{ username: "u" }],
			clients: [{ directive: "allow", address: "10.0.0.0/24" }],
		},
	});
	assert.match(out, /listen 443/);
	assert.match(out, /auth_basic_user_file\s+\/data\/access\/5;/);
	assert.match(out, /allow 10\.0\.0\.0\/24;/);
});

test("assertHostRelationsLoaded rejects rows whose relations were never loaded", () => {
	const { assertHostRelationsLoaded } = _testExports;
	assert.throws(
		() => assertHostRelationsLoaded("proxy_host", { id: 1, certificate_id: 3 }),
		(err) => err instanceof errs.ConfigurationError && /no certificate loaded/.test(err.message),
	);
	assert.throws(
		() => assertHostRelationsLoaded("proxy_host", { id: 1, access_list_id: 5, access_list: { id: 5 } }),
		/no access list clients\/items loaded/,
	);
	assert.throws(() => assertHostRelationsLoaded("proxy_host", { id: 1, access_list_id: 5 }), /access list/);
	// fetched but no match (soft-deleted cert) is null: render without SSL
	assert.doesNotThrow(() => assertHostRelationsLoaded("proxy_host", { id: 1, certificate_id: 3, certificate: null }));
	assert.doesNotThrow(() =>
		assertHostRelationsLoaded("proxy_host", {
			id: 1,
			access_list_id: 5,
			access_list: { items: [], clients: [] },
		}),
	);
	assert.doesNotThrow(() => assertHostRelationsLoaded("dead_host", { id: 1, certificate_id: 0 }));
	assert.doesNotThrow(() => assertHostRelationsLoaded("default", { id: 0 }));
	assert.throws(() => assertHostRelationsLoaded("redirection_host", { id: 2, certificate_id: 4 }), /certificate/);
});

test("getHostsWithDomains loads the relations the templates need", async () => {
	const { default: internalHost } = await import("./host.js");
	const { default: proxyHostModel } = await import("../models/proxy_host.js");
	const { default: redirectionHostModel } = await import("../models/redirection_host.js");
	const { default: deadHostModel } = await import("../models/dead_host.js");
	const graphs = {};
	const stub = (name, rows) => () => {
		const qb = {
			where: () => qb,
			andWhere: (cb) => {
				cb({ orWhere: () => {} });
				return qb;
			},
			withGraphFetched: (g) => {
				graphs[name] = g;
				return qb;
			},
			// biome-ignore lint/suspicious/noThenProperty: mimics the awaitable query builder
			then: (resolve, reject) => Promise.resolve(rows).then(resolve, reject),
		};
		return qb;
	};
	const orig = [proxyHostModel.query, redirectionHostModel.query, deadHostModel.query];
	// id 3 is a LIKE-prefilter hit only and must not be included
	proxyHostModel.query = stub("proxy", [
		{ id: 1, domain_names: ["App.example.com"] },
		{ id: 3, domain_names: ["sub.app.example.com"] },
	]);
	redirectionHostModel.query = stub("redirection", [{ id: 2, domain_names: ["other.example"] }]);
	deadHostModel.query = stub("dead", []);
	try {
		const res = await internalHost.getHostsWithDomains(["app.example.com"]);
		assert.equal(graphs.proxy, "[certificate,access_list.[clients,items]]");
		assert.equal(graphs.redirection, "[certificate]");
		assert.equal(graphs.dead, "[certificate]");
		assert.equal(res.total_count, 1);
		assert.deepEqual(
			res.proxy_hosts.map((h) => h.id),
			[1],
		);
	} finally {
		[proxyHostModel.query, redirectionHostModel.query, deadHostModel.query] = orig;
	}
});

// Upstream #5543: users but no client rules + "satisfy all" rendered a bare
// "deny all" that 403'd every request, valid logins included.
test("_access.conf: users without client rules render no deny all", async () => {
	for (const satisfy_any of [0, 1]) {
		const out = await renderProxyHost({
			access_list_id: 5,
			access_list: { id: 5, pass_auth: 0, satisfy_any, items: [{ username: "u" }], clients: [] },
		});
		assert.match(out, /auth_basic_user_file\s+\/data\/access\/5;/);
		assert.doesNotMatch(out, /deny all;/);
		assert.match(out, satisfy_any ? /satisfy any;/ : /satisfy all;/);
	}
});

test("_access.conf: an access list without users and rules stays closed", async () => {
	for (const access_list of [
		{ id: 5, satisfy_any: 0, items: [], clients: [] },
		{ id: 5, satisfy_any: 1, items: [], clients: [] },
		{ id: 5, satisfy_any: 0, items: [{ username: "u" }] }, // clients not loaded
		{ id: 5, satisfy_any: 0 },
	]) {
		const out = await renderProxyHost({ access_list_id: 5, access_list });
		assert.match(out, /deny all;/, JSON.stringify(access_list));
	}
});

test("_access.conf: client rules keep their trailing deny all", async () => {
	const out = await renderProxyHost({
		access_list_id: 5,
		access_list: {
			id: 5,
			satisfy_any: 0,
			items: [{ username: "u" }],
			clients: [{ directive: "allow", address: "10.0.0.0/24" }],
		},
	});
	assert.match(out, /allow 10\.0\.0\.0\/24;\s+deny all;/);
});

// Upstream #5741: an IPv6 forwarding_host rendered "fe80::1:25" (invalid port).
test("streamUpstreamHost brackets IPv6 literals only", () => {
	const { streamUpstreamHost } = _testExports;
	assert.equal(streamUpstreamHost("fe80::528:3c87:e7bb:ab08"), "[fe80::528:3c87:e7bb:ab08]");
	assert.equal(streamUpstreamHost("2001:db8::1"), "[2001:db8::1]");
	assert.equal(streamUpstreamHost("::1"), "[::1]");
	assert.equal(streamUpstreamHost("10.0.0.5"), "10.0.0.5");
	assert.equal(streamUpstreamHost("router.internal"), "router.internal");
	assert.equal(streamUpstreamHost(undefined), undefined);
});

test("stream.conf renders an IPv6 upstream as [addr]:port", async () => {
	const { streamUpstreamHost } = _testExports;
	const fsMod = await import("node:fs");
	const { default: utils } = await import("../lib/utils.js");
	const template = fsMod.readFileSync(new URL("../templates/stream.conf", import.meta.url), "utf8");
	const out = await utils.getRenderEngine().parseAndRender(template, {
		id: 4,
		enabled: 1,
		incoming_port: 2525,
		tcp_forwarding: 1,
		udp_forwarding: 1,
		forwarding_host: streamUpstreamHost("2001:db8::25"),
		forwarding_port: 25,
	});
	assert.equal((out.match(/proxy_pass \[2001:db8::25\]:25;/g) || []).length, 2);
});
