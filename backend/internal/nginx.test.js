import assert from "node:assert/strict";
import test from "node:test";
import { _testExports } from "./nginx.js";

const { assertSafeAdvancedConfig, assertSafeForwardField } = _testExports;

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
	assert.throws(() => assertSafeAdvancedConfig("location /leak { alias /; autoindex on; }"), /forbidden nginx directive: alias/);
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
	assert.throws(() => assertSafeAdvancedConfig("load_module /tmp/evil.so;"), /forbidden nginx directive: load_module/);
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
	assert.throws(
		() => assertSafeForwardField("1.2.3.4\n  deny all;", "forwarding_host"),
		/forwarding_host/,
	);
	assert.doesNotThrow(() => assertSafeForwardField("10.0.0.1", "forwarding_host"));
	assert.doesNotThrow(() => assertSafeForwardField("backend.internal", "forwarding_host"));
});
