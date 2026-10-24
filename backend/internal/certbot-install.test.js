// lib/certbot.js plugin install (upstream 18b3404/03c70e3) and
// scripts/regenerate-config host types (upstream #5813).
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "node:test";

const { default: utils } = await import("../lib/utils.js");
const { buildPipInstallCommand, installPlugin } = await import("../lib/certbot.js");
const { default: dnsPlugins } = await import("../certbot/dns-plugins.json", { with: { type: "json" } });

// Runs the generated command with stub activate/pip/certbot and returns the
// argv pip received; a ">=" spec that became a redirect would create a file.
const runWithStubs = (cmd) => {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "fg-pip-"));
	try {
		const bin = path.join(dir, "bin");
		fs.mkdirSync(bin);
		fs.writeFileSync(path.join(bin, "pip"), '#!/bin/sh\nfor a in "$@"; do printf "%s\\n" "$a"; done\n', {
			mode: 0o755,
		});
		fs.writeFileSync(path.join(bin, "certbot"), "#!/bin/sh\necho 'certbot 4.1.1'\n", { mode: 0o755 });
		const local = cmd.replace(". /opt/certbot/bin/activate", `PATH=${bin}:$PATH`).replace("&& deactivate", "");
		const out = execFileSync("/bin/sh", ["-c", local], { cwd: dir, encoding: "utf8" });
		return { argv: out.trim().split("\n"), files: fs.readdirSync(dir).filter((f) => f !== "bin") };
	} finally {
		fs.rmSync(dir, { recursive: true, force: true });
	}
};

describe("certbot plugin install command", () => {
	it("passes version specs with >= as one argument, not as a redirect", () => {
		const { argv, files } = runWithStubs(buildPipInstallCommand(dnsPlugins.arvan));
		assert.deepEqual(argv, ["install", "--no-cache-dir", "certbot-dns-arvan>=0.1.0"]);
		assert.deepEqual(files, []);
	});

	it("keeps the $(certbot --version) substitution for {{certbot-version}}", () => {
		const cmd = buildPipInstallCommand(dnsPlugins.cloudflare);
		assert.match(cmd, /\$\(certbot --version/);
		const { argv } = runWithStubs(cmd);
		assert.deepEqual(argv, ["install", "--no-cache-dir", "acme==4.1.1", "certbot-dns-cloudflare==4.1.1"]);
	});

	it("splits multi-word dependencies into separate arguments", () => {
		const { argv } = runWithStubs(buildPipInstallCommand(dnsPlugins.zoneedit));
		assert.deepEqual(argv, ["install", "--no-cache-dir", "--no-deps", "dnspython", "certbot-dns-zoneedit~=0.3.2"]);
	});

	it("does not interpret shell metacharacters in plugin specs", () => {
		const { argv, files } = runWithStubs(
			buildPipInstallCommand({ dependencies: "a;touch x", package_name: "p$(touch y)", version: "'>z" }),
		);
		assert.deepEqual(argv, ["install", "--no-cache-dir", "a;touch", "x", "p$(touch y)'>z"]);
		assert.deepEqual(files, []);
	});
});

describe("installPlugin", () => {
	const origExec = utils.exec;
	afterEach(() => {
		utils.exec = origExec;
	});

	it("uses SETUPTOOLS_USE_DISTUTILS=local and does not mutate the plugin list", async () => {
		const before = JSON.stringify(dnsPlugins.cloudflare);
		let seen = null;
		utils.exec = async (cmd, opts) => {
			seen = { cmd, env: opts.env };
			return "";
		};
		await installPlugin("cloudflare");
		assert.equal(seen.env.SETUPTOOLS_USE_DISTUTILS, "local");
		assert.equal(JSON.stringify(dnsPlugins.cloudflare), before);
		assert.equal(seen.cmd, buildPipInstallCommand(dnsPlugins.cloudflare));
	});
});

describe("scripts/regenerate-config", () => {
	it("configures every row with its own model and host type", () => {
		const src = fs.readFileSync(new URL("../scripts/regenerate-config", import.meta.url), "utf8");
		assert.match(src, /internalNginx\.configure\(model, hostType, row\)/);
		assert.doesNotMatch(src, /configure\(proxyHostModel, "proxy_host"/);
		for (const [model, type] of [
			["proxyHostModel", "proxy_host"],
			["redirectionHostModel", "redirection_host"],
			["deadHostModel", "dead_host"],
			["streamModel", "stream"],
		]) {
			assert.match(src, new RegExp(`processItems\\(${model}, "[^"]+", "${type}"\\)`));
		}
	});
});
