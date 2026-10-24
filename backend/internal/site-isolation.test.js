import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { evaluateFlow } from "./agent-ingress-catalog.js";
import { createLinkLoader, createSiteIsolationApplier } from "./site-isolation.js";
import { buildSiteIsolationNft, normalizePair, siteIsolationVerdict } from "./site-isolation-rules.js";

const H = "wg0:88I9yCmRuMLXDyUxAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const D = "wg0:FPfjO8lOu0b5+foyAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const links = () => [
	{
		id: H,
		name: "Hinderlich Office",
		type: "site-to-site",
		importedNetworks: ["192.168.210.0/24", "10.4.0.0/16"],
		tunnelAddresses: ["10.10.0.7/32"],
	},
	{
		id: D,
		name: "Daniel Home",
		type: "site-to-site",
		importedNetworks: ["192.168.111.0/24"],
		tunnelAddresses: ["10.10.0.5/32"],
	},
];
const quiet = { info() {}, warn() {}, error() {} };

function harness({ failCheck = false, failApply = false, tableMissing = false, input } = {}) {
	const calls = [];
	const dir = mkdtempSync(path.join(os.tmpdir(), "fg-sites-test-"));
	const persist = path.join(dir, "nftables.d", "floppyguard-sites.nft");
	let current = input || { pairs: [normalizePair(H, D)], links: links() };
	const applier = createSiteIsolationApplier({
		execFile: async (file, args) => {
			const content = args.includes("-f") ? readFileSync(args[args.length - 1], "utf8") : null;
			calls.push({ file, args, content });
			if (args[0] === "-c" && failCheck) {
				const e = new Error("nft failed");
				e.stderr = "Error: syntax error";
				throw e;
			}
			if (args[0] === "-f" && failApply) throw new Error("apply failed");
			if (args[0] === "list" && tableMissing) throw new Error("No such file or directory");
			return { stdout: "", stderr: "" };
		},
		fs: fsp,
		tmpDir: dir,
		persistPath: () => persist,
		nftBin: () => "nft",
		loadInput: async () => {
			if (current instanceof Error) throw current;
			return current;
		},
		log: quiet,
		now: () => 1000,
	});
	return {
		applier,
		calls,
		persist,
		dir,
		set: (v) => {
			current = v;
		},
		cleanup: () => rmSync(dir, { recursive: true, force: true }),
	};
}

test("apply: nft -c then nft -f with the generated script, persisted, tmp removed", async () => {
	const h = harness();
	try {
		const res = await h.applier.apply();
		assert.equal(res.ok, true);
		assert.equal(res.changed, true);
		assert.deepEqual(
			h.calls.map((c) => c.args.slice(0, 2)),
			[
				["-c", "-f"],
				["-f", h.calls[1].args[1]],
			],
		);
		const expected = buildSiteIsolationNft({ pairs: [normalizePair(H, D)], links: links() });
		assert.equal(h.calls[0].content, expected);
		assert.equal(h.calls[1].content, expected);
		assert.equal(readFileSync(h.persist, "utf8"), expected);
		assert.equal(res.persisted, h.persist);
		// temp dir cleaned up (only the persist dir is left)
		assert.deepEqual(
			(await fsp.readdir(h.dir)).filter((n) => n.startsWith("fg-sites-")),
			[],
		);
		// unchanged + table present → only a `list table` probe, no re-apply
		const again = await h.applier.apply();
		assert.equal(again.changed, false);
		assert.deepEqual(h.calls[2].args, ["list", "table", "inet", "floppyguard_sites"]);
		assert.equal(h.calls.length, 3);
	} finally {
		h.cleanup();
	}
});

test("apply: unchanged but table vanished → re-applied", async () => {
	const h = harness({ tableMissing: true });
	try {
		await h.applier.apply();
		const n = h.calls.length;
		const res = await h.applier.apply();
		assert.equal(res.ok, true);
		assert.deepEqual(
			h.calls.slice(n).map((c) => c.args[0]),
			["list", "-c", "-f"],
		);
	} finally {
		h.cleanup();
	}
});

test("apply: nft -c failure never runs nft -f nor writes the boot file", async () => {
	const h = harness({ failCheck: true });
	try {
		const res = await h.applier.apply();
		assert.equal(res.ok, false);
		assert.match(res.error, /syntax error/);
		assert.deepEqual(
			h.calls.map((c) => c.args[0]),
			["-c"],
		);
		assert.throws(() => readFileSync(h.persist, "utf8"));
		assert.equal(res.hash, null);
	} finally {
		h.cleanup();
	}
});

test("apply: failure after a good apply keeps the old hash/file and reports the error; next success clears it", async () => {
	let fail = false;
	const calls = [];
	const dir = mkdtempSync(path.join(os.tmpdir(), "fg-sites-test-"));
	const persist = path.join(dir, "out.nft");
	let input = { pairs: [normalizePair(H, D)], links: links() };
	const applier = createSiteIsolationApplier({
		execFile: async (_f, args) => {
			calls.push(args);
			if (fail && args[0] === "-c")
				throw Object.assign(new Error("x"), { stderr: "Error: conflicting intervals" });
			return { stdout: "" };
		},
		tmpDir: dir,
		persistPath: () => persist,
		loadInput: async () => input,
		log: quiet,
		now: () => 5,
	});
	try {
		const ok = await applier.apply();
		const file = readFileSync(persist, "utf8");
		fail = true;
		input = { pairs: [], links: links() };
		const bad = await applier.apply();
		assert.equal(bad.ok, false);
		assert.equal(bad.hash, ok.hash);
		assert.match(bad.error, /conflicting intervals/);
		assert.equal(readFileSync(persist, "utf8"), file);
		fail = false;
		const good = await applier.apply();
		assert.equal(good.ok, true);
		assert.equal(good.error, null);
		assert.notEqual(good.hash, ok.hash);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("apply: unreadable input (e.g. corrupt metadata) never touches nft", async () => {
	const h = harness({ input: new Error("metadata store is corrupt") });
	try {
		const res = await h.applier.apply();
		assert.equal(res.ok, false);
		assert.match(res.error, /corrupt/);
		assert.equal(h.calls.length, 0);
	} finally {
		h.cleanup();
	}
});

test("apply: calls are serialized", async () => {
	const order = [];
	let active = 0;
	const dir = mkdtempSync(path.join(os.tmpdir(), "fg-sites-test-"));
	const applier = createSiteIsolationApplier({
		execFile: async (_f, args) => {
			active++;
			assert.equal(active, 1);
			order.push(args[0]);
			await new Promise((r) => setTimeout(r, 5));
			active--;
			return { stdout: "" };
		},
		tmpDir: dir,
		persistPath: () => path.join(dir, "x.nft"),
		loadInput: async () => ({ pairs: [normalizePair(H, D)], links: links() }),
		log: quiet,
	});
	try {
		await Promise.all([applier.apply({ force: true }), applier.apply({ force: true })]);
		assert.deepEqual(order, ["-c", "-f", "-c", "-f"]);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("loadLinks: status unavailable or failing keeps the last known tunnel /32s", async () => {
	const meta = {
		links: {
			[H]: { name: "Hinderlich Office", type: "site-to-site", importedNetworks: ["192.168.210.0/24"] },
			[D]: { name: "Daniel Home", type: "site-to-site", importedNetworks: ["192.168.111.0/24"] },
		},
	};
	let mode = "ok";
	const load = createLinkLoader({
		readMetadataStore: async () => meta,
		getStatus: async () => {
			if (mode === "throw") throw new Error("wg show failed");
			if (mode === "down") return { available: false, links: [] };
			if (mode === "partial")
				return { available: true, links: [{ id: D, tunnelAddresses: ["10.10.0.5/32"], active: true }] };
			return {
				available: true,
				links: [
					{ id: H, tunnelAddresses: ["10.10.0.7/32"], active: true },
					{ id: D, tunnelAddresses: ["10.10.0.5/32"], active: true },
				],
			};
		},
		log: quiet,
	});
	const tunnels = (ls) => Object.fromEntries(ls.map((l) => [l.id, l.tunnelAddresses]));
	const first = await load();
	assert.deepEqual(tunnels(first), { [H]: ["10.10.0.7/32"], [D]: ["10.10.0.5/32"] });
	for (mode of ["throw", "down", "partial"]) {
		const ls = await load();
		assert.deepEqual(tunnels(ls), { [H]: ["10.10.0.7/32"], [D]: ["10.10.0.5/32"] }, mode);
		// the script built from it still drops the tunnel addresses
		const script = buildSiteIsolationNft({ pairs: [normalizePair(H, D)], links: ls.map((l) => ({ ...l })) });
		assert.match(script, /10\.10\.0\.7\/32/);
		assert.match(script, /10\.10\.0\.5\/32/);
	}
	// a live link WITH an empty tunnel list is believed (address really removed)
	mode = "ok";
	await load();
});

test("loadLinks: status unavailable keeps the live-derived type and networks of metadata entries without them", async () => {
	const meta = {
		links: {
			[H]: { name: "Hinderlich Office" },
			[D]: { name: "Daniel Home", type: "site-to-site" },
		},
	};
	let mode = "ok";
	const load = createLinkLoader({
		readMetadataStore: async () => meta,
		getStatus: async () => {
			if (mode === "throw") throw new Error("wg show failed");
			if (mode === "down") return { available: false, links: [] };
			const liveH = {
				id: H,
				type: "site-to-site",
				importedNetworks: ["192.168.210.0/24"],
				tunnelAddresses: ["10.10.0.7/32"],
				active: true,
			};
			const liveD = {
				id: D,
				type: "site-to-site",
				importedNetworks: ["192.168.111.0/24"],
				tunnelAddresses: ["10.10.0.5/32"],
				active: true,
			};
			return { available: true, links: mode === "partial" ? [liveD] : [liveH, liveD] };
		},
		log: quiet,
	});
	const view = (ls) =>
		Object.fromEntries(ls.map((l) => [l.id, [l.type, l.importedNetworks, l.tunnelAddresses, l.live]]));
	const expected = {
		[H]: ["site-to-site", ["192.168.210.0/24"], ["10.10.0.7/32"], true],
		[D]: ["site-to-site", ["192.168.111.0/24"], ["10.10.0.5/32"], true],
	};
	assert.deepEqual(view(await load()), expected);
	for (mode of ["throw", "down", "partial"]) {
		const ls = await load();
		assert.deepEqual(view(ls), expected, mode);
		const script = buildSiteIsolationNft({ pairs: [normalizePair(H, D)], links: ls });
		assert.match(script, /192\.168\.210\.0\/24/, mode);
		assert.match(script, /192\.168\.111\.0\/24/, mode);
	}
});

test("apply: a pair dropped because a link has no live view (cold start, wg down) keeps the previous table", async () => {
	const E = "wg0:EEEEEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAAAAAAAAA=";
	const meta = {
		links: {
			[H]: { name: "Hinderlich Office", type: "site-to-site", importedNetworks: ["192.168.210.0/24"] },
			// type/networks only in the live status (inferred from AllowedIPs)
			[D]: { name: "Daniel Home" },
			[E]: { name: "Erika", type: "site-to-site", importedNetworks: ["192.168.50.0/24"] },
		},
	};
	let up = false;
	const load = createLinkLoader({
		readMetadataStore: async () => meta,
		getStatus: async () =>
			up
				? {
						available: true,
						links: [{ id: D, type: "site-to-site", importedNetworks: ["192.168.111.0/24"], active: true }],
					}
				: { available: true, links: [] },
		log: quiet,
	});
	const pairs = [normalizePair(H, D), normalizePair(H, E)];
	const h = harness();
	try {
		h.set({ pairs, links: await load() });
		const bad = await h.applier.apply({ force: true });
		assert.equal(bad.ok, false);
		assert.equal(bad.error_code, "links-unresolved");
		assert.match(bad.error, /WireGuard-Status nicht lesbar/);
		assert.equal(h.calls.filter((c) => c.args.includes("-f")).length, 0, "nft never ran");
		await assert.rejects(fsp.readFile(h.persist, "utf8"), "boot file untouched");
		up = true;
		h.set({ pairs, links: await load() });
		const ok = await h.applier.apply({ force: true });
		assert.equal(ok.ok, true);
		assert.deepEqual(ok.applied_pairs.sort(), pairs.map((p) => `${p.a}|${p.b}`).sort());
	} finally {
		h.cleanup();
	}
});

test("apply: a preloaded input skips loadInput", async () => {
	let loads = 0;
	const h = harness();
	try {
		const applier = createSiteIsolationApplier({
			execFile: async () => ({ stdout: "", stderr: "" }),
			fs: fsp,
			tmpDir: h.dir,
			persistPath: () => h.persist,
			nftBin: () => "nft",
			loadInput: async () => {
				loads++;
				return { pairs: [], links: [] };
			},
			log: quiet,
			now: () => 1000,
		});
		const res = await applier.apply({ force: true, input: { pairs: [normalizePair(H, D)], links: links() } });
		assert.equal(res.ok, true);
		assert.equal(res.pairs, 1);
		assert.equal(loads, 0);
	} finally {
		h.cleanup();
	}
});

test("start: SITE_ISOLATION_DISABLED=true never runs nft", async () => {
	const prev = process.env.SITE_ISOLATION_DISABLED;
	const prevBin = process.env.NFT_BIN;
	process.env.SITE_ISOLATION_DISABLED = "true";
	// would fail loudly if start() reached the applier
	process.env.NFT_BIN = "/nonexistent/nft-must-not-run";
	try {
		const { default: internalSiteIsolation } = await import("./site-isolation.js");
		assert.equal(await internalSiteIsolation.start(), null);
	} finally {
		if (prev === undefined) delete process.env.SITE_ISOLATION_DISABLED;
		else process.env.SITE_ISOLATION_DISABLED = prev;
		if (prevBin === undefined) delete process.env.NFT_BIN;
		else process.env.NFT_BIN = prevBin;
	}
});

test("apply: stored pairs but no resolvable site links (empty/missing metadata) keep the previous table", async () => {
	const h = harness();
	try {
		const ok = await h.applier.apply();
		assert.equal(ok.ok, true);
		const n = h.calls.length;
		const file = readFileSync(h.persist, "utf8");
		// metadata store missing → loadLinks() returns no links at all
		h.set({ pairs: [normalizePair(H, D)], links: [] });
		// the first miss holds the last sets (unchanged script → no nft write)
		const held = await h.applier.apply();
		assert.equal(held.ok, true);
		assert.ok(held.warnings.some((w) => w.code === "link-missing-held"));
		// second miss: fail closed instead of lifting the separation
		const bad = await h.applier.apply({ force: true });
		assert.equal(bad.ok, false);
		assert.equal(bad.error_code, "links-unresolved");
		assert.equal(bad.hash, ok.hash);
		assert.equal(
			h.calls.slice(n).filter((c) => c.args[0] === "-f" || c.args[0] === "-c").length,
			0,
			"nft never ran with the weakened script",
		);
		assert.equal(readFileSync(h.persist, "utf8"), file);
		// links re-created under new keys: same verdict
		h.set({
			pairs: [normalizePair(H, D)],
			links: links().map((l) => ({ ...l, id: `${l.id.slice(0, 10)}NEW=` })),
		});
		const bad2 = await h.applier.apply({ force: true });
		assert.equal(bad2.error_code, "links-unresolved");
	} finally {
		h.cleanup();
	}
});

test("apply: a vanished link keeps its last sets for one apply, then the pair is lifted", async () => {
	const F2 = "wg0:3/5dhEQsF68H43gPAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
	const three = () => [
		...links(),
		{ id: F2, name: "Floppy Home", type: "site-to-site", importedNetworks: ["10.3.10.0/24"], tunnelAddresses: [] },
	];
	const pairs = [normalizePair(H, D), normalizePair(H, F2)];
	const h = harness({ input: { pairs, links: three() } });
	try {
		await h.applier.apply();
		h.set({ pairs, links: links() }); // Floppy Home gone
		const held = await h.applier.apply();
		assert.equal(held.ok, true);
		assert.equal(held.pairs, 2);
		assert.match(readFileSync(h.persist, "utf8"), /10\.3\.10\.0\/24/);
		const lifted = await h.applier.apply();
		assert.equal(lifted.ok, true);
		assert.equal(lifted.pairs, 1);
		assert.doesNotMatch(readFileSync(h.persist, "utf8"), /10\.3\.10\.0\/24/);
		assert.ok(lifted.warnings.some((w) => w.code === "link-missing"));
		assert.deepEqual(lifted.applied_pairs, [`${normalizePair(H, D).a}|${normalizePair(H, D).b}`]);
	} finally {
		h.cleanup();
	}
});

test("apply: persist failure stays reported on unchanged applies and is retried until it works", async () => {
	const dir = mkdtempSync(path.join(os.tmpdir(), "fg-sites-test-"));
	let failWrite = true;
	const fs = {
		...fsp,
		rename: async (a, b) => {
			if (failWrite) throw Object.assign(new Error("EROFS: read-only file system"), { code: "EROFS" });
			return fsp.rename(a, b);
		},
	};
	const persist = path.join(dir, "d", "sites.nft");
	const applier = createSiteIsolationApplier({
		execFile: async () => ({ stdout: "" }),
		fs,
		tmpDir: dir,
		persistPath: () => persist,
		loadInput: async () => ({ pairs: [normalizePair(H, D)], links: links() }),
		log: quiet,
	});
	try {
		const a = await applier.apply();
		assert.equal(a.ok, true);
		assert.equal(a.persisted, null);
		assert.ok(a.warnings.some((w) => w.code === "persist-failed"));
		const b = await applier.apply(); // unchanged hash → fast path
		assert.equal(b.changed, false);
		assert.ok(
			b.warnings.some((w) => w.code === "persist-failed"),
			"warning must survive the fast path",
		);
		failWrite = false;
		const c = await applier.apply();
		assert.equal(c.changed, false);
		assert.equal(c.persisted, persist);
		assert.ok(!c.warnings.some((w) => w.code === "persist-failed"));
		assert.equal(
			readFileSync(persist, "utf8"),
			buildSiteIsolationNft({ pairs: [normalizePair(H, D)], links: links() }),
		);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("apply: applied_pairs follow the last successful apply only", async () => {
	let fail = false;
	const dir = mkdtempSync(path.join(os.tmpdir(), "fg-sites-test-"));
	const F2 = "wg0:3/5dhEQsF68H43gPAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
	const ls = [...links(), { id: F2, name: "Floppy Home", type: "site-to-site", importedNetworks: ["10.3.10.0/24"] }];
	let pairs = [normalizePair(H, D)];
	const applier = createSiteIsolationApplier({
		execFile: async (_f, args) => {
			if (fail && args[0] === "-c") throw new Error("boom");
			return { stdout: "" };
		},
		tmpDir: dir,
		persistPath: () => path.join(dir, "x.nft"),
		loadInput: async () => ({ pairs, links: ls }),
		log: quiet,
	});
	try {
		const ok = await applier.apply();
		assert.equal(ok.applied_pairs.length, 1);
		fail = true;
		pairs = [normalizePair(H, D), normalizePair(D, F2)];
		const bad = await applier.apply();
		assert.equal(bad.ok, false);
		assert.deepEqual(bad.applied_pairs, ok.applied_pairs);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("evaluateFlow: site isolation wins over Freigaben", () => {
	const pairs = [normalizePair(H, D)];
	const isolation = siteIsolationVerdict({ pairs, links: links(), src: "192.168.210.5", dst: "192.168.111.10" });
	const r = evaluateFlow({
		mode: "open",
		rules: [{ id: 1, name: "all", sources: [], destinations: [], ports: [], enabled: true }],
		ownNets: ["192.168.111.0/24"],
		src: "192.168.210.5/32",
		dst: "192.168.111.10/32",
		isolation,
	});
	assert.equal(r.allowed, false);
	assert.equal(r.filtered, true);
	assert.equal(r.reason, "site-isolation");
	assert.equal(
		r.site_isolation.name_a === "Hinderlich Office" || r.site_isolation.name_b === "Hinderlich Office",
		true,
	);
	const notApplied = evaluateFlow({
		ownNets: ["192.168.111.0/24"],
		src: "192.168.210.5/32",
		dst: "192.168.111.10/32",
		isolation: { ...isolation, applied: false },
	});
	assert.ok(notApplied.notes.includes("site-isolation-not-applied"));
	// not blocked → unchanged behaviour
	const open = evaluateFlow({
		ownNets: ["192.168.111.0/24"],
		src: "192.168.11.5/32",
		dst: "192.168.111.10/32",
		isolation: { blocked: false, partial: false },
	});
	assert.equal(open.reason, "open-mode");
});

// Real syntax + atomic replace check in a throwaway network namespace. Needs root
// plus `ip` and `nft`; skipped otherwise. Never touches the host's own ruleset.
const canNetns =
	process.getuid?.() === 0 && spawnSync("nft", ["--version"]).status === 0 && spawnSync("ip", ["-V"]).status === 0;

test("real nft: generated script loads, replaces atomically, bad script keeps old table", { skip: !canNetns }, () => {
	const ns = `fgsites${process.pid}`;
	const dir = mkdtempSync(path.join(os.tmpdir(), "fg-sites-nft-"));
	const run = (...args) => spawnSync("ip", ["netns", "exec", ns, "nft", ...args], { encoding: "utf8" });
	assert.equal(spawnSync("ip", ["netns", "add", ns]).status, 0);
	try {
		const f1 = path.join(dir, "a.nft");
		writeFileSync(f1, buildSiteIsolationNft({ pairs: [normalizePair(H, D)], links: links() }));
		let r = run("-c", "-f", f1);
		assert.equal(r.status, 0, r.stderr);
		r = run("-f", f1);
		assert.equal(r.status, 0, r.stderr);
		// applying twice works (the create+delete prologue)
		r = run("-f", f1);
		assert.equal(r.status, 0, r.stderr);
		let list = run("list", "table", "inet", "floppyguard_sites");
		assert.match(list.stdout, /counter packets 0 bytes 0 drop/);
		assert.match(list.stdout, /priority filter - 10; policy accept;/);
		// empty pair list: table stays, no drops
		const f2 = path.join(dir, "b.nft");
		writeFileSync(f2, buildSiteIsolationNft({ pairs: [], links: links() }));
		r = run("-f", f2);
		assert.equal(r.status, 0, r.stderr);
		list = run("list", "table", "inet", "floppyguard_sites");
		assert.doesNotMatch(list.stdout, /drop/);
		// a broken script fails as one transaction: the previous table survives
		r = run("-f", f1);
		assert.equal(r.status, 0, r.stderr);
		const bad = path.join(dir, "bad.nft");
		writeFileSync(bad, readFileSync(f1, "utf8").replace("10.10.0.5/32", "10.10.0.5/32, 300.1.1.1"));
		r = run("-f", bad);
		assert.notEqual(r.status, 0);
		list = run("list", "table", "inet", "floppyguard_sites");
		assert.match(list.stdout, /drop/);
		assert.match(list.stdout, /10\.10\.0\.5/);
		// other tables in the namespace are left alone
		assert.equal(run("add", "table", "inet", "filter").status, 0);
		assert.equal(run("-f", f2).status, 0);
		assert.equal(run("list", "table", "inet", "filter").status, 0);
	} finally {
		spawnSync("ip", ["netns", "del", ns]);
		rmSync(dir, { recursive: true, force: true });
	}
});

test("evaluateFlow: a manual hub drop (no pair) is reported as site-isolation with the rule", () => {
	const r = evaluateFlow({
		ownNets: ["192.168.111.0/24"],
		src: "192.168.210.5/32",
		dst: "192.168.111.10/32",
		isolation: {
			blocked: true,
			partial: false,
			manual: { family: "inet", table: "filter", chain: "forward", comment: "x" },
			applied: true,
		},
	});
	assert.equal(r.reason, "site-isolation");
	assert.equal(r.site_isolation, null);
	assert.equal(r.site_isolation_manual.table, "filter");
});
