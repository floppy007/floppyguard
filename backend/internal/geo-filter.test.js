// Länder-Filter je Proxy-Host: Bereich→CIDR, DB-IP-Liste, Datei-Erzeugung, Fehlerfälle, Einstellungen, Template.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import zlib from "node:zlib";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "fg-geo-filter-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));
process.env.FG_GEO_FILTER_CONF = path.join(tmp, "fg-geo-filter.conf");
process.env.FG_GEO_FILTER_SETTINGS = path.join(tmp, "geo-filter.json");
process.env.FG_GEO_STATS = path.join(tmp, "stats.json");
process.env.FG_GEO_BLOCKED_LOG = path.join(tmp, "blocked.log");
process.env.FG_GEO_DBIP_CACHE = path.join(tmp, "dbip.csv.gz");

const mod = await import("./geo-filter.js");
const {
	default: geo,
	isCidr,
	renderConf,
	hostUsesGeoFilter,
	DEFAULT_COUNTRIES,
	confPath,
	normalizeCountries,
	sanitizeGeoMeta,
	readConfInfo,
	rangeToCidrs,
	parseDbip,
} = mod;
const { default: utils } = await import("../lib/utils.js");

// Nachgebaute DB-IP-Liste: je Land ein /24, je Land ein v6-/32, Rest „Füllzeilen“ (US), damit MIN_ROWS erreicht wird
const ALL = [...DEFAULT_COUNTRIES].sort();
const buildCsv = (countries = ALL, filler = 210000) => {
	const lines = countries.map((cc, i) => `${i + 1}.2.3.0,${i + 1}.2.3.255,${cc}`);
	lines.push(...countries.map((cc, i) => `2a0${i % 10}:${(i + 1).toString(16)}::,2a0${i % 10}:${(i + 1).toString(16)}:ffff:ffff:ffff:ffff:ffff:ffff,${cc}`));
	for (let i = 0; i < filler; i++) lines.push(`100.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255},100.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255},US`);
	return `${lines.join("\n")}\n`;
};
const gz = (text) => zlib.gzipSync(Buffer.from(text));
const CSV_GZ = gz(buildCsv());
const okFetch = (calls = []) => async (url) => {
	calls.push(url);
	return CSV_GZ;
};

test("rangeToCidrs: v4 und v6 exakt zerlegt", () => {
	assert.deepEqual(rangeToCidrs("1.2.3.0", "1.2.3.255"), ["1.2.3.0/24"]);
	assert.deepEqual(rangeToCidrs("10.0.0.1", "10.0.0.6"), ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]);
	assert.deepEqual(rangeToCidrs("141.255.160.0", "141.255.167.255"), ["141.255.160.0/21"]);
	assert.deepEqual(rangeToCidrs("0.0.0.0", "255.255.255.255"), ["0.0.0.0/0"]);
	assert.deepEqual(rangeToCidrs("2a00:1::", "2a00:1:ffff:ffff:ffff:ffff:ffff:ffff"), ["2a00:1::/32"]);
	assert.deepEqual(rangeToCidrs("2001:db8::", "2001:db8::1"), ["2001:db8::/127"]);
	assert.throws(() => rangeToCidrs("1.2.3.4", "::1"), /mischt/);
});

test("parseDbip: nur gewählte Länder, zählt Zeilen", () => {
	const r = parseDbip("1.0.0.0,1.0.0.255,AU\n2.0.0.0,2.0.0.255,DE\n2a00::,2a00::ffff,DE\n", ["DE"]);
	assert.deepEqual(r.ranges, ["2.0.0.0/24", "2a00::/112"]);
	assert.equal(r.rows, 3);
	assert.equal(r.perCountry.DE, 2);
	// angrenzende Bereiche (auch verschiedener Länder) werden zusammengefasst, Lücken nicht
	const m = parseDbip("2.0.0.0,2.0.0.127,DE\n2.0.0.128,2.0.0.255,AT\n2.0.1.0,2.0.1.255,US\n2.0.2.0,2.0.2.255,DE\n", ["AT", "DE"]);
	assert.deepEqual(m.ranges, ["2.0.0.0/24", "2.0.2.0/24"]);
	assert.throws(() => parseDbip("2.0.0.9,2.0.0.1,DE\n", ["DE"]), /verkehrt/);
});

test("isCidr: nur saubere v4/v6-Netze", () => {
	for (const ok of ["1.2.3.0/24", "0.0.0.0/0", "2a00:1::/32", "::1/128"]) assert.equal(isCidr(ok), true, ok);
	for (const bad of ["1.2.3.0", "1.2.3.0/33", "1.2.3.0/24;", "1.2.3.0/24 1; } server {", "fe80::1%eth0/64",
		"2a00::/129", "", null, "/24", "1.2.3.4/x"]) assert.equal(isCidr(bad), false, String(bad));
});

test("hostUsesGeoFilter: nur bei meta.geo_filter/geoFilter === true", () => {
	assert.equal(hostUsesGeoFilter({ meta: { geo_filter: true } }), true);
	assert.equal(hostUsesGeoFilter({ meta: { geoFilter: true } }), true);
	assert.equal(hostUsesGeoFilter({ meta: { geo_filter: "true" } }), false);
	assert.equal(hostUsesGeoFilter({ meta: null }), false);
	assert.equal(hostUsesGeoFilter({}), false);
});

test("renderConf: private Netze erlaubt, ACME bleibt offen, Standard = sperren", () => {
	const out = renderConf(["1.2.3.0/24"], ["DE"]);
	assert.match(out, /geo \$fg_geo_allowed \{\n {2}default 0;/);
	assert.match(out, / {2}10\.0\.0\.0\/8 1;/);
	assert.match(out, / {2}1\.2\.3\.0\/24 1;/);
	assert.match(out, /map "\$fg_geo_allowed:\$uri" \$fg_geo_deny \{\n {2}default 1;\n {2}"~\^1:" 0;/);
	assert.match(out, /acme-challenge/);
	assert.match(out, /DB-IP/);
	assert.match(out, /log_format fg_geo '\$msec \$remote_addr \$host';/);
});

test("ensureConf schreibt eine Notfassung, wenn die Datei fehlt", () => {
	fs.rmSync(confPath(), { force: true });
	assert.equal(geo.ensureConf(), true);
	const out = fs.readFileSync(confPath(), "utf8");
	assert.match(out, /NOTFASSUNG/);
	assert.match(out, /192\.168\.0\.0\/16 1;/);
	assert.equal(geo.ensureConf(), false, "vorhandene Datei bleibt");
});

test("refresh lädt die Liste, ersetzt die Notfassung, lädt nginx nicht ohne reload", async () => {
	const calls = [];
	const changed = await geo.refresh({ reload: false, fetchBuffer: okFetch(calls), now: new Date("2026-11-01T12:00:00Z") });
	assert.equal(changed, true);
	assert.deepEqual(calls, ["https://download.db-ip.com/free/dbip-country-lite-2026-11.csv.gz"]);
	const out = fs.readFileSync(confPath(), "utf8");
	assert.doesNotMatch(out, /NOTFASSUNG/);
	assert.match(out, / {2}1\.2\.3\.0\/24 1;/);
	assert.match(out, / {2}2a00:1::\/32 1;/);
	assert.doesNotMatch(out, /100\.0\.0\.0/, "Länder außerhalb der Auswahl fehlen");
	assert.equal(geo.lastError, null);
	const info = readConfInfo();
	assert.equal(info.ranges, ALL.length * 2);
	assert.deepEqual(info.countries, ALL);
	assert.equal(info.fallback, false);
});

test("Monatsanfang: neue Liste fehlt (404) → Vormonat", async () => {
	const calls = [];
	const fetchBuffer = async (url) => {
		calls.push(url);
		if (url.includes("2026-01")) {
			const err = new Error("HTTP 404");
			err.status = 404;
			throw err;
		}
		return CSV_GZ;
	};
	await geo.refresh({ force: true, reload: false, fetchBuffer, now: new Date("2026-01-01T00:30:00Z") });
	assert.deepEqual(calls.map((u) => u.slice(-14)), ["2026-01.csv.gz", "2025-12.csv.gz"]);
	assert.equal(geo.lastError, null);
});

test("refresh überspringt eine frische Datei, außer mit force", async () => {
	const calls = [];
	assert.equal(await geo.refresh({ reload: false, fetchBuffer: okFetch(calls) }), false);
	assert.equal(calls.length, 0);
	assert.equal(await geo.refresh({ force: true, reload: false, fetchBuffer: okFetch(calls) }), false, "gleiche Daten = unverändert");
	assert.equal(calls.length, 1);
});

test("Fehlerfälle: vorige Datei bleibt, Fehler im Status", async () => {
	const before = fs.readFileSync(confPath(), "utf8");
	const cases = [
		[async () => gz("1.2.3.0,1.2.3.255,DE\n"), /unplausibel/],
		[async () => Buffer.from("<html>Service down</html>"), /incorrect header|unexpected end|invalid/i],
		[async () => gz(buildCsv(["US"])), /Keine Netze/],
		[async () => {
			throw new Error("ECONNRESET");
		}, /ECONNRESET/],
		[async () => {
			const e = new Error("HTTP 500");
			e.status = 500;
			throw e;
		}, /HTTP 500/],
	];
	for (const [fetchBuffer, re] of cases) {
		assert.equal(await geo.refresh({ force: true, reload: false, fetchBuffer }), false);
		assert.match(geo.lastError, re);
		assert.equal(fs.readFileSync(confPath(), "utf8"), before);
	}
});

test("normalizeCountries: nur bekannte ISO-Codes, sortiert, ohne Doppelte", () => {
	assert.deepEqual(normalizeCountries(["de", "AT", "DE", " ch "]), ["AT", "CH", "DE"]);
	assert.throws(() => normalizeCountries(["DE", "XX"]), /Unbekannte Ländercodes: XX/);
	assert.throws(() => normalizeCountries(["DE;", "AT"]), /Unbekannte/);
	assert.throws(() => normalizeCountries([]), /Mindestens ein Land/);
	assert.throws(() => normalizeCountries("DE"), /Liste/);
});

test("save: geänderte Länder → sofort neu laden, Status zeigt Auswahl + Hosts", async () => {
	const calls = [];
	const res = await geo.save({ countries: ["de", "at"] }, { reload: false, fetchBuffer: okFetch(calls) });
	assert.equal(res.changed, true);
	assert.deepEqual(res.countries, ["AT", "DE"]);
	assert.equal(calls.length, 1);
	const st = geo.status([{ id: 13, domain_names: ["skynet.example.com"], enabled: true }]);
	assert.deepEqual(st.countries, ["AT", "DE"]);
	assert.deepEqual(st.active_countries, ["AT", "DE"]);
	assert.equal(st.ranges, 4);
	assert.equal(st.pending, false);
	assert.equal(st.hosts.length, 1);
	assert.ok(st.all_countries.includes("JP") && !st.all_countries.includes("XX"));
	assert.match(st.source, /DB-IP/);
	assert.deepEqual(JSON.parse(fs.readFileSync(process.env.FG_GEO_FILTER_SETTINGS, "utf8")), { countries: ["AT", "DE"] });
	calls.length = 0;
	assert.equal((await geo.save({ countries: ["DE", "AT"] }, { reload: false, fetchBuffer: okFetch(calls) })).changed, false);
	assert.equal(calls.length, 0, "gleiche Auswahl: kein Abruf");
	await assert.rejects(geo.save({ countries: ["ZZ"] }, { reload: false, fetchBuffer: okFetch(calls) }), /Unbekannte/);
	assert.deepEqual(geo.status().countries, ["AT", "DE"], "ungültige Eingabe ändert nichts");
});

test("refresh lädt neu, wenn die Datei andere Länder enthält als eingestellt", async () => {
	fs.writeFileSync(process.env.FG_GEO_FILTER_SETTINGS, JSON.stringify({ countries: ["DE"] }));
	const calls = [];
	assert.equal(await geo.refresh({ reload: false, fetchBuffer: okFetch(calls) }), true);
	assert.equal(calls.length, 1);
	assert.deepEqual(readConfInfo().countries, ["DE"]);
});

const renderProxyHost = async (meta) => {
	const template = fs.readFileSync(new URL("../templates/proxy_host.conf", import.meta.url), "utf8");
	return utils.getRenderEngine().parseAndRender(template, {
		id: 7, domain_names: ["skynet.example.com"], forward_scheme: "http", forward_host: "10.0.0.5",
		forward_port: 80, advanced_config: "", locations: [], use_default_location: true, ipv6: false,
		enabled: 1, meta,
	});
};

test("proxy_host.conf: Filter nur, wenn am Host eingeschaltet", async () => {
	const on = await renderProxyHost({ geo_filter: true });
	assert.match(on, /if \(\$fg_geo_deny\) \{\s*return 403;\s*\}/);
	assert.match(on, /access_log \/data\/logs\/fg-geo-blocked\.log fg_geo if=\$fg_geo_deny;/);
	// server-Ebene, vor location / – gilt auch für eigene Locations
	assert.ok(on.indexOf("$fg_geo_deny") < on.indexOf("location /"));
	assert.doesNotMatch(await renderProxyHost({}), /fg_geo_deny/);
	assert.doesNotMatch(await renderProxyHost({ geo_filter: false }), /fg_geo_deny/);
	assert.doesNotMatch(await renderProxyHost(undefined), /fg_geo_deny/);
});

const { default: stats, buildLookup } = await import("./geo-filter-stats.js");

test("refresh legt die DB-IP-Liste für die Statistik ab", () => {
	assert.ok(fs.existsSync(process.env.FG_GEO_DBIP_CACHE));
});

test("buildLookup: v4/v6 per binärer Suche, unbekannt = null", () => {
	const look = buildLookup("1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\n2a00::,2a00::ffff,DE\n");
	assert.equal(look("8.8.8.8"), "US");
	assert.equal(look("1.0.0.7"), "AU");
	assert.equal(look("2a00::12"), "DE");
	assert.equal(look("9.9.9.9"), null);
	assert.equal(look("kaputt"), null);
});

test("Statistik: zählt Sperren je Land/Host/IP, liest nur neue Zeilen, übersteht Rotation", () => {
	const log = process.env.FG_GEO_BLOCKED_LOG;
	const now = new Date("2026-11-01T12:00:00").getTime();
	const sec = (ms) => (ms / 1000).toFixed(3);
	const factory = () => buildLookup("8.8.8.0,8.8.8.255,US\n1.0.0.0,1.0.0.255,CN\n");
	fs.rmSync(process.env.FG_GEO_STATS, { force: true });
	fs.writeFileSync(log, `${sec(now)} 8.8.8.8 Skynet.Example.com\n${sec(now)} 8.8.8.8 skynet.example.com\n${sec(now - 86400000)} 1.0.0.1 file.example.com\nmüll\n${sec(now)} 7.7.7.7 x.example.com\nhalbe zei`);
	assert.equal(stats.collect({ lookupFactory: factory, now }), 4);
	assert.equal(stats.collect({ lookupFactory: factory, now }), 0, "nichts doppelt");
	let s = stats.summary(now);
	assert.equal(s.total, 4);
	assert.deepEqual(s.countries, [{ code: "US", count: 2 }, { code: "CN", count: 1 }, { code: "ZZ", count: 1 }]);
	assert.deepEqual(s.hosts[0], { host: "skynet.example.com", count: 2 });
	assert.deepEqual(s.top_ips[0], { ip: "8.8.8.8", code: "US", count: 2 });
	assert.equal(s.per_day.length, 30);
	assert.equal(s.per_day.at(-1).count, 3);
	// halbe Zeile wird fertig geschrieben, dann rotiert: Rest aus .1, danach neue Datei
	fs.appendFileSync(log, "le\n");
	fs.renameSync(log, `${log}.1`);
	fs.appendFileSync(`${log}.1`, `${sec(now)} 8.8.8.9 skynet.example.com\n`);
	fs.writeFileSync(log, `${sec(now)} 1.0.0.2 skynet.example.com\n`);
	assert.equal(stats.collect({ lookupFactory: factory, now }), 2);
	s = stats.summary(now);
	assert.equal(s.total, 6);
	assert.equal(s.countries.find((c) => c.code === "CN").count, 2);
});

test("Statistik: Tage älter als 30 werden gelöscht", () => {
	const now = new Date("2026-12-15T12:00:00").getTime();
	fs.writeFileSync(process.env.FG_GEO_BLOCKED_LOG, "");
	stats.collect({ lookupFactory: () => () => "US", now });
	const s = stats.summary(now);
	assert.equal(s.total, 0);
	assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(process.env.FG_GEO_STATS, "utf8")).days), []);
});

test("ältere Dateifassung (ohne/andere Formatnummer) wird neu erzeugt", async () => {
	const cur = fs.readFileSync(confPath(), "utf8");
	fs.writeFileSync(confPath(), cur.replace(/^# Format: \d+\n/m, ""));
	assert.equal(readConfInfo().format, 1);
	const calls = [];
	assert.equal(await geo.refresh({ reload: false, fetchBuffer: okFetch(calls) }), true);
	assert.equal(calls.length, 1);
	assert.equal(readConfInfo().format, mod.CONF_FORMAT);
});

test("sanitizeGeoMeta: nur true schaltet ein, [on] und Strings nicht", () => {
	assert.deepEqual(sanitizeGeoMeta({ geo_filter: ["on"], x: 1 }), { geo_filter: false, x: 1 });
	assert.deepEqual(sanitizeGeoMeta({ geo_filter: "true" }), { geo_filter: false });
	assert.deepEqual(sanitizeGeoMeta({ geo_filter: true }), { geo_filter: true });
	assert.deepEqual(sanitizeGeoMeta({ geoFilter: true }), { geo_filter: true });
	assert.deepEqual(sanitizeGeoMeta({ nginx_online: true }), { nginx_online: true }, "ohne Schlüssel unverändert");
	assert.equal(sanitizeGeoMeta(undefined), undefined);
});
