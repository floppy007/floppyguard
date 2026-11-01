/**
 * Länder-Filter je Proxy-Host ("Nur aus erlaubten Ländern erreichbar").
 *
 * - Erlaubte Länder: Einstellungen → Länder-Filter, gespeichert in /data/geo-filter.json
 *   (Standard EU-27 + Schweiz).
 * - Erzeugt /etc/nginx/conf.d/fg-geo-filter.conf (http-Kontext):
 *     geo $fg_geo_allowed  – 1 für Adressen aus den erlaubten Ländern und private Netze
 *     map $fg_geo_deny     – 1 = sperren; ACME-HTTP-01 (/.well-known/acme-challenge/) bleibt immer offen,
 *                            sonst scheitert die Let's-Encrypt-Erneuerung (Prüfserver stehen u. a. in den USA)
 * - Proxy-Hosts mit meta.geo_filter = true bekommen im server-Block `if ($fg_geo_deny) { return 403; }`
 *   (templates/_geo_filter.conf).
 * - Datenquelle: DB-IP „IP to Country Lite“ (https://db-ip.com, CC BY 4.0, monatlich) – ordnet nach Standort
 *   statt nach RIR-Registrierung (ipdeny führte z. B. Zürcher Hosting-Adressen nicht als CH). Höchstens alle
 *   7 Tage neu geladen, sofort bei geänderter Länderauswahl. Schlägt ein Abruf fehl, bleibt die vorige Datei stehen. Gibt es noch keine, wird eine
 *   Notfassung nur mit privaten Netzen geschrieben (fail-closed: gefilterte Hosts sind dann von außen gesperrt,
 *   nginx startet aber, weil $fg_geo_deny definiert bleibt).
 */
import fs from "node:fs";
import zlib from "node:zlib";
import net from "node:net";
import path from "node:path";
import errs from "../lib/error.js";
import { ipRanges as logger } from "../logger.js";
import internalGeoStats, { dbipCachePath } from "./geo-filter-stats.js";
import internalNginx from "./nginx.js";

// ISO-3166-1 alpha-2 (ohne reservierte Codes) – nur diese Codes dürfen in die Auswahl
const ISO_CODES = new Set(
	("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY " +
		"BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK " +
		"FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR " +
		"IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK " +
		"ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM " +
		"PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF " +
		"TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW").split(" "),
);

export const EU_COUNTRIES = [
	"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
	"IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
];
export const DEFAULT_COUNTRIES = [...EU_COUNTRIES, "CH"];

const PRIVATE_RANGES = [
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
	"::1/128", "fc00::/7", "fe80::/10",
];

export const SOURCE_LABEL = "IP Geolocation by DB-IP (db-ip.com, CC BY 4.0)";
const DBIP_URL = (d) =>
	`https://download.db-ip.com/free/dbip-country-lite-${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}.csv.gz`;
const DOWNLOAD_TIMEOUT_MS = 120000;
const MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024;
// Plausibilität: die vollständige Liste hat > 700.000 Zeilen; deutlich weniger = abgeschnitten/Fehlerseite
const MIN_ROWS = 200000;

const defaultFetchBuffer = async (url) => {
	const res = await fetch(url, { signal: AbortSignal.timeout(DOWNLOAD_TIMEOUT_MS), redirect: "follow" });
	if (!res.ok) {
		const err = new Error(`Download ${url} fehlgeschlagen: HTTP ${res.status}`);
		err.status = res.status;
		throw err;
	}
	const buf = Buffer.from(await res.arrayBuffer());
	if (buf.length > MAX_DOWNLOAD_BYTES) throw new Error(`Download ${url} zu groß (${buf.length} Bytes)`);
	return buf;
};

// ── Adressbereich → CIDR (v4 und v6 über BigInt) ──────────────────────────────
const v4ToBig = (a) => a.split(".").reduce((n, o) => (n << 8n) + BigInt(o), 0n);
const v6ToBig = (a) => {
	const [head, tail] = a.includes("::") ? a.split("::") : [a, null];
	const h = head ? head.split(":") : [];
	const t = tail ? tail.split(":") : [];
	const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
	if (groups.length !== 8) throw new Error(`IPv6 ungültig: ${a}`);
	return groups.reduce((n, g) => (n << 16n) + BigInt(`0x${g || "0"}`), 0n);
};
const bigToV4 = (n) => [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join(".");
const bigToV6 = (n) => {
	const groups = [];
	for (let s = 112n; s >= 0n; s -= 16n) groups.push(((n >> s) & 0xffffn).toString(16));
	// längste Null-Folge kürzen
	let best = [-1, 0];
	for (let i = 0; i < 8; ) {
		if (groups[i] !== "0") { i++; continue; }
		let j = i;
		while (j < 8 && groups[j] === "0") j++;
		if (j - i > best[1] && j - i > 1) best = [i, j - i];
		i = j;
	}
	if (best[0] < 0) return groups.join(":");
	return `${groups.slice(0, best[0]).join(":")}::${groups.slice(best[0] + best[1]).join(":")}`;
};

/** Kleinste CIDR-Liste, die genau [start, end] abdeckt. */
export const rangeToCidrs = (start, end) => {
	const v6 = start.includes(":");
	if (v6 !== end.includes(":")) throw new Error("Bereich mischt IPv4 und IPv6");
	return bigRangeToCidrs(v6 ? v6ToBig(start) : v4ToBig(start), v6 ? v6ToBig(end) : v4ToBig(end), v6);
};

/** Bereich [start, hi] (BigInt) → kleinste CIDR-Liste. */
const bigRangeToCidrs = (start, hi, v6) => {
	const bits = v6 ? 128n : 32n;
	const out = [];
	let lo = start;
	while (lo <= hi) {
		let size = 0n;
		while (size < bits && (lo & ((1n << (size + 1n)) - 1n)) === 0n && lo + (1n << (size + 1n)) - 1n <= hi) size++;
		out.push(`${v6 ? bigToV6(lo) : bigToV4(lo)}/${bits - size}`);
		lo += 1n << size;
	}
	return out;
};

/**
 * DB-IP-CSV (start,end,cc) → CIDRs der gewählten Länder. Aneinandergrenzende Bereiche (auch verschiedener gewählter
 * Länder) werden vorher zusammengefasst – DB-IP unterteilt nach Städten, ohne das wären es ~7× so viele Netze.
 */
export const parseDbip = (csvText, countries) => {
	const wanted = new Set(countries);
	const perCountry = Object.fromEntries(countries.map((c) => [c, 0]));
	const spans = { v4: [], v6: [] };
	let rows = 0;
	for (const line of csvText.split("\n")) {
		if (!line) continue;
		rows++;
		const [start, end, cc] = line.trim().split(",");
		if (!wanted.has(cc)) continue;
		const v6 = start.includes(":");
		if (v6 !== end.includes(":")) throw new Error(`Bereich mischt IPv4 und IPv6: ${start}-${end}`);
		const lo = v6 ? v6ToBig(start) : v4ToBig(start);
		const hi = v6 ? v6ToBig(end) : v4ToBig(end);
		if (hi < lo) throw new Error(`Bereich verkehrt: ${start}-${end}`);
		spans[v6 ? "v6" : "v4"].push([lo, hi]);
		perCountry[cc]++;
	}
	const ranges = [];
	for (const [fam, list] of Object.entries(spans)) {
		list.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
		let cur = null;
		const flush = () => {
			if (cur) ranges.push(...bigRangeToCidrs(cur[0], cur[1], fam === "v6"));
		};
		for (const [lo, hi] of list) {
			if (cur && lo <= cur[1] + 1n) {
				if (hi > cur[1]) cur[1] = hi;
			} else {
				flush();
				cur = [lo, hi];
			}
		}
		flush();
	}
	for (const cidr of ranges) if (!isCidr(cidr)) throw new Error(`Ungültiges Netz aus der Liste: ${cidr}`);
	return { ranges, rows, perCountry };
};

const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;
const MAX_COUNTRIES = 250;

export const confPath = () => process.env.FG_GEO_FILTER_CONF || "/etc/nginx/conf.d/fg-geo-filter.conf";
export const settingsPath = () => process.env.FG_GEO_FILTER_SETTINGS || "/data/geo-filter.json";

/** Strenge CIDR-Prüfung – der Wert landet unverändert in einer von root geladenen nginx-Datei. */
export const isCidr = (value) => {
	if (typeof value !== "string") return false;
	const idx = value.indexOf("/");
	if (idx < 1) return false;
	const addr = value.slice(0, idx);
	const prefix = value.slice(idx + 1);
	if (!/^\d{1,3}$/.test(prefix)) return false;
	if (net.isIPv4(addr)) return Number(prefix) <= 32 && /^[\d.]+$/.test(addr);
	return /^[0-9a-fA-F:]+$/.test(addr) && net.isIPv6(addr) && Number(prefix) <= 128;
};

export const parseZone = (text) =>
	String(text || "")
		.split("\n")
		.map((l) => l.trim())
		.filter((l) => l && !l.startsWith("#"))
		.filter(isCidr);

/** true, wenn der Host den Länder-Filter nutzt (Backend: geo_filter; das Frontend sendet geoFilter → geo_filter). */
export const hostUsesGeoFilter = (host) => {
	const m = host?.meta;
	if (!m || typeof m !== "object") return false;
	return m.geo_filter === true || m.geoFilter === true;
};

/**
 * meta.geo_filter auf einen echten Wahrheitswert bringen (nur true schaltet ein). Ein Formular schickte
 * bei fehlendem Startwert ["on"] – das darf weder als „an“ gelten noch so gespeichert bleiben.
 */
export const sanitizeGeoMeta = (meta) => {
	if (!meta || typeof meta !== "object" || Array.isArray(meta)) return meta;
	if (!("geo_filter" in meta) && !("geoFilter" in meta)) return meta;
	const out = { ...meta, geo_filter: meta.geo_filter === true || meta.geoFilter === true };
	delete out.geoFilter;
	return out;
};

/** Länderauswahl prüfen und normalisieren (Großbuchstaben, sortiert, ohne Doppelte). */
export const normalizeCountries = (input) => {
	if (!Array.isArray(input)) throw new errs.ValidationError("countries muss eine Liste von Ländercodes sein");
	const out = [...new Set(input.map((c) => String(c).trim().toUpperCase()))].sort();
	const bad = out.filter((c) => !ISO_CODES.has(c));
	if (bad.length) throw new errs.ValidationError(`Unbekannte Ländercodes: ${bad.slice(0, 5).join(", ")}`);
	if (!out.length) throw new errs.ValidationError("Mindestens ein Land auswählen");
	if (out.length > MAX_COUNTRIES) throw new errs.ValidationError(`Höchstens ${MAX_COUNTRIES} Länder`);
	return out;
};

export const readSettings = () => {
	try {
		const raw = JSON.parse(fs.readFileSync(settingsPath(), "utf8"));
		return { countries: normalizeCountries(raw.countries) };
	} catch {
		return { countries: [...DEFAULT_COUNTRIES].sort() };
	}
};

const writeSettings = (settings) => {
	const target = settingsPath();
	const tmp = path.join(path.dirname(target), `.geo-filter.json.${process.pid}.${Date.now()}.tmp`);
	fs.writeFileSync(tmp, `${JSON.stringify(settings, null, 2)}\n`, { mode: 0o644 });
	fs.renameSync(tmp, target);
};

// Erhöhen, wenn sich der Aufbau der erzeugten Datei ändert – ältere Dateien werden dann neu erzeugt
export const CONF_FORMAT = 2;
const HEADER_FORMAT = "# Format: ";
const HEADER_COUNTRIES = "# Länder: ";
const HEADER_STAND = "# Stand: ";

export const renderConf = (ranges, countries, { generatedAt = new Date(), complete = true } = {}) =>
	[
		"# Von FloppyGuard erzeugt – Länder-Filter (Proxy-Host-Option, Einstellungen → Länder-Filter). Nicht von Hand ändern.",
		`${HEADER_FORMAT}${CONF_FORMAT}`,
		`${HEADER_COUNTRIES}${countries.join(",")}`,
		`${HEADER_STAND}${generatedAt.toISOString()} · ${SOURCE_LABEL}`,
		complete ? `# Netze: ${ranges.length}` : "# NOTFASSUNG: Länderliste fehlt – nur private Netze erlaubt (fail-closed)",
		// Nur Länder-Sperren protokollieren (Statistik Einstellungen → Länder-Filter)
		"log_format fg_geo '$msec $remote_addr $host';",
		"geo $fg_geo_allowed {",
		"  default 0;",
		...PRIVATE_RANGES.map((r) => `  ${r} 1;`),
		...ranges.map((r) => `  ${r} 1;`),
		"}",
		'map "$fg_geo_allowed:$uri" $fg_geo_deny {',
		"  default 1;",
		'  "~^1:" 0;',
		'  "~^0:/\\.well-known/acme-challenge/" 0;',
		"}",
		"",
	].join("\n");

/** Kopf der erzeugten Datei lesen: Länder, Stand, Anzahl Netze, Notfassung. */
export const readConfInfo = () => {
	let text;
	try {
		text = fs.readFileSync(confPath(), "utf8");
	} catch {
		return { exists: false, countries: [], updatedAt: null, ranges: 0, fallback: true, format: 0 };
	}
	const head = text.split("\n", 8);
	const line = (prefix) => head.find((l) => l.startsWith(prefix))?.slice(prefix.length) || "";
	const ranges = Number((head.find((l) => l.startsWith("# Netze: ")) || "").slice(9)) || 0;
	return {
		exists: true,
		countries: line(HEADER_COUNTRIES).split(",").filter(Boolean),
		updatedAt: line(HEADER_STAND).split(" ")[0] || null,
		ranges,
		fallback: text.includes("NOTFASSUNG"),
		format: Number(line(HEADER_FORMAT)) || 1,
	};
};

const fileAgeMs = (file) => {
	try {
		return Date.now() - fs.statSync(file).mtimeMs;
	} catch {
		return Number.POSITIVE_INFINITY;
	}
};

/** true = Datei geändert. Der Zeitstempel im Kopf zählt nicht als Änderung. */
const writeIfChanged = (file, text) => {
	let current = null;
	try {
		current = fs.readFileSync(file, "utf8");
	} catch {
		// fehlt: schreiben
	}
	const body = (s) => (s || "").split("\n").filter((l) => !l.startsWith(HEADER_STAND)).join("\n");
	if (current !== null && body(current) === body(text)) {
		const now = new Date();
		fs.utimesSync(file, now, now); // Alter zurücksetzen, sonst jeder Lauf neu laden
		return false;
	}
	const tmp = `${file}.tmp`;
	fs.writeFileSync(tmp, text, { encoding: "utf8", mode: 0o644 });
	fs.renameSync(tmp, file);
	return true;
};

const sameList = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

const internalGeoFilter = {
	interval: null,
	processing: null,
	lastError: null,
	lastAttemptAt: null,

	/** Sorgt dafür, dass die Datei existiert (nginx kennt $fg_geo_deny sonst nicht und `nginx -t` scheitert). */
	ensureConf: () => {
		const file = confPath();
		if (fs.existsSync(file)) return false;
		logger.warn(`${file} fehlt – schreibe Notfassung (nur private Netze), bis die Länderliste geladen ist`);
		writeIfChanged(file, renderConf([], readSettings().countries, { complete: false }));
		return true;
	},

	/** Liste laden und Datei schreiben. Ohne `force` nur, wenn älter als 7 Tage, Notfassung oder Länder geändert. */
	refresh: async ({ force = false, reload = true, fetchBuffer = defaultFetchBuffer, now = new Date() } = {}) => {
		if (internalGeoFilter.processing) return internalGeoFilter.processing;
		const file = confPath();
		const { countries } = readSettings();
		const info = readConfInfo();
		const stale =
			fileAgeMs(file) >= MAX_AGE_MS ||
			info.fallback ||
			info.format !== CONF_FORMAT ||
			!sameList(info.countries, countries);
		if (!force && !stale) return false;
		internalGeoFilter.processing = (async () => {
			internalGeoFilter.lastAttemptAt = new Date().toISOString();
			try {
				// Monatsliste; Anfang des Monats ist die neue evtl. noch nicht da → Vormonat
				let gz;
				try {
					gz = await fetchBuffer(DBIP_URL(now));
				} catch (err) {
					if (err.status !== 404) throw err;
					gz = await fetchBuffer(DBIP_URL(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1))));
				}
				const { ranges: all, rows, perCountry } = parseDbip(zlib.gunzipSync(gz).toString("utf8"), countries);
				if (rows < MIN_ROWS) throw new Error(`Nur ${rows} Zeilen – Liste unplausibel`);
				// vollständige Liste für die Länder-Zuordnung der Statistik aufheben
				try {
					fs.writeFileSync(`${dbipCachePath()}.tmp`, gz, { mode: 0o644 });
					fs.renameSync(`${dbipCachePath()}.tmp`, dbipCachePath());
				} catch (err) {
					logger.warn(`Länder-Filter: Liste für die Statistik nicht gespeichert: ${err.message}`);
				}
				const empty = countries.filter((c) => !perCountry[c]);
				if (empty.length === countries.length) throw new Error("Keine Netze für die gewählten Länder gefunden");
				if (empty.length) logger.warn(`Länder-Filter: keine Netze für ${empty.join(", ")}`);
				const ranges = [...new Set(all)];
				const changed = writeIfChanged(file, renderConf(ranges, countries));
				internalGeoFilter.lastError = null;
				logger.info(`Länder-Filter: ${ranges.length} Netze (${countries.join(",")})${changed ? ", nginx wird neu geladen" : ", unverändert"}`);
				if (changed && reload) await internalNginx.reload();
				return changed;
			} catch (err) {
				internalGeoFilter.lastError = err.message;
				logger.error(`Länder-Filter: Abruf fehlgeschlagen, vorige Liste bleibt: ${err.message}`);
				internalGeoFilter.ensureConf();
				return false;
			} finally {
				internalGeoFilter.processing = null;
			}
		})();
		return internalGeoFilter.processing;
	},

	/** Status für Einstellungen → Länder-Filter. `hosts` = Proxy-Hosts mit eingeschaltetem Filter. */
	status: (hosts = []) => {
		const { countries } = readSettings();
		const info = readConfInfo();
		return {
			countries,
			default_countries: [...DEFAULT_COUNTRIES].sort(),
			eu_countries: [...EU_COUNTRIES].sort(),
			active_countries: info.countries,
			updated_at: info.updatedAt,
			ranges: info.ranges,
			fallback: info.fallback,
			pending: !sameList(info.countries, countries),
			refreshing: Boolean(internalGeoFilter.processing),
			last_error: internalGeoFilter.lastError,
			last_attempt_at: internalGeoFilter.lastAttemptAt,
			source: SOURCE_LABEL,
			all_countries: [...ISO_CODES].sort(),
			stats: internalGeoStats.summary(),
			hosts,
		};
	},

	/** Länderauswahl speichern und Liste sofort neu laden. Gibt { changed: boolean } zurück. */
	save: async (input, opts = {}) => {
		const countries = normalizeCountries(input?.countries);
		const before = readSettings().countries;
		writeSettings({ countries });
		const changed = !sameList(before, countries);
		if (changed) await internalGeoFilter.refresh({ force: true, ...opts });
		return { changed, before, countries };
	},

	initTimer: () => {
		internalGeoFilter.interval = setInterval(() => {
			internalGeoFilter.refresh().catch(() => {});
		}, CHECK_INTERVAL_MS);
		internalGeoFilter.interval.unref();
		internalGeoStats.initTimer();
	},
};

export default internalGeoFilter;
