/**
 * Statistik des Länder-Filters: Welche Länder/IPs/Hosts wurden in den letzten 30 Tagen gesperrt?
 *
 * nginx schreibt jede Länder-Sperre (nur diese, `if=$fg_geo_deny`) als "<msec> <ip> <host>" nach
 * /data/logs/fg-geo-blocked.log (templates/_geo_filter.conf, log_format fg_geo in fg-geo-filter.conf).
 * collect() liest alle 5 Minuten die neuen Zeilen (Offset + Inode, übersteht logrotate mit delaycompress),
 * ordnet jede IP über die zuletzt geladene DB-IP-Liste einem Land zu und zählt je Tag nach Land, Host und IP.
 * Gespeichert in /data/geo-filter-stats.json, Tage älter als 30 werden gelöscht.
 */
import fs from "node:fs";
import net from "node:net";
import zlib from "node:zlib";
import { ipRanges as logger } from "../logger.js";

export const RETENTION_DAYS = 30;
const MAX_READ_BYTES = 64 * 1024 * 1024;
const MAX_IPS_PER_DAY = 500;
const MAX_HOSTS_PER_DAY = 200;

export const statsPath = () => process.env.FG_GEO_STATS || "/data/geo-filter-stats.json";
export const blockedLogPath = () => process.env.FG_GEO_BLOCKED_LOG || "/data/logs/fg-geo-blocked.log";
export const dbipCachePath = () => process.env.FG_GEO_DBIP_CACHE || "/data/geo-filter-dbip.csv.gz";

const dayKey = (ms) => {
	const d = new Date(ms);
	return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
};

const v4ToNum = (a) => a.split(".").reduce((n, o) => n * 256 + Number(o), 0);
const v6ToBig = (a) => {
	const [head, tail] = a.includes("::") ? a.split("::") : [a, null];
	const h = head ? head.split(":") : [];
	const t = tail ? tail.split(":") : [];
	const groups = tail === null ? h : [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
	return groups.reduce((n, g) => (n << 16n) + BigInt(`0x${g || "0"}`), 0n);
};

/** Länder-Suche über die DB-IP-Liste (sortierte Bereiche, binäre Suche). */
export const buildLookup = (csvText) => {
	const v4 = [];
	const v6 = [];
	for (const line of csvText.split("\n")) {
		if (!line) continue;
		const [start, end, cc] = line.trim().split(",");
		if (!/^[A-Z]{2}$/.test(cc || "")) continue;
		if (start.includes(":")) v6.push([v6ToBig(start), v6ToBig(end), cc]);
		else v4.push([v4ToNum(start), v4ToNum(end), cc]);
	}
	const cmp = (a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
	v4.sort(cmp);
	v6.sort(cmp);
	const find = (list, x) => {
		let lo = 0;
		let hi = list.length - 1;
		while (lo <= hi) {
			const mid = (lo + hi) >> 1;
			const [s, e, cc] = list[mid];
			if (x < s) hi = mid - 1;
			else if (x > e) lo = mid + 1;
			else return cc;
		}
		return null;
	};
	return (ip) => {
		if (net.isIPv4(ip)) return find(v4, v4ToNum(ip));
		if (net.isIPv6(ip)) return find(v6, v6ToBig(ip));
		return null;
	};
};

const readStats = () => {
	try {
		const s = JSON.parse(fs.readFileSync(statsPath(), "utf8"));
		return { inode: s.inode ?? null, offset: Number(s.offset) || 0, days: s.days && typeof s.days === "object" ? s.days : {} };
	} catch {
		return { inode: null, offset: 0, days: {} };
	}
};

const writeStats = (stats) => {
	const target = statsPath();
	const tmp = `${target}.${process.pid}.tmp`;
	fs.writeFileSync(tmp, JSON.stringify(stats), { mode: 0o644 });
	fs.renameSync(tmp, target);
};

const readFrom = (file, offset) => {
	const fd = fs.openSync(file, "r");
	try {
		const size = fs.fstatSync(fd).size;
		if (offset >= size) return { text: "", end: size };
		const len = Math.min(size - offset, MAX_READ_BYTES);
		const buf = Buffer.alloc(len);
		fs.readSync(fd, buf, 0, len, offset);
		// nur bis zur letzten vollständigen Zeile
		const lastNl = buf.lastIndexOf(10);
		if (lastNl < 0) return { text: "", end: offset };
		return { text: buf.subarray(0, lastNl + 1).toString("utf8"), end: offset + lastNl + 1 };
	} finally {
		fs.closeSync(fd);
	}
};

const trimMap = (obj, max) =>
	Object.keys(obj).length <= max
		? obj
		: Object.fromEntries(
				Object.entries(obj)
					.sort((a, b) => b[1] - a[1])
					.slice(0, max),
			);

const internalGeoStats = {
	interval: null,
	running: false,

	/**
	 * Neue Zeilen auswerten. `lookupFactory` (Tests) liefert ip → Ländercode; Standard = DB-IP-Cache.
	 * @returns {number} Anzahl neu gezählter Sperren
	 */
	collect: ({ lookupFactory, now = Date.now() } = {}) => {
		if (internalGeoStats.running) return 0;
		internalGeoStats.running = true;
		try {
			const stats = readStats();
			const file = blockedLogPath();
			const chunks = [];
			let st = null;
			try {
				st = fs.statSync(file);
			} catch {
				// noch keine Sperre protokolliert
			}
			if (st) {
				if (stats.inode !== null && st.ino !== stats.inode) {
					// rotiert: Rest der alten Datei (jetzt .1, dank delaycompress unkomprimiert) noch lesen
					try {
						const old = `${file}.1`;
						if (fs.statSync(old).ino === stats.inode) chunks.push(readFrom(old, stats.offset).text);
					} catch {
						// alte Datei weg: Rest verloren, egal
					}
					stats.offset = 0;
				}
				if (st.size < stats.offset) stats.offset = 0; // abgeschnitten
				const { text, end } = readFrom(file, stats.offset);
				chunks.push(text);
				stats.inode = st.ino;
				stats.offset = end;
			}

			let lookup = null;
			const cache = new Map();
			const countryOf = (ip) => {
				if (cache.has(ip)) return cache.get(ip);
				if (!lookup) {
					lookup = lookupFactory
						? lookupFactory()
						: (() => {
								try {
									return buildLookup(zlib.gunzipSync(fs.readFileSync(dbipCachePath())).toString("utf8"));
								} catch (err) {
									logger.warn(`Länder-Statistik: keine Länderliste für die Zuordnung (${err.message})`);
									return () => null;
								}
							})();
				}
				const cc = lookup(ip) || "ZZ";
				cache.set(ip, cc);
				return cc;
			};

			let counted = 0;
			const cutoff = dayKey(now - RETENTION_DAYS * 86400000);
			for (const text of chunks) {
				for (const line of text.split("\n")) {
					const [msec, ip, host] = line.trim().split(" ");
					const ms = Math.round(Number(msec) * 1000);
					if (!ms || !ip || !net.isIP(ip)) continue;
					const day = dayKey(ms);
					if (day < cutoff) continue;
					const cc = countryOf(ip);
					if (!stats.days[day]) stats.days[day] = { countries: {}, hosts: {}, ips: {} };
					const d = stats.days[day];
					d.countries[cc] = (d.countries[cc] || 0) + 1;
					const h = String(host || "?").toLowerCase().slice(0, 253);
					d.hosts[h] = (d.hosts[h] || 0) + 1;
					const key = `${ip} ${cc}`;
					d.ips[key] = (d.ips[key] || 0) + 1;
					counted++;
				}
			}
			for (const day of Object.keys(stats.days)) {
				if (day < cutoff) delete stats.days[day];
				else {
					stats.days[day].ips = trimMap(stats.days[day].ips || {}, MAX_IPS_PER_DAY);
					stats.days[day].hosts = trimMap(stats.days[day].hosts || {}, MAX_HOSTS_PER_DAY);
				}
			}
			writeStats(stats);
			return counted;
		} finally {
			internalGeoStats.running = false;
		}
	},

	/** Zusammenfassung der letzten 30 Tage für die Einstellungsseite. */
	summary: (now = Date.now()) => {
		const { days } = readStats();
		const countries = {};
		const hosts = {};
		const ips = {};
		const perDay = [];
		let total = 0;
		for (let i = RETENTION_DAYS - 1; i >= 0; i--) {
			const key = dayKey(now - i * 86400000);
			const d = days[key];
			let n = 0;
			if (d) {
				for (const [cc, c] of Object.entries(d.countries || {})) {
					countries[cc] = (countries[cc] || 0) + c;
					n += c;
				}
				for (const [h, c] of Object.entries(d.hosts || {})) hosts[h] = (hosts[h] || 0) + c;
				for (const [k, c] of Object.entries(d.ips || {})) ips[k] = (ips[k] || 0) + c;
			}
			perDay.push({ day: key, count: n });
			total += n;
		}
		const sortDesc = (obj) => Object.entries(obj).sort((a, b) => b[1] - a[1]);
		return {
			days: RETENTION_DAYS,
			total,
			countries: sortDesc(countries).map(([code, count]) => ({ code, count })),
			hosts: sortDesc(hosts)
				.slice(0, 10)
				.map(([host, count]) => ({ host, count })),
			top_ips: sortDesc(ips)
				.slice(0, 10)
				.map(([k, count]) => {
					const [ip, code] = k.split(" ");
					return { ip, code, count };
				}),
			per_day: perDay,
		};
	},

	initTimer: () => {
		const run = () => {
			try {
				const n = internalGeoStats.collect();
				if (n) logger.info(`Länder-Statistik: ${n} neue Sperren gezählt`);
			} catch (err) {
				logger.error(`Länder-Statistik fehlgeschlagen: ${err.message}`);
			}
		};
		setTimeout(run, 30 * 1000).unref();
		internalGeoStats.interval = setInterval(run, 5 * 60 * 1000);
		internalGeoStats.interval.unref();
	},
};

export default internalGeoStats;
