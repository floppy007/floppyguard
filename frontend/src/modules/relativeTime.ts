import { intl } from "src/locale/IntlProvider";

/** Localised "vor 5 Minuten" / "5 minutes ago". */
export const relativeTime = (ts: number, now = Date.now() / 1000): string => {
	const diff = Math.max(0, Math.floor(now - ts));
	const steps: Array<[Intl.RelativeTimeFormatUnit, number]> = [
		["second", 60],
		["minute", 60],
		["hour", 24],
		["day", 30],
		["month", 12],
	];
	let value = diff;
	for (const [unit, size] of steps) {
		if (value < size) return intl.formatRelativeTime(-value, unit, { numeric: "auto" });
		value = Math.floor(value / size);
	}
	return intl.formatRelativeTime(-value, "year", { numeric: "auto" });
};

/** relativeTime, or "—" when there is no timestamp (e.g. a peer that never handshook). */
export const relativeTimeOrDash = (ts: number | null | undefined): string => (ts ? relativeTime(ts) : "—");
