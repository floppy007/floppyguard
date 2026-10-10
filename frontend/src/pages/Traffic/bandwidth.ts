import type { PeerBandwidth } from "src/api/backend";

/** Current RX/TX rate = sum of every peer's newest live sample. */
export const currentRates = (peers: PeerBandwidth[]): { rx: number; tx: number } =>
	peers.reduce(
		(acc, p) => {
			const last = p.history[p.history.length - 1];
			return { rx: acc.rx + (last?.rx ?? 0), tx: acc.tx + (last?.tx ?? 0) };
		},
		{ rx: 0, tx: 0 },
	);

const volume = (p: PeerBandwidth) => p.history.reduce((s, h) => s + h.rx + h.tx, 0);

/** Chart palette (12 peers visually distinct). */
export const PEER_COLORS = [
	"#4299e1",
	"#48bb78",
	"#ed8936",
	"#a78bfa",
	"#f687b3",
	"#38b2ac",
	"#d69e2e",
	"#e53e3e",
	"#2b6cb0",
	"#2f855a",
	"#9c4221",
	"#b83280",
];

/**
 * Stable colour per peer id.
 *
 * The base assignment uses ONLY the current link ids (the live WireGuard status —
 * the same on every page and in every range), sorted, so a link keeps its colour
 * across polls, ranges, Dashboard and Traffic, in charts, legends and table
 * sparklines — independent of the (rate- or volume-ranked) order it is shown in.
 * History-only ids (a deleted peer still in the 30d history) do not shift it.
 *
 * `shown` (the charted peers) then gets a de-duplication pass: a shown id
 * without a base colour (history-only) or whose base colour an earlier shown id
 * already uses (more links than colours) gets the first colour no other shown
 * peer uses — so the charted peers never share a colour.
 */
export const peerColorMap = (linkIds: string[], shown: string[] = []): Map<string, string> => {
	const map = new Map<string, string>(
		[...new Set(linkIds)].sort().map((id, i) => [id, PEER_COLORS[i % PEER_COLORS.length]]),
	);
	const uniqueShown = [...new Set(shown)].sort();
	const ordered = [...uniqueShown.filter((id) => map.has(id)), ...uniqueShown.filter((id) => !map.has(id))];
	const used = new Set<string>();
	for (const id of ordered) {
		const base = map.get(id);
		if (base && !used.has(base)) {
			used.add(base);
			continue;
		}
		const free = PEER_COLORS.find((c) => !used.has(c)) ?? base ?? PEER_COLORS[0];
		map.set(id, free);
		used.add(free);
	}
	return map;
};

/** Busiest peers first (the history API returns them in DB order). */
export const sortByVolume = (peers: PeerBandwidth[]): PeerBandwidth[] =>
	[...peers].sort((a, b) => volume(b) - volume(a));
