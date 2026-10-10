import { useQuery } from "@tanstack/react-query";
import { type BandwidthRange, getWireGuardBandwidth, type PeerBandwidth } from "src/api/backend";

/**
 * History buckets only change at their resolution (24h: 1 min, 30d: 15 min,
 * 12m: 1 day) — re-reading thousands of rows every 10 s gains nothing.
 */
const REFRESH_MS: Record<BandwidthRange, number> = {
	live: 10_000,
	"24h": 60_000,
	"30d": 5 * 60_000,
	"12m": 15 * 60_000,
};

const bandwidthRefreshMs = (range: BandwidthRange): number => REFRESH_MS[range] ?? 10_000;

const useWireGuardBandwidth = (range: BandwidthRange = "live", options: { enabled?: boolean } = {}) => {
	const interval = bandwidthRefreshMs(range);
	return useQuery<PeerBandwidth[], Error>({
		queryKey: ["wireguard-bandwidth", range],
		queryFn: () => getWireGuardBandwidth(range),
		staleTime: interval,
		refetchInterval: interval,
		...options,
	});
};

export { bandwidthRefreshMs, useWireGuardBandwidth };
