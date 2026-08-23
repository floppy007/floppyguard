import { useQuery } from "@tanstack/react-query";
import { getWireGuardBandwidth, type BandwidthRange, type PeerBandwidth } from "src/api/backend";

const useWireGuardBandwidth = (range: BandwidthRange = "live") => {
	return useQuery<PeerBandwidth[], Error>({
		queryKey: ["wireguard-bandwidth", range],
		queryFn: () => getWireGuardBandwidth(range),
		staleTime: 10_000,
		refetchInterval: 10_000,
	});
};

export { useWireGuardBandwidth };
