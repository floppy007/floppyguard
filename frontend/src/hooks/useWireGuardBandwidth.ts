import { useQuery } from "@tanstack/react-query";
import { getWireGuardBandwidth, type PeerBandwidth } from "src/api/backend";

const useWireGuardBandwidth = () => {
	return useQuery<PeerBandwidth[], Error>({
		queryKey: ["wireguard-bandwidth"],
		queryFn: getWireGuardBandwidth,
		staleTime: 10_000,
		refetchInterval: 10_000,
	});
};

export { useWireGuardBandwidth };
