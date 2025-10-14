import { useQuery } from "@tanstack/react-query";
import { getWireGuardStatus, type WireGuardStatus } from "src/api/backend";

const fetchWireGuardStatus = () => {
	return getWireGuardStatus();
};

const useWireGuardStatus = (options = {}) => {
	return useQuery<WireGuardStatus, Error>({
		queryKey: ["wireguard-status"],
		queryFn: fetchWireGuardStatus,
		staleTime: 15 * 1000,
		refetchInterval: 15 * 1000,
		...options,
	});
};

export { fetchWireGuardStatus, useWireGuardStatus };
