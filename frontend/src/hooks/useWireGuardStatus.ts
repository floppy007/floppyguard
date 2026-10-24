import { useQuery } from "@tanstack/react-query";
import { getWireGuardStatus, type WireGuardStatus } from "src/api/backend";

const useWireGuardStatus = (options = {}) => {
	return useQuery<WireGuardStatus, Error>({
		queryKey: ["wireguard-status"],
		queryFn: getWireGuardStatus,
		staleTime: 15 * 1000,
		refetchInterval: 15 * 1000,
		...options,
	});
};

export { useWireGuardStatus };
