import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
	type DeleteWireGuardPeerRequest,
	type DeleteWireGuardPeerResponse,
	deleteWireGuardPeer,
} from "src/api/backend";

const useDeleteWireGuardPeer = () => {
	const queryClient = useQueryClient();
	return useMutation<DeleteWireGuardPeerResponse, Error, DeleteWireGuardPeerRequest>({
		mutationFn: deleteWireGuardPeer,
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["wireguard-status"] });
			queryClient.invalidateQueries({ queryKey: ["wireguard-metadata"] });
			queryClient.invalidateQueries({ queryKey: ["wireguard-bandwidth"] });
			queryClient.invalidateQueries({ queryKey: ["wireguard-apply-state"] });
		},
	});
};

export { useDeleteWireGuardPeer };
