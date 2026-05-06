import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
	type CreateWireGuardPeerRequest,
	type CreateWireGuardPeerResponse,
	createWireGuardPeer,
} from "src/api/backend";

const useCreateWireGuardPeer = () => {
	const queryClient = useQueryClient();
	return useMutation<CreateWireGuardPeerResponse, Error, CreateWireGuardPeerRequest>({
		mutationFn: createWireGuardPeer,
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["wireguard-status"] });
			queryClient.invalidateQueries({ queryKey: ["wireguard-bandwidth"] });
		},
	});
};

export { useCreateWireGuardPeer };
