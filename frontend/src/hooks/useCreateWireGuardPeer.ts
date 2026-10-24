import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
	type CreateWireGuardPeerRequest,
	type CreateWireGuardPeerResponse,
	createWireGuardPeer,
} from "src/api/backend";
import { invalidateWireGuard } from "./wireguardKeys";

const useCreateWireGuardPeer = () => {
	const queryClient = useQueryClient();
	return useMutation<CreateWireGuardPeerResponse, Error, CreateWireGuardPeerRequest>({
		mutationFn: createWireGuardPeer,
		onSuccess: () => invalidateWireGuard(queryClient),
	});
};

export { useCreateWireGuardPeer };
