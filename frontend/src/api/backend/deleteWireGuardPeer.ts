import * as api from "./base";

export interface DeleteWireGuardPeerRequest {
	linkId: string;
}

export interface DeleteWireGuardPeerResponse {
	deleted: boolean;
	linkId: string;
}

export async function deleteWireGuardPeer(data: DeleteWireGuardPeerRequest): Promise<DeleteWireGuardPeerResponse> {
	return api.post({ url: "wireguard/delete-peer", data }) as Promise<DeleteWireGuardPeerResponse>;
}
