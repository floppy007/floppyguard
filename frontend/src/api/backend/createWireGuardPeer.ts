import * as api from "./base";

export interface CreateWireGuardPeerRequest {
	name: string;
	type: "client" | "site-to-site" | "hub-link";
	dns?: string[];
	fullTunnel?: boolean;
	platform?: "desktop" | "mobile";
	importedNetworks?: string[];
	ifaceName?: string;
}

export interface CreateWireGuardPeerResponse {
	linkId: string;
	publicKey: string;
	tunnelAddress: string;
	filename: string;
	content: string;
}

export async function createWireGuardPeer(data: CreateWireGuardPeerRequest): Promise<CreateWireGuardPeerResponse> {
	return api.post({ url: "wireguard/create-peer", data }) as Promise<CreateWireGuardPeerResponse>;
}
