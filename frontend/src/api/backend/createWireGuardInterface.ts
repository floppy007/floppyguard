import * as api from "./base";

export interface CreateWireGuardInterfaceRequest {
	name?: string;
	address: string;
	listenPort?: number;
	role?: string;
}

export interface CreateWireGuardInterfaceResponse {
	created: boolean;
	name: string;
	address: string;
	listenPort: number;
	publicKey: string;
}

export async function createWireGuardInterface(
	data: CreateWireGuardInterfaceRequest,
): Promise<CreateWireGuardInterfaceResponse> {
	// rawBody: the backend route reads camelCase keys (listenPort),
	// so the default decamelizeKeys() conversion would silently drop them.
	return api.post({ url: "wireguard/create-interface", data, rawBody: true }) as Promise<CreateWireGuardInterfaceResponse>;
}
