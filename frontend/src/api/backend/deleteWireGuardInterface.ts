import * as api from "./base";

export interface DeleteWireGuardInterfaceRequest {
	name: string;
}

export interface DeleteWireGuardInterfaceResponse {
	deleted: boolean;
	name: string;
}

export async function deleteWireGuardInterface(
	data: DeleteWireGuardInterfaceRequest,
): Promise<DeleteWireGuardInterfaceResponse> {
	return api.post({ url: "wireguard/delete-interface", data }) as Promise<DeleteWireGuardInterfaceResponse>;
}
