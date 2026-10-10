import * as api from "./base";
import type { BoundAgentCheck, BoundAgentDeleteOptions, BoundAgentDeleteResult } from "./deleteWireGuardPeer";

export interface DeleteWireGuardInterfaceRequest extends BoundAgentDeleteOptions {
	name: string;
}

export interface DeleteWireGuardInterfaceResponse {
	deleted?: boolean;
	dryRun?: boolean;
	name: string;
	agents?: BoundAgentCheck[] | BoundAgentDeleteResult;
}

export async function deleteWireGuardInterface(
	data: DeleteWireGuardInterfaceRequest,
): Promise<DeleteWireGuardInterfaceResponse> {
	return api.post({ url: "wireguard/delete-interface", data }) as Promise<DeleteWireGuardInterfaceResponse>;
}
