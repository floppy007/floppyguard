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
	// rawBody: backend deleteOptions() reads camelCase dryRun/deleteBoundAgents/forceAgentIds
	return api.post({
		url: "wireguard/delete-interface",
		data,
		rawBody: true,
	}) as Promise<DeleteWireGuardInterfaceResponse>;
}
