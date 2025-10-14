import { post } from "./base";
import type { WireGuardApplyMetadataResponse, WireGuardMetadataPatch } from "./models";

export function applyWireGuardMetadata(data: WireGuardMetadataPatch) {
	return post({ url: "wireguard/apply-metadata", data, rawBody: true }) as Promise<WireGuardApplyMetadataResponse>;
}
