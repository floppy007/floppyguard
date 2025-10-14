import { put } from "./base";
import type { WireGuardMetadataPatch, WireGuardMetadataResponse } from "./models";

export function updateWireGuardMetadata(data: WireGuardMetadataPatch) {
	return put({ url: "wireguard/metadata", data }) as Promise<WireGuardMetadataResponse & { saved: boolean }>;
}
