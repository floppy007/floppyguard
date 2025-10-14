import { get } from "./base";
import type { WireGuardMetadataResponse } from "./models";

export function getWireGuardMetadata() {
	return get({ url: "wireguard/metadata" }) as Promise<WireGuardMetadataResponse>;
}
