import { post } from "./base";
import type { WireGuardRestoreMetadataResponse } from "./models";

export function restoreWireGuardMetadata(backupPath: string) {
	return post({ url: "wireguard/restore-metadata", data: { backupPath } }) as Promise<WireGuardRestoreMetadataResponse>;
}
