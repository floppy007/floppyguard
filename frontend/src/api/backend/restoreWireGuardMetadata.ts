import { post } from "./base";
import type { WireGuardRestoreMetadataResponse } from "./models";

export function restoreWireGuardMetadata(backupPath: string) {
	// rawBody: the backend route reads the camelCase key (backupPath),
	// so the default decamelize-to-snake_case body building must be skipped.
	return post({
		url: "wireguard/restore-metadata",
		data: { backupPath },
		rawBody: true,
	}) as Promise<WireGuardRestoreMetadataResponse>;
}
