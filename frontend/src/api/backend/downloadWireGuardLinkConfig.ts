import * as api from "./base";

export async function downloadWireGuardLinkConfig(linkId: string, filename: string): Promise<void> {
	await api.download({ url: "wireguard/link-config", params: { linkId } }, filename);
}
