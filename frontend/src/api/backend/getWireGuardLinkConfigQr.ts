import { fetchBlob } from "./base";

export async function getWireGuardLinkConfigQr(linkId: string): Promise<string> {
	// buildUrl decamelizes linkId → link_id
	const blob = await fetchBlob({ url: "wireguard/link-config-qr", params: { linkId } });
	return URL.createObjectURL(blob);
}
