import queryString from "query-string";
import AuthStore from "src/modules/AuthStore";

function buildAuthHeader(): Record<string, string> {
	if (AuthStore.token) {
		return { Authorization: `Bearer ${AuthStore.token.token}` };
	}
	return {};
}

export async function getWireGuardLinkConfigQr(linkId: string): Promise<string> {
	const url = queryString.stringifyUrl({
		url: "/api/wireguard/link-config-qr",
		query: { link_id: linkId },
	});
	const res = await fetch(url, { headers: buildAuthHeader() });
	if (!res.ok) throw new Error("Failed to load QR code");
	const blob = await res.blob();
	return URL.createObjectURL(blob);
}
