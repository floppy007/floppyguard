import * as api from "./base";

export interface CloudflareSettings {
	ipv4: string;
	ipv6: string;
	autoNewHosts: boolean;
	proxiedDefault: boolean;
	allowAllUsers: boolean;
	hasToken: boolean;
	tokenHint: string;
	envToken: boolean;
	detected: { ipv4: string[]; ipv6: string[] };
	effectiveAddresses: string[];
}

export interface CloudflareSettingsInput {
	ipv4: string;
	ipv6: string;
	autoNewHosts: boolean;
	proxiedDefault: boolean;
	allowAllUsers: boolean;
	apiToken?: string;
	clearToken?: boolean;
}

/** Für jeden Benutzer: darf er den Hauptschlüssel nutzen, und was gilt für neue Hosts. */
export interface CloudflareStatus {
	configured: boolean;
	available: boolean;
	autoNewHosts: boolean;
	proxiedDefault: boolean;
}

export interface CloudflareTestResult {
	ok: boolean;
	message: string;
	zones: string[];
}

export async function getCloudflare(): Promise<CloudflareSettings> {
	return await api.get({ url: "/cloudflare" });
}

export async function updateCloudflare(data: CloudflareSettingsInput): Promise<CloudflareSettings> {
	return await api.put({ url: "/cloudflare", data });
}

export async function testCloudflare(apiToken?: string): Promise<CloudflareTestResult> {
	return await api.post({ url: "/cloudflare/test", data: { apiToken } });
}

export async function getCloudflareStatus(): Promise<CloudflareStatus> {
	return await api.get({ url: "/cloudflare/status" });
}
