import * as api from "./base";

export interface OidcSettings {
	enabled: boolean;
	label: string;
	issuer: string;
	clientId: string;
	redirectUri: string;
	requiredGroup: string;
	groupsClaim: string;
	scopes: string;
	expiry: string;
	hasClientSecret: boolean;
	configPath: string;
}

export interface OidcSettingsInput extends Omit<OidcSettings, "hasClientSecret" | "configPath"> {
	clientSecret?: string;
	clearClientSecret?: boolean;
}

export interface OidcTestResult {
	ok: boolean;
	message: string;
}

export async function getOidcSettings(): Promise<OidcSettings> {
	return await api.get({ url: "/oidc/settings" });
}

export async function updateOidcSettings(data: OidcSettingsInput): Promise<OidcSettings> {
	return await api.put({ url: "/oidc/settings", data });
}

export async function testOidcSettings(issuer: string): Promise<OidcTestResult> {
	return await api.post({ url: "/oidc/settings/test", data: { issuer } });
}
