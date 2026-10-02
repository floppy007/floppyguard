import * as api from "./base";
import type { TokenResponse } from "./responseTypes";

export interface OidcStatusResponse {
	enabled: boolean;
	label: string;
}

/**
 * Sagt der Anmeldeseite, ob ein Anbieter eingerichtet ist. Braucht kein Token.
 */
export async function getOidcStatus(): Promise<OidcStatusResponse> {
	return await api.get({
		url: "/oidc/status",
	});
}

/**
 * Holt das Ergebnis einer SSO-Anmeldung einmalig ab. Das Token liegt nach dem
 * Rueckweg vom Anbieter in einem HttpOnly-Cookie dieses Browsers - nie in der
 * URL. Ein Link mit untergeschobenem Token kann so niemanden anmelden.
 */
export async function exchangeOidcLogin(): Promise<TokenResponse> {
	return await api.post({
		url: "/oidc/exchange",
		data: {},
		noAuth: true,
	});
}
