import { getUnixTime, parseISO } from "date-fns";
import type { TokenResponse } from "src/api/backend";
import { safeLocal } from "src/modules/safeStorage";

export const TOKEN_KEY = "authentications";

export class AuthStore {
	// Get all tokens from stack
	get tokens() {
		const t = safeLocal.get(TOKEN_KEY);
		let tokens = [];
		if (t !== null) {
			try {
				tokens = JSON.parse(t);
			} catch (e) {
				console.error("Failed to parse tokens from localStorage", e);
			}
		}
		return tokens;
	}

	// Get last token from stack
	get token() {
		const t = this.tokens;
		if (t.length) {
			return t[t.length - 1];
		}
		return null;
	}

	// Whether the current (top) token has expired. Read-only, unlike hasActiveToken()
	isTopTokenExpired(now = Date.now()) {
		const t = this.token;
		const ts = t?.expires ? parseISO(t.expires).getTime() : Number.NaN;
		return Number.isNaN(ts) || ts <= now;
	}

	// Filter out invalid tokens and return true if we find one that is valid
	// hasActiveToken() {
	// 	const t = this.tokens;
	// 	return t.length > 0;
	// }
	// Start from the END of the stack and work backwards
	// Expired tokens are stripped from the top down until the first valid one; storage
	// is read once and written at most once.
	hasActiveToken() {
		const t = this.tokens;
		const now = Math.round(Date.now() / 1000);
		const oneMinuteBuffer = 60;
		let keep = t.length;
		while (keep > 0 && !(getUnixTime(parseISO(t[keep - 1].expires)) - oneMinuteBuffer > now)) {
			keep--;
		}
		if (keep !== t.length) {
			safeLocal.set(TOKEN_KEY, JSON.stringify(t.slice(0, keep)));
		}
		return keep > 0;
	}

	// Set a single token on the stack
	set({ token, expires }: TokenResponse) {
		safeLocal.set(TOKEN_KEY, JSON.stringify([{ token, expires }]));
	}

	// Replace the token at the END of the stack, preserving any tokens below it.
	// Used by token refresh so a "login as" stack isn't wiped out.
	replaceTop({ token, expires }: TokenResponse) {
		const t = this.tokens;
		if (!t.length) {
			this.set({ token, expires });
			return;
		}
		t[t.length - 1] = { token, expires };
		safeLocal.set(TOKEN_KEY, JSON.stringify(t));
	}

	// Add a token to the END of the stack
	add({ token, expires }: TokenResponse) {
		const t = this.tokens;
		t.push({ token, expires });
		safeLocal.set(TOKEN_KEY, JSON.stringify(t));
	}

	// Drop a token from the END of the stack
	drop() {
		const t = this.tokens;
		t.splice(-1, 1);
		safeLocal.set(TOKEN_KEY, JSON.stringify(t));
	}

	clear() {
		safeLocal.remove(TOKEN_KEY);
	}

	count() {
		return this.tokens.length;
	}
}

export default new AuthStore();
