/** localStorage/sessionStorage wrapped so a blocked store (private mode, site data blocked, partitioned iframe) degrades to "nothing remembered" instead of throwing. */
const wrap = (pick: () => Storage) => ({
	get(key: string): string | null {
		try {
			return pick().getItem(key);
		} catch {
			return null;
		}
	},
	set(key: string, value: string): void {
		try {
			pick().setItem(key, value);
		} catch {
			/* not remembered */
		}
	},
	remove(key: string): void {
		try {
			pick().removeItem(key);
		} catch {
			/* nothing to forget */
		}
	},
});

export const safeLocal = wrap(() => window.localStorage);
export const safeSession = wrap(() => window.sessionStorage);
