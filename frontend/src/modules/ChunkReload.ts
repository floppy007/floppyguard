/**
 * After an app update the old content-hashed chunks are gone (vite empties
 * dist/), but tabs opened before still run the old entry bundle. A lazy page
 * then fails to import — reload once to pick up the new bundle.
 */

const RELOAD_KEY = "floppyguard.chunk-reload-at";
/** No second automatic reload within this window — avoids a reload loop if the server is really broken. */
const RELOAD_GUARD_MS = 30_000;

const CHUNK_ERROR =
	/Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module|ChunkLoadError|Unable to preload CSS|is not a valid JavaScript MIME type/i;

export const isChunkLoadError = (err: unknown): boolean => {
	const text = err instanceof Error ? `${err.name} ${err.message}` : String(err ?? "");
	return CHUNK_ERROR.test(text);
};

/** Reload the page unless that already happened a moment ago. Returns whether it reloads. */
export const reloadForNewBundle = (now = Date.now()): boolean => {
	try {
		const last = Number(window.sessionStorage.getItem(RELOAD_KEY) || 0);
		if (now - last < RELOAD_GUARD_MS) return false;
		window.sessionStorage.setItem(RELOAD_KEY, String(now));
	} catch {
		// Without storage there is no loop guard — leave it to the manual reload button
		return false;
	}
	window.location.reload();
	return true;
};
