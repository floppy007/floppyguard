// Tiny hook registry so agent.js (syncAgentConfigs) can ask for a site-isolation
// re-apply without importing site-isolation.js (which imports wireguard.js /
// agent-ingress.js and would deepen the import cycle). No-op until the server
// entrypoint registers the real scheduler (internalSiteIsolation.start()), so
// tests and CLI scripts never schedule anything.

let trigger = null;

export function setSiteIsolationTrigger(fn) {
	trigger = typeof fn === "function" ? fn : null;
}

/** Request a (debounced) re-apply. Never throws. */
export function triggerSiteIsolation(reason = "") {
	if (!trigger) return;
	try {
		trigger(reason);
	} catch {
		// never let a scheduling problem break the caller
	}
}
