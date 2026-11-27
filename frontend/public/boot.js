// Boot helpers (external file so the admin UI can run with a strict CSP: script-src 'self').
if (typeof window.global === "undefined") {
	window.global = window;
}
window.__hideBootSplash = () => {
	const el = document.getElementById("boot-splash");
	if (!el) return;
	el.classList.add("boot-hidden");
	window.setTimeout(() => el.remove(), 320);
};
