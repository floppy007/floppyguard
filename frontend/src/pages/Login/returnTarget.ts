// Nach Session-Ablauf rendert der Router <Login/> an Ort und Stelle, die URL
// zeigt noch die zuletzt besuchte Seite. Dorthin zurueck; "/login" ist nur die
// SSO-Ruecksprungadresse ohne Route und faellt auf das Dashboard zurueck.
// F-42: Nur eigene Pfade. "//evil.example" bzw. "/\evil.example" waeren fuer
// location.assign() protokoll-relative Adressen auf eine fremde Domain.
export const safeReturnTarget = (pathname: string, search: string): string => {
	if (pathname === "/login") return "/";
	if (!pathname.startsWith("/") || pathname.startsWith("//") || pathname.startsWith("/\\")) return "/";
	for (let i = 0; i < pathname.length; i++) {
		const c = pathname.charCodeAt(i);
		if (c < 0x20 || c === 0x5c) return "/";
	}
	return `${pathname}${search}`;
};
