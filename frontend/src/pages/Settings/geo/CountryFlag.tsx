import { useEffect, useState } from "react";

// Flaggen aus country-flag-icons, je Land als eigener kleiner Chunk erst bei Bedarf geladen
// (Emoji-Flaggen zeigt Windows nur als Buchstaben an).
const loaders = import.meta.glob<{ default: string }>("/node_modules/country-flag-icons/string/3x2/*.js");
const cache = new Map<string, string>();

export default function CountryFlag({ code, size = 18 }: { code: string; size?: number }) {
	const [svg, setSvg] = useState<string | null>(cache.get(code) ?? null);
	useEffect(() => {
		if (cache.has(code)) {
			setSvg(cache.get(code) ?? null);
			return;
		}
		const load = loaders[`/node_modules/country-flag-icons/string/3x2/${code}.js`];
		if (!load) return;
		let alive = true;
		load().then((m) => {
			cache.set(code, m.default);
			if (alive) setSvg(m.default);
		});
		return () => {
			alive = false;
		};
	}, [code]);
	const style = { width: size, height: Math.round((size * 2) / 3) };
	if (!svg) return <span className="geo-flag geo-flag-empty" style={style} aria-hidden="true" />;
	// SVG-Quelltext stammt aus dem Paket (keine Nutzereingabe)
	// biome-ignore lint/security/noDangerouslySetInnerHtml: statische Flaggen-SVGs aus country-flag-icons
	return <span className="geo-flag" style={style} aria-hidden="true" dangerouslySetInnerHTML={{ __html: svg }} />;
}
