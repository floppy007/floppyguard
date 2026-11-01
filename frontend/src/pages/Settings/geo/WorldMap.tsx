import { geoNaturalEarth1, geoPath } from "d3-geo";
import { type MouseEvent, useMemo, useRef, useState } from "react";
import { feature } from "topojson-client";
import type { GeometryCollection, Topology } from "topojson-specification";
import world from "world-atlas/countries-110m.json";
import { countryName } from "./countries";
import { ISO_NUMERIC } from "./isoNumeric";

const WIDTH = 960;
const HEIGHT = 470;
const STEPS = 5;

interface Props {
	counts: Record<string, number>;
	allowed: string[];
	total: number;
}

type Shape = { code: string; d: string };

// einmal berechnen: Länderumrisse als SVG-Pfade (Antarktis weggelassen)
let shapesCache: Shape[] | null = null;
const shapes = (): Shape[] => {
	if (shapesCache) return shapesCache;
	const topo = world as unknown as Topology<{ countries: GeometryCollection }>;
	const fc = feature(topo, topo.objects.countries) as unknown as GeoJSON.FeatureCollection;
	const projection = geoNaturalEarth1().fitExtent(
		[
			[4, 4],
			[WIDTH - 4, HEIGHT - 4],
		],
		{ type: "FeatureCollection", features: fc.features.filter((f) => f.id !== "010") },
	);
	const path = geoPath(projection);
	shapesCache = fc.features
		.filter((f) => f.id !== "010")
		.map((f) => ({ code: ISO_NUMERIC[String(Number(f.id))] || "", d: path(f) || "" }))
		.filter((s) => s.d);
	return shapesCache;
};

/** Stufe 1..5 auf logarithmischer Skala (wenige Länder mit sehr vielen Sperren dominieren sonst alles). */
const step = (n: number, max: number) =>
	n <= 0 ? 0 : Math.max(1, Math.ceil((Math.log(n + 1) / Math.log(max + 1)) * STEPS));

export default function WorldMap({ counts, allowed, total }: Props) {
	const wrap = useRef<HTMLDivElement>(null);
	const [hover, setHover] = useState<{ code: string; x: number; y: number } | null>(null);
	const list = useMemo(shapes, []);
	const max = Math.max(1, ...Object.values(counts));
	const allowedSet = useMemo(() => new Set(allowed), [allowed]);

	const onMove = (code: string) => (e: MouseEvent) => {
		const r = wrap.current?.getBoundingClientRect();
		if (r) setHover({ code, x: e.clientX - r.left, y: e.clientY - r.top });
	};

	const h = hover ? { n: counts[hover.code] || 0, allowed: allowedSet.has(hover.code) } : null;

	return (
		// Hover nur als Zusatz – dieselben Zahlen stehen in den Listen darunter (Top-Länder, IPs)
		// biome-ignore lint/a11y/noStaticElementInteractions: reine Maus-Ergänzung, Daten auch als Liste
		<div className="geo-map" ref={wrap} onMouseLeave={() => setHover(null)}>
			<svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label="Weltkarte der gesperrten Zugriffe">
				{list.map((s, i) => {
					const n = counts[s.code] || 0;
					const cls = n
						? `geo-map-s${step(n, max)}`
						: allowedSet.has(s.code)
							? "geo-map-allowed"
							: "geo-map-none";
					return (
						// biome-ignore lint/a11y/noStaticElementInteractions: reine Maus-Ergänzung, Daten auch als Liste
						<path
							key={`${s.code}-${i}`}
							d={s.d}
							className={`geo-map-country ${cls} ${hover?.code === s.code && s.code ? "is-hover" : ""}`}
							onMouseMove={s.code ? onMove(s.code) : undefined}
						/>
					);
				})}
			</svg>
			{hover && h ? (
				<div
					className="geo-map-tip"
					style={{ left: Math.min(hover.x + 14, (wrap.current?.clientWidth || 0) - 190), top: hover.y + 14 }}
				>
					<div className="fw-semibold">{countryName(hover.code)}</div>
					{h.allowed ? (
						<div className="text-secondary small">erlaubt</div>
					) : (
						<div className="small">
							<strong>{h.n.toLocaleString()}</strong> Sperren
							{total && h.n ? (
								<span className="text-secondary"> · {((h.n / total) * 100).toFixed(1)} %</span>
							) : null}
						</div>
					)}
				</div>
			) : null}
			<div className="geo-map-legend">
				<span className="d-inline-flex align-items-center gap-1">
					<i className="geo-map-allowed" /> erlaubt
				</span>
				<span className="d-inline-flex align-items-center gap-1 ms-3">
					weniger
					{Array.from({ length: STEPS }, (_, i) => (
						<i key={i} className={`geo-map-s${i + 1}`} />
					))}
					mehr Sperren (max. {max.toLocaleString()})
				</span>
			</div>
		</div>
	);
}
