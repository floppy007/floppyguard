interface PeerSparklineProps {
	/** Array of bandwidth samples (bytes/s) — most recent last */
	data: number[];
	/** Line/fill color */
	color?: string;
	/** SVG height in px */
	height?: number;
}

const W = 200;

export function PeerSparkline({ data, color = "var(--tblr-green)", height = 32 }: PeerSparklineProps) {
	const H = height;

	if (!data.length) {
		return (
			<svg viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: H, display: "block" }}>
				<line x1="0" y1={H / 2} x2={W} y2={H / 2} stroke="currentColor" strokeOpacity="0.08" />
			</svg>
		);
	}

	const yMax = Math.max(...data, 1024) * 1.3;
	const pts = data.map((v, i) => {
		const x = (i / (data.length - 1)) * W;
		const y = H - (v / yMax) * H;
		return `${x.toFixed(1)},${y.toFixed(1)}`;
	});

	const line = `M ${pts.join(" L ")}`;
	const lastX = ((data.length - 1) / (data.length - 1)) * W;
	const area = `${line} L ${lastX.toFixed(1)},${H} L 0,${H} Z`;
	const gradId = `sg-${Math.random().toString(36).slice(2, 8)}`;

	return (
		<svg
			viewBox={`0 0 ${W} ${H}`}
			style={{ width: "100%", height: H, display: "block" }}
			aria-label="bandwidth sparkline"
		>
			<defs>
				<linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
					<stop offset="0%" stopColor={color} stopOpacity="0.15" />
					<stop offset="100%" stopColor={color} stopOpacity="0" />
				</linearGradient>
			</defs>
			<path d={area} fill={`url(#${gradId})`} />
			<path d={line} fill="none" stroke={color} strokeWidth="1.2" strokeLinejoin="round" strokeLinecap="round" />
		</svg>
	);
}
