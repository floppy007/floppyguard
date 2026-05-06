interface DonutGaugeProps {
	/** Current value */
	value: number;
	/** Maximum value (denominator) */
	max: number;
	/** Ring color — any CSS color */
	color?: string;
	/** Size in px (default 56) */
	size?: number;
	/** Override center label (default: percentage) */
	label?: string;
	/** Show a pulsing dot instead of text */
	liveDot?: boolean;
}

const R = 14;
const C = 2 * Math.PI * R; // ~87.96

export function DonutGauge({ value, max, color = "var(--tblr-primary)", size = 56, label, liveDot }: DonutGaugeProps) {
	const pct = max > 0 ? Math.min(value / max, 1) : 0;
	const dash = pct * C;
	const centerText = label ?? `${Math.round(pct * 100)}%`;

	return (
		<div style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
			<svg viewBox="0 0 36 36" width={size} height={size} style={{ transform: "rotate(-90deg)" }}>
				<circle cx="18" cy="18" r={R} fill="none" stroke="var(--tblr-border-color)" strokeWidth="3.5" />
				<circle
					cx="18"
					cy="18"
					r={R}
					fill="none"
					stroke={color}
					strokeWidth="3.5"
					strokeDasharray={`${dash.toFixed(1)} ${C.toFixed(1)}`}
					strokeLinecap="round"
					style={{ transition: "stroke-dasharray 0.6s ease" }}
				/>
			</svg>
			<div
				style={{
					position: "absolute",
					inset: 0,
					display: "flex",
					alignItems: "center",
					justifyContent: "center",
					fontSize: size * 0.23,
					fontWeight: 700,
				}}
			>
				{liveDot ? (
					<span className="status-dot status-green status-dot-animated" style={{ width: 6, height: 6 }} />
				) : (
					centerText
				)}
			</div>
		</div>
	);
}
