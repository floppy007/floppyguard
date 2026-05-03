import { useHealth } from "src/hooks";
import type { HealthResponse } from "src/api/backend";

export function SiteFooter() {
	const health = useHealth();

	const getVersion = () => {
		if (!health.data) return "";
		const v = (health.data as unknown as HealthResponse).version;
		return `v${v.major}.${v.minor}.${v.revision}`;
	};

	return (
		<footer className="footer d-print-none platform-footer">
			<div className="container-xl">
				<div className="platform-footer-row">
					<div className="text-secondary small">
						© {new Date().getFullYear()} Florian Hesse |{" "}
						<a href="https://comnic-it.de" target="_blank" rel="noopener">Comnic-IT</a>
					</div>
					<div className="text-secondary small" style={{ opacity: 0.6 }}>
						Based on{" "}
						<a href="https://github.com/NginxProxyManager/nginx-proxy-manager" target="_blank" rel="noopener">nginx-proxy-manager</a>
						{" "}by Jamie Curnow · MIT License
					</div>
					<div className="text-secondary small">{getVersion()}</div>
				</div>
			</div>
		</footer>
	);
}
