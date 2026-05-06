import { IconBrandGithub } from "@tabler/icons-react";
import type { HealthResponse } from "src/api/backend";
import { useHealth } from "src/hooks";

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
						<a href="https://comnic-it.de" target="_blank" rel="noopener">
							Comnic-IT
						</a>
					</div>
					<a
						href="https://github.com/floppy007/floppyguard"
						target="_blank"
						rel="noopener"
						className="d-flex align-items-center gap-1 text-secondary small text-decoration-none"
						style={{ opacity: 0.7 }}
					>
						<IconBrandGithub size={14} stroke={1.5} />
						<span>FloppyGuard</span>
						<span className="text-muted">· AGPL-3.0</span>
					</a>
					<div className="text-secondary small">{getVersion()}</div>
				</div>
			</div>
		</footer>
	);
}
