import { IconAlertTriangle, IconChevronRight, IconX } from "@tabler/icons-react";
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useCertProblems, useUser } from "src/hooks";
import { intl } from "src/locale";
import { isAdmin } from "src/modules/Permissions";
import { safeSession } from "src/modules/safeStorage";

const t = (id: string, values?: Record<string, string | number>) => intl.formatMessage({ id }, values);
const KEY = "fg.cert-problems.dismissed";

/**
 * Warnleiste unter der Kopfzeile: Zertifikat abgelaufen / Erneuerung fehlgeschlagen / läuft bald ab.
 * Nur für Admins. Wegklicken gilt bis zum nächsten Wechsel der Problemliste (pro Browser-Sitzung).
 */
export function CertProblemsBanner() {
	const { data: me } = useUser("me");
	const admin = isAdmin(me?.roles);
	const { data } = useCertProblems(admin);
	const navigate = useNavigate();
	const list = data?.certificates || [];
	const signature = list.map((p) => `${p.id}:${p.kind}`).join(",");
	const [dismissed, setDismissed] = useState(() => safeSession.get(KEY));

	if (!admin || !list.length || dismissed === signature) return null;

	const severe = list.some((p) => p.kind !== "expiring");
	const first = list[0];
	const describe = (p: (typeof list)[number]) =>
		p.kind === "expired"
			? t("cert-problems.expired", { name: p.name })
			: p.kind === "failed"
				? t("cert-problems.failed", { name: p.name })
				: t("cert-problems.expiring", { name: p.name, days: p.daysLeft ?? 0 });

	return (
		<div className={`fg-alertbar ${severe ? "is-danger" : "is-warning"}`} role="alert">
			<div className="container-xl d-flex align-items-center gap-3">
				<span className="fg-alertbar-icon">
					<IconAlertTriangle size={18} />
				</span>
				<div className="flex-fill small">
					<strong>{describe(first)}</strong>
					{first.kind === "failed" && first.error ? (
						<span className="fg-alertbar-detail"> – {first.error}</span>
					) : null}
					{list.length > 1 ? (
						<span className="ms-2 text-nowrap">{t("cert-problems.more", { count: list.length - 1 })}</span>
					) : null}
				</div>
				<button type="button" className="btn btn-sm fg-alertbar-btn" onClick={() => navigate("/certificates")}>
					{t("cert-problems.open")}
					<IconChevronRight size={14} className="ms-1" />
				</button>
				<button
					type="button"
					className="btn btn-sm btn-ghost-secondary px-1"
					aria-label={t("cert-problems.dismiss")}
					title={t("cert-problems.dismiss")}
					onClick={() => {
						safeSession.set(KEY, signature);
						setDismissed(signature);
					}}
				>
					<IconX size={16} />
				</button>
			</div>
		</div>
	);
}
