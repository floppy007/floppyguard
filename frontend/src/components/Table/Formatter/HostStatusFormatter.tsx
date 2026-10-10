import { IconAlertTriangle } from "@tabler/icons-react";
import { intl } from "src/locale/IntlProvider";
import { TrueFalseFormatter } from "./TrueFalseFormatter";

interface Props {
	enabled: boolean;
	meta?: Record<string, any> | null;
}

/** nginx_err from the host meta (camelized by the API client, raw as fallback). */
export const hostNginxError = (meta?: Record<string, any> | null): string | null => {
	const err = meta?.nginxErr ?? meta?.nginx_err;
	return typeof err === "string" && err.trim() ? err : null;
};

/**
 * Host status: online/offline plus a warning badge when nginx rejected the
 * saved settings (meta.nginx_err). The host can still be served by its
 * previous conf (nginx_online true) — then the saved values are not live, and
 * the next bulk regeneration (access list / certificate) trips over this host.
 */
export function HostStatusFormatter({ enabled, meta }: Props) {
	const err = hostNginxError(meta);
	return (
		<span className="d-inline-flex align-items-center gap-2 flex-wrap">
			<TrueFalseFormatter value={enabled} trueLabel="online" falseLabel="offline" />
			{err && (
				<span
					className="badge bg-yellow-lt text-yellow"
					title={err}
					data-testid="host-nginx-error"
					style={{ whiteSpace: "pre-line" }}
				>
					<IconAlertTriangle size={12} className="me-1" />
					{intl.formatMessage({ id: "host.nginx-rejected" })}
				</span>
			)}
		</span>
	);
}
