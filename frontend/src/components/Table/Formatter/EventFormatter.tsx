import {
	IconArrowsCross,
	IconBolt,
	IconBoltOff,
	IconDisc,
	IconKey,
	IconLock,
	IconRefresh,
	IconShield,
	IconShieldLock,
	IconUser,
} from "@tabler/icons-react";
import cn from "classnames";
import type { AuditLog } from "src/api/backend";
import { useLocaleState } from "src/context";
import { formatDateTime, T } from "src/locale";

const getEventValue = (event: AuditLog) => {
	switch (event.objectType) {
		case "access-list":
		case "user":
			return event.meta?.name;
		case "proxy-host":
		case "redirection-host":
		case "dead-host":
			return event.meta?.domainNames?.join(", ") || "N/A";
		case "stream":
			return event.meta?.incomingPort || "N/A";
		case "agent-ingress":
			return event.meta?.name || event.meta?.agent || "N/A";
		case "certificate":
			return event.meta?.domainNames?.join(", ") || event.meta?.niceName || "N/A";
		case "oidc-settings":
			// Only field names are logged, never values (client secret)
			return (Array.isArray(event.meta?.changed) ? event.meta.changed.join(", ") : "") || "SSO";
		case "floppyguard":
			return "FloppyGuard";
		default:
			return event.meta?.name || event.objectType;
	}
};

const getColorForAction = (action: string) => {
	switch (action) {
		case "created":
			return "text-lime";
		case "deleted":
			return "text-red";
		default:
			return "text-blue";
	}
};

/**
 * Older app-update rows were written without an object_type ("") — treat them as
 * "floppyguard" so they render like the new ones instead of an empty object.
 */
const normalize = (row: AuditLog): AuditLog =>
	!row.objectType && row.action === "floppyguard.update" ? { ...row, objectType: "floppyguard" } : row;

/** Actions whose message has no {object} placeholder (nothing to translate). */
const NO_OBJECT_ACTIONS = new Set(["floppyguard.update", "sso-login", "sso-refused"]);

const getIcon = (row: AuditLog) => {
	const c = cn(getColorForAction(row.action), "me-1");
	let ico = null;
	switch (row.objectType) {
		case "user":
			ico = <IconUser size={16} className={c} />;
			break;
		case "proxy-host":
			ico = <IconBolt size={16} className={c} />;
			break;
		case "redirection-host":
			ico = <IconArrowsCross size={16} className={c} />;
			break;
		case "dead-host":
			ico = <IconBoltOff size={16} className={c} />;
			break;
		case "stream":
			ico = <IconDisc size={16} className={c} />;
			break;
		case "access-list":
			ico = <IconLock size={16} className={c} />;
			break;
		case "certificate":
			ico = <IconShield size={16} className={c} />;
			break;
		case "agent-ingress":
			ico = <IconShieldLock size={16} className={c} />;
			break;
		case "oidc-settings":
			ico = <IconKey size={16} className={c} />;
			break;
		case "floppyguard":
			ico = <IconRefresh size={16} className={c} />;
			break;
	}

	return ico;
};

interface Props {
	row: AuditLog;
}
export function EventFormatter({ row: rawRow }: Props) {
	const { locale } = useLocaleState();
	const row = normalize(rawRow);
	// T skips empty tData values (an empty message id throws); {object} stays filled
	const tData = NO_OBJECT_ACTIONS.has(row.action) ? undefined : { object: row.objectType };
	return (
		<div className="flex-fill">
			<div className="font-weight-medium">
				{getIcon(row)}
				<T id={`object.event.${row.action}`} tData={tData} />
				&nbsp; &mdash; <span className="badge">{getEventValue(row)}</span>
			</div>
			<div className="text-secondary mt-1">{formatDateTime(row.createdOn, locale)}</div>
		</div>
	);
}
