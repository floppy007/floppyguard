import type { WireGuardLink } from "src/api/backend";
import { intl } from "src/locale/IntlProvider";

// Backend code ids (backend/internal/wireguard.js) that have a translation.
// Unknown ids fall back to the raw id so a new backend code is still visible.
const KNOWN_WARNINGS = new Set([
	"remote-endpoint-missing",
	"imported-network-missing-live-route",
	"nat-likely-needed",
	"exported-networks-missing",
	"return-path-mode-undefined",
	"remote-management-mode-undefined",
	"link-not-currently-active",
	"allowedips-conflict",
]);
export const fmtWarning = (w: string) =>
	KNOWN_WARNINGS.has(w) ? intl.formatMessage({ id: `wireguard.warning.${w}` }) : w;

const KNOWN_NEXT_ACTIONS = new Set([
	"verify-return-path",
	"model-exported-networks",
	"define-remote-management-mode",
	"fix-return-path",
	"decide-nat-or-static-route",
	"define-return-path-mode",
	"verify-live-tunnel-state",
	"mount-wireguard-config-directory",
]);
export const fmtNextAction = (a: string) =>
	KNOWN_NEXT_ACTIONS.has(a) ? intl.formatMessage({ id: `wireguard.next.${a}` }) : a;

export const getPlanBadge = (link: WireGuardLink) => {
	switch (link.planState) {
		case "ready":
			return { labelId: "platform.plan.ready", className: "bg-green-lt text-green" };
		case "validate":
			return { labelId: "platform.plan.validate", className: "bg-yellow-lt text-yellow" };
		case "shape":
			return { labelId: "platform.plan.shaping", className: "bg-blue-lt text-blue" };
		case "discover":
			return { labelId: "platform.plan.discover", className: "bg-secondary-lt text-secondary" };
		default:
			return { labelId: "platform.plan.unplanned", className: "bg-secondary-lt text-secondary" };
	}
};

export const getLinkTypeBadge = (link: WireGuardLink) => {
	switch (link.type) {
		case "client":
			return { labelId: "platform.link-type.client", className: "bg-emerald-lt text-emerald" };
		case "site-to-site":
			return { labelId: "platform.link-type.site", className: "bg-indigo-lt text-indigo" };
		case "hub-link":
			return { labelId: "platform.link-type.hub", className: "bg-cyan-lt text-cyan" };
		default:
			return { labelId: "platform.link-type.other", className: "bg-secondary-lt text-secondary" };
	}
};
