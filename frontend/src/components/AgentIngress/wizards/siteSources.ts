import type { AgentIngressCatalog } from "src/api/backend";
import type { PickerEntry } from "../catalog";

/** Sources a site wizard offers: other sites (and their nets), VPN clients, the tunnel. */
export const siteSourceEntries = (catalog: AgentIngressCatalog): PickerEntry[] =>
	catalog.sources.filter((e) => e.kind === "site" || e.kind === "site-net" || e.kind === "client" || e.kind === "tunnel");
