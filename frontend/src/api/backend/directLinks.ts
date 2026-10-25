import { del, get, post, put } from "./base";
import type { DirectLink, DirectLinkCheck, DirectLinkInput, DirectLinkSite } from "./models";

/** Direct links ("Direktverbindungen") between two site agents; the hub stays the fallback. */
export function getDirectLinks(): Promise<DirectLink[]> {
	return get({ url: "direct-links" }) as Promise<DirectLink[]>;
}

/**
 * Request body: the generic decamelize turns `agentAId` into `agent_aid` (no
 * split before the "Id" after a single capital), so the agent ids are sent as
 * snake_case keys, which pass through unchanged.
 */
export const directLinkBody = (data: Partial<DirectLinkInput>): Record<string, unknown> => {
	const { agentAId, agentBId, ...rest } = data;
	return {
		...rest,
		...(agentAId !== undefined ? { agent_a_id: agentAId } : {}),
		...(agentBId !== undefined ? { agent_b_id: agentBId } : {}),
	};
};

export function createDirectLink(data: DirectLinkInput): Promise<DirectLink> {
	return post({ url: "direct-links", data: directLinkBody(data) }) as Promise<DirectLink>;
}

export function updateDirectLink(id: number, data: Partial<DirectLinkInput>): Promise<DirectLink> {
	return put({ url: `direct-links/${id}`, data: directLinkBody(data) }) as Promise<DirectLink>;
}

export function deleteDirectLink(id: number): Promise<void> {
	return del({ url: `direct-links/${id}` }) as Promise<void>;
}

/** Router settings + public address per site agent. */
export function getDirectLinkSites(): Promise<DirectLinkSite[]> {
	return get({ url: "direct-links/sites" }) as Promise<DirectLinkSite[]>;
}

/** Connection check of one link (DNS, public IP, port forward, path). Read only. */
export function checkDirectLink(id: number): Promise<DirectLinkCheck> {
	return get({ url: `direct-links/${id}/check` }) as Promise<DirectLinkCheck>;
}
