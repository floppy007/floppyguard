import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	checkDirectLink,
	createDirectLink,
	type DirectLinkCheck,
	type DirectLinkSite,
	getDirectLinkSites,
	type DirectLink,
	type DirectLinkInput,
	deleteDirectLink,
	getDirectLinks,
	updateDirectLink,
} from "src/api/backend";
import { invalidateAgentIngress } from "./useAgentIngress";

/**
 * Direct links. Refetched every 30 s (agents report their health in the
 * heartbeat); no retry so an older backend (404) never holds up the page.
 */
const useDirectLinks = (options = {}) => {
	return useQuery<DirectLink[], Error>({
		queryKey: ["direct-links"],
		queryFn: getDirectLinks,
		staleTime: 15 * 1000,
		refetchInterval: 30 * 1000,
		retry: false,
		...options,
	});
};

/** Create (no id) or update; a link changes the agents' Freigaben ruleset too. */
const useSaveDirectLink = () => {
	const queryClient = useQueryClient();
	return useMutation<DirectLink, Error, { id?: number; data: Partial<DirectLinkInput> }>({
		mutationFn: ({ id, data }) => (id ? updateDirectLink(id, data) : createDirectLink(data as DirectLinkInput)),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["direct-links"] });
			return invalidateAgentIngress(queryClient);
		},
	});
};

const useDeleteDirectLink = () => {
	const queryClient = useQueryClient();
	return useMutation<void, Error, number>({
		mutationFn: (id: number) => deleteDirectLink(id),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["direct-links"] });
			return invalidateAgentIngress(queryClient);
		},
	});
};

/** Router settings + public address per site (DNS lookups on the hub → refreshed every minute). */
const useDirectLinkSites = (options = {}) => {
	return useQuery<DirectLinkSite[], Error>({
		queryKey: ["direct-links", "sites"],
		queryFn: getDirectLinkSites,
		staleTime: 30 * 1000,
		refetchInterval: 60 * 1000,
		retry: false,
		...options,
	});
};

/** "Prüfen" on demand (button), not polled. */
const useCheckDirectLink = () => {
	return useMutation<DirectLinkCheck, Error, number>({
		mutationFn: (id: number) => checkDirectLink(id),
	});
};

export { useCheckDirectLink, useDeleteDirectLink, useDirectLinkSites, useDirectLinks, useSaveDirectLink };
