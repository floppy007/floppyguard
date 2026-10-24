import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	getSiteIsolation,
	type SiteIsolationOverview,
	type SiteIsolationPairInput,
	setSiteIsolation,
} from "src/api/backend";
import { invalidateAgentIngress } from "./useAgentIngress";

/**
 * "Standorte untereinander". No retry: an older backend without the endpoint
 * (404) or a failing WireGuard view must not hold up the Freigaben page.
 */
const useSiteIsolation = (options = {}) => {
	return useQuery<SiteIsolationOverview, Error>({
		queryKey: ["site-isolation"],
		queryFn: getSiteIsolation,
		staleTime: 30 * 1000,
		retry: false,
		...options,
	});
};

/**
 * PUT the full pair set. The response is the new overview (taken over at once);
 * site isolation also changes tester verdicts and the per-site banners, so the
 * ingress queries are refreshed as well.
 */
const useSetSiteIsolation = () => {
	const queryClient = useQueryClient();
	return useMutation<SiteIsolationOverview, Error, SiteIsolationPairInput[]>({
		mutationFn: (pairs: SiteIsolationPairInput[]) => setSiteIsolation(pairs),
		onSuccess: (data) => {
			// the PUT already returns the fresh overview — no refetch of the same query
			queryClient.setQueryData(["site-isolation"], data);
			return invalidateAgentIngress(queryClient);
		},
	});
};

export { useSetSiteIsolation, useSiteIsolation };
