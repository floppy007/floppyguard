import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getCloudflare, getCloudflareStatus, testCloudflare, updateCloudflare } from "src/api/backend";

export const useCloudflare = () =>
	useQuery({ queryKey: ["cloudflare"], queryFn: getCloudflare, refetchOnWindowFocus: false });

export const useUpdateCloudflare = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: updateCloudflare,
		onSuccess: (data) => {
			queryClient.setQueryData(["cloudflare"], data);
			queryClient.invalidateQueries({ queryKey: ["cloudflare-status"] });
		},
	});
};

export const useTestCloudflare = () => useMutation({ mutationFn: testCloudflare });

export const useCloudflareStatus = () =>
	useQuery({ queryKey: ["cloudflare-status"], queryFn: getCloudflareStatus, staleTime: 60 * 1000 });
