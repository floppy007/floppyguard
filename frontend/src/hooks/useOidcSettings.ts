import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getOidcSettings, testOidcSettings, updateOidcSettings } from "src/api/backend";

export const useOidcSettings = () =>
	useQuery({
		queryKey: ["oidc-settings"],
		queryFn: getOidcSettings,
		refetchOnWindowFocus: false,
	});

export const useUpdateOidcSettings = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: updateOidcSettings,
		onSuccess: (data) => {
			queryClient.setQueryData(["oidc-settings"], data);
		},
	});
};

export const useTestOidcSettings = () => useMutation({ mutationFn: testOidcSettings });
