import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getApplicationUpdate, startApplicationUpdate } from "src/api/backend";

export const useApplicationUpdate = () =>
	useQuery({
		queryKey: ["application-update"],
		queryFn: getApplicationUpdate,
		refetchInterval: 5_000,
		refetchOnWindowFocus: true,
	});

export const useStartApplicationUpdate = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: startApplicationUpdate,
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["application-update"] });
		},
	});
};
