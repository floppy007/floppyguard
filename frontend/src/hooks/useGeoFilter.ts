import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getGeoFilter, refreshGeoFilter, updateGeoFilter } from "src/api/backend";

export const useGeoFilter = (enabled = true) =>
	useQuery({
		queryKey: ["geo-filter"],
		queryFn: getGeoFilter,
		refetchOnWindowFocus: false,
		enabled,
	});

export const useUpdateGeoFilter = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: updateGeoFilter,
		onSuccess: (data) => {
			queryClient.setQueryData(["geo-filter"], data);
		},
	});
};

export const useRefreshGeoFilter = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: refreshGeoFilter,
		onSuccess: (data) => {
			queryClient.setQueryData(["geo-filter"], data);
		},
	});
};
