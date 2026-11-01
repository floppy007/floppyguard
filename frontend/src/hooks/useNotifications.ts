import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getCertProblems, getNotifications, testNotifications, updateNotifications } from "src/api/backend";

export const useNotifications = () =>
	useQuery({ queryKey: ["notifications"], queryFn: getNotifications, refetchOnWindowFocus: false });

export const useUpdateNotifications = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: updateNotifications,
		onSuccess: (data) => queryClient.setQueryData(["notifications"], data),
	});
};

export const useTestNotifications = () => useMutation({ mutationFn: testNotifications });

/** Zertifikats-Warnungen (nur Admins); alle 5 Minuten neu. */
export const useCertProblems = (enabled = true) =>
	useQuery({
		queryKey: ["cert-problems"],
		queryFn: getCertProblems,
		enabled,
		refetchInterval: 5 * 60 * 1000,
		staleTime: 60 * 1000,
	});
