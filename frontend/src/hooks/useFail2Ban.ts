import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getFail2BanStatus, unbanIp } from "src/api/backend";

export const useFail2BanStatus = () =>
	useQuery({
		queryKey: ["fail2ban"],
		queryFn: getFail2BanStatus,
		refetchInterval: 30_000,
	});

export const useUnbanIp = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: ({ jail, ip }: { jail: string; ip: string }) => unbanIp(jail, ip),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["fail2ban"] });
		},
	});
};
