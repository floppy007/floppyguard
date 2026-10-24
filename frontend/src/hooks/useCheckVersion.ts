import { useQuery } from "@tanstack/react-query";
import { checkVersion, type VersionCheckResponse } from "src/api/backend";

const fetchVersion = () => checkVersion();

const useCheckVersion = (options = {}) => {
	return useQuery<VersionCheckResponse, Error>({
		queryKey: ["version-check"],
		queryFn: fetchVersion,
		refetchOnWindowFocus: false,
		retry: 5,
		refetchInterval: 5 * 60 * 1000, // 5 min: matches staleTime; the backend caches the GitHub result, so polling faster never yields new data
		staleTime: 5 * 60 * 1000, // 5 mins
		...options,
	});
};

export { fetchVersion, useCheckVersion };
