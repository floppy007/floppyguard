import { useQuery } from "@tanstack/react-query";
import { getHealth, type HealthResponse } from "src/api/backend";

const fetchHealth = () => getHealth();
const HEALTH_CACHE_KEY = "floppyguard.health-cache";
const HEALTH_CACHE_TTL_MS = 15 * 60 * 1000;

interface CachedHealthPayload {
	data: HealthResponse;
	updatedAt: number;
}

const readCachedHealth = (): CachedHealthPayload | undefined => {
	const cached = localStorage.getItem(HEALTH_CACHE_KEY);
	if (!cached) {
		return undefined;
	}

	try {
		const parsed = JSON.parse(cached) as CachedHealthPayload;
		if (Date.now() - parsed.updatedAt > HEALTH_CACHE_TTL_MS) {
			localStorage.removeItem(HEALTH_CACHE_KEY);
			return undefined;
		}
		return parsed;
	} catch {
		localStorage.removeItem(HEALTH_CACHE_KEY);
		return undefined;
	}
};

const writeCachedHealth = (data: HealthResponse) => {
	localStorage.setItem(
		HEALTH_CACHE_KEY,
		JSON.stringify({
			data,
			updatedAt: Date.now(),
		} satisfies CachedHealthPayload),
	);
};

const useHealth = () => {
	const cached = readCachedHealth();
	const query = useQuery<HealthResponse, Error>({
		queryKey: ["health"],
		queryFn: fetchHealth,
		refetchOnWindowFocus: false,
		refetchOnMount: cached ? false : "always",
		retry: 1,
		retryDelay: 750,
		refetchOnReconnect: false,
		refetchInterval: 60 * 1000,
		staleTime: 60 * 1000,
		...(cached ? { initialData: cached.data, initialDataUpdatedAt: cached.updatedAt } : {}),
	});

	if (query.data) {
		writeCachedHealth(query.data);
	}

	return query;
};

export { fetchHealth, useHealth };
