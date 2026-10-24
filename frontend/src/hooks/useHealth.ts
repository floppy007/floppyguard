import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { getHealth, type HealthResponse } from "src/api/backend";
import { safeLocal } from "src/modules/safeStorage";

const fetchHealth = () => getHealth();
const HEALTH_CACHE_KEY = "floppyguard.health-cache-v2";
const HEALTH_CACHE_TTL_MS = 15 * 60 * 1000;

interface CachedHealthPayload {
	data: HealthResponse;
	updatedAt: number;
}

const readCachedHealth = (): CachedHealthPayload | undefined => {
	const cached = safeLocal.get(HEALTH_CACHE_KEY);
	if (!cached) {
		return undefined;
	}

	try {
		const parsed = JSON.parse(cached) as CachedHealthPayload;
		if (Date.now() - parsed.updatedAt > HEALTH_CACHE_TTL_MS) {
			safeLocal.remove(HEALTH_CACHE_KEY);
			return undefined;
		}
		return parsed;
	} catch {
		safeLocal.remove(HEALTH_CACHE_KEY);
		return undefined;
	}
};

// Several components use the hook; persist each fetched result once, not once per render/consumer.
let lastWrittenAt = 0;

const writeCachedHealth = (data: HealthResponse, updatedAt: number) => {
	if (updatedAt <= lastWrittenAt) {
		return;
	}
	lastWrittenAt = updatedAt;
	// Keep the fetch time, not "now": re-saving cached data must not extend its TTL
	safeLocal.set(HEALTH_CACHE_KEY, JSON.stringify({ data, updatedAt } satisfies CachedHealthPayload));
};

const useHealth = () => {
	const query = useQuery<HealthResponse, Error>({
		queryKey: ["health"],
		queryFn: fetchHealth,
		refetchOnWindowFocus: false,
		refetchOnMount: "always",
		retry: 1,
		retryDelay: 750,
		refetchOnReconnect: false,
		refetchInterval: 60 * 1000,
		staleTime: 60 * 1000,
		// Functions: only evaluated when the query is first created, not on every render
		initialData: () => readCachedHealth()?.data,
		initialDataUpdatedAt: () => readCachedHealth()?.updatedAt,
	});

	const { data, dataUpdatedAt } = query;
	useEffect(() => {
		if (data && dataUpdatedAt) {
			writeCachedHealth(data, dataUpdatedAt);
		}
	}, [data, dataUpdatedAt]);

	return query;
};

export { fetchHealth, HEALTH_CACHE_KEY, useHealth };
