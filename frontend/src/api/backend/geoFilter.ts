import * as api from "./base";

export interface GeoFilterHost {
	id: number;
	domainNames: string[];
	enabled: boolean;
}

export interface GeoFilterStats {
	days: number;
	total: number;
	countries: { code: string; count: number }[];
	hosts: { host: string; count: number }[];
	topIps: { ip: string; code: string; count: number }[];
	perDay: { day: string; count: number }[];
}

export interface GeoFilterStatus {
	countries: string[];
	defaultCountries: string[];
	euCountries: string[];
	activeCountries: string[];
	updatedAt: string | null;
	ranges: number;
	fallback: boolean;
	pending: boolean;
	refreshing: boolean;
	lastError: string | null;
	lastAttemptAt: string | null;
	hosts: GeoFilterHost[];
	source: string;
	allCountries: string[];
	stats: GeoFilterStats;
}

export async function getGeoFilter(): Promise<GeoFilterStatus> {
	return await api.get({ url: "/geo-filter" });
}

export async function updateGeoFilter(data: { countries: string[] }): Promise<GeoFilterStatus> {
	return await api.put({ url: "/geo-filter", data });
}

export async function refreshGeoFilter(): Promise<GeoFilterStatus> {
	return await api.post({ url: "/geo-filter/refresh", data: {} });
}
