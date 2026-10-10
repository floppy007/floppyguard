import { get, put } from "./base";
import type { SiteIsolationOverview, SiteIsolationPairInput } from "./models";

/** "Standorte untereinander": sites, blocked pairs, applied state and warnings. */
export function getSiteIsolation(): Promise<SiteIsolationOverview> {
	return get({ url: "site-isolation" }) as Promise<SiteIsolationOverview>;
}

/** Replace the FULL set of blocked pairs; the hub applies it and returns the new overview. */
export function setSiteIsolation(pairs: SiteIsolationPairInput[]): Promise<SiteIsolationOverview> {
	return put({ url: "site-isolation", data: { pairs } }) as Promise<SiteIsolationOverview>;
}
