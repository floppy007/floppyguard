import { get } from "./base";

export interface BandwidthSample {
	ts: number;
	rx: number;
	tx: number;
}

export interface PeerBandwidth {
	id: string;
	name: string;
	history: BandwidthSample[];
}

export type BandwidthRange = "live" | "24h" | "30d" | "12m";

export function getWireGuardBandwidth(range: BandwidthRange = "live"): Promise<PeerBandwidth[]> {
	return get({ url: `wireguard/bandwidth?range=${range}` }) as Promise<PeerBandwidth[]>;
}
