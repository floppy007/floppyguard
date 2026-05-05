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

export function getWireGuardBandwidth(): Promise<PeerBandwidth[]> {
	return get({ url: "wireguard/bandwidth" }) as Promise<PeerBandwidth[]>;
}
