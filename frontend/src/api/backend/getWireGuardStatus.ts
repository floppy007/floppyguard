import { get } from "./base";
import type { WireGuardStatus } from "./models";

export function getWireGuardStatus() {
	return get({ url: "wireguard/status" }) as Promise<WireGuardStatus>;
}
