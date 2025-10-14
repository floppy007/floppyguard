import { get } from "./base";
import type { WireGuardApplyStateResponse } from "./models";

export function getWireGuardApplyState() {
	return get({ url: "wireguard/apply-state" }) as Promise<WireGuardApplyStateResponse>;
}
