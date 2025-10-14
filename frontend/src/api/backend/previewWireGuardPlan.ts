import { post } from "./base";
import type { WireGuardMetadataPatch, WireGuardPlanPreviewResponse } from "./models";

export function previewWireGuardPlan(data: WireGuardMetadataPatch) {
	return post({ url: "wireguard/plan-preview", data, rawBody: true }) as Promise<WireGuardPlanPreviewResponse>;
}
