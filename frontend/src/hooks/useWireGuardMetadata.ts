import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	applyWireGuardMetadata,
	getWireGuardApplyState,
	previewWireGuardPlan,
	restoreWireGuardMetadata,
	type WireGuardApplyStateResponse,
	type WireGuardMetadataPatch,
} from "src/api/backend";
import { invalidateWireGuard } from "./wireguardKeys";

const useWireGuardApplyState = (options = {}) => {
	return useQuery<WireGuardApplyStateResponse, Error>({
		queryKey: ["wireguard-apply-state"],
		queryFn: getWireGuardApplyState,
		staleTime: 30 * 1000,
		...options,
	});
};

const useApplyWireGuardMetadata = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (values: WireGuardMetadataPatch) => applyWireGuardMetadata(values),
		// Apply cascades link renames into Agent.wg_link_name/allowed_sites and resyncs
		// agent config_text/config_hash — a stale agents cache would un-match the
		// agent in matchLinkAgent and let AgentSection auto-create a duplicate.
		onSuccess: async () => invalidateWireGuard(queryClient, { agents: true }),
	});
};

const useRestoreWireGuardMetadata = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (backupPath: string) => restoreWireGuardMetadata(backupPath),
		// The restore resyncs every agent's config
		onSuccess: async () => invalidateWireGuard(queryClient, { agents: true }),
	});
};

const usePreviewWireGuardPlan = () => {
	return useMutation({
		mutationFn: (values: WireGuardMetadataPatch) => previewWireGuardPlan(values),
	});
};

export { useApplyWireGuardMetadata, usePreviewWireGuardPlan, useRestoreWireGuardMetadata, useWireGuardApplyState };
