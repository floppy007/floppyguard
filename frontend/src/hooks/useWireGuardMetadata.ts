import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	applyWireGuardMetadata,
	getWireGuardApplyState,
	getWireGuardMetadata,
	previewWireGuardPlan,
	restoreWireGuardMetadata,
	type WireGuardApplyStateResponse,
	type WireGuardMetadataPatch,
	type WireGuardMetadataResponse,
} from "src/api/backend";

const fetchWireGuardMetadata = () => getWireGuardMetadata();
const fetchWireGuardApplyState = () => getWireGuardApplyState();

const useWireGuardMetadata = (options = {}) => {
	return useQuery<WireGuardMetadataResponse, Error>({
		queryKey: ["wireguard-metadata"],
		queryFn: fetchWireGuardMetadata,
		staleTime: 30 * 1000,
		...options,
	});
};

const useWireGuardApplyState = (options = {}) => {
	return useQuery<WireGuardApplyStateResponse, Error>({
		queryKey: ["wireguard-apply-state"],
		queryFn: fetchWireGuardApplyState,
		staleTime: 30 * 1000,
		...options,
	});
};

const useApplyWireGuardMetadata = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (values: WireGuardMetadataPatch) => applyWireGuardMetadata(values),
		onSuccess: async () => {
			queryClient.invalidateQueries({ queryKey: ["wireguard-metadata"] });
			queryClient.invalidateQueries({ queryKey: ["wireguard-status"] });
			queryClient.invalidateQueries({ queryKey: ["wireguard-apply-state"] });
		},
	});
};

const useRestoreWireGuardMetadata = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (backupPath: string) => restoreWireGuardMetadata(backupPath),
		onSuccess: async () => {
			queryClient.invalidateQueries({ queryKey: ["wireguard-metadata"] });
			queryClient.invalidateQueries({ queryKey: ["wireguard-status"] });
			queryClient.invalidateQueries({ queryKey: ["wireguard-apply-state"] });
		},
	});
};

const usePreviewWireGuardPlan = () => {
	return useMutation({
		mutationFn: (values: WireGuardMetadataPatch) => previewWireGuardPlan(values),
	});
};

export { fetchWireGuardApplyState, fetchWireGuardMetadata, useApplyWireGuardMetadata, usePreviewWireGuardPlan, useRestoreWireGuardMetadata, useWireGuardApplyState, useWireGuardMetadata };
