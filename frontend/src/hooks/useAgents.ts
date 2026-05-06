import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
	type Agent,
	type AgentCreateData,
	type AgentUpdateData,
	createAgent,
	deleteAgent,
	getAgents,
	updateAgent,
} from "src/api/backend";

const useAgents = (options = {}) => {
	return useQuery<Agent[], Error>({
		queryKey: ["agents"],
		queryFn: getAgents,
		staleTime: 30 * 1000,
		...options,
	});
};

const useCreateAgent = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (data: AgentCreateData) => createAgent(data),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["agents"] });
		},
	});
};

const useUpdateAgent = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: ({ id, data }: { id: number; data: AgentUpdateData }) => updateAgent(id, data),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["agents"] });
		},
	});
};

const useDeleteAgent = () => {
	const queryClient = useQueryClient();
	return useMutation({
		mutationFn: (id: number) => deleteAgent(id),
		onSuccess: () => {
			queryClient.invalidateQueries({ queryKey: ["agents"] });
		},
	});
};

export { useAgents, useCreateAgent, useDeleteAgent, useUpdateAgent };
