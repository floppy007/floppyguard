import { IconHelp, IconSearch } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { deleteDeadHost, toggleDeadHost } from "src/api/backend";
import { Button, HasPermission, LoadingPage } from "src/components";
import { useDeadHosts } from "src/hooks";
import { T } from "src/locale";
import { showDeadHostModal, showDeleteConfirmModal, showHelpModal } from "src/modals";
import { DEAD_HOSTS, MANAGE } from "src/modules/Permissions";
import { showError, showObjectSuccess } from "src/notifications";
import Table from "./Table";

export default function TableWrapper() {
	const queryClient = useQueryClient();
	const [search, setSearch] = useState("");
	const { isFetching, isLoading, isError, error, data } = useDeadHosts(["owner", "certificate"]);

	const handleDelete = useCallback(
		(id: number) =>
			showDeleteConfirmModal({
				title: <T id="object.delete" tData={{ object: "dead-host" }} />,
				onConfirm: async () => {
					await deleteDeadHost(id);
					showObjectSuccess("dead-host", "deleted");
				},
				invalidations: [["dead-hosts"], ["dead-host", id]],
				children: <T id="object.delete.content" tData={{ object: "dead-host" }} />,
			}),
		[],
	);

	const handleDisableToggle = useCallback(
		async (id: number, enabled: boolean) => {
			try {
				await toggleDeadHost(id, enabled);
				showObjectSuccess("dead-host", enabled ? "enabled" : "disabled");
			} catch (err) {
				showError(err instanceof Error ? err.message : String(err));
			} finally {
				queryClient.invalidateQueries({ queryKey: ["dead-hosts"] });
				queryClient.invalidateQueries({ queryKey: ["dead-host", id] });
			}
		},
		[queryClient],
	);

	if (isLoading) {
		return <LoadingPage />;
	}

	if (isError) {
		return <Alert variant="danger">{error?.message || "Unknown error"}</Alert>;
	}

	let filtered = null;
	if (search && data?.length) {
		filtered = data?.filter((item) => {
			return item.domainNames.some((domain: string) => domain.toLowerCase().includes(search));
		});
	} else if (search !== "") {
		// list became empty (e.g. last matching item deleted) - drop the stale filter
		setSearch("");
	}

	return (
		<div className="card platform-admin-card">
			<div className="card-status-top bg-red" />
			<div className="card-table">
				<div className="card-header">
					<div className="platform-admin-header">
						<div>
							<h2 className="platform-admin-title">
								<T id="dead-hosts" />
							</h2>
						</div>

						<div className="platform-admin-tools">
							{data?.length ? (
								<div className="input-group input-group-flat platform-search">
									<span className="input-group-text input-group-text-sm">
										<IconSearch size={16} />
									</span>
									<input
										id="advanced-table-search"
										type="text"
										className="form-control form-control-sm"
										autoComplete="off"
										onChange={(e: any) => setSearch(e.target.value.toLowerCase().trim())}
									/>
								</div>
							) : null}
							<Button size="sm" onClick={() => showHelpModal("DeadHosts", "red")}>
								<IconHelp size={20} />
							</Button>
							<HasPermission section={DEAD_HOSTS} permission={MANAGE} hideError>
								{data?.length ? (
									<Button size="sm" className="btn-red" onClick={() => showDeadHostModal("new")}>
										<T id="object.add" tData={{ object: "dead-host" }} />
									</Button>
								) : null}
							</HasPermission>
						</div>
					</div>
				</div>
				<Table
					data={filtered ?? data ?? []}
					isFiltered={!!search}
					isFetching={isFetching}
					onEdit={showDeadHostModal}
					onDelete={handleDelete}
					onDisableToggle={handleDisableToggle}
					onNew={() => showDeadHostModal("new")}
				/>
			</div>
		</div>
	);
}
