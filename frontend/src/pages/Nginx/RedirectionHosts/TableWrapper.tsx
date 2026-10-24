import { IconHelp, IconSearch } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { deleteRedirectionHost, toggleRedirectionHost } from "src/api/backend";
import { Button, HasPermission, LoadingPage } from "src/components";
import { useRedirectionHosts } from "src/hooks";
import { T } from "src/locale";
import { showDeleteConfirmModal, showHelpModal, showRedirectionHostModal } from "src/modals";
import { MANAGE, REDIRECTION_HOSTS } from "src/modules/Permissions";
import { showError, showObjectSuccess } from "src/notifications";
import Table from "./Table";

export default function TableWrapper() {
	const queryClient = useQueryClient();
	const [search, setSearch] = useState("");
	const { isFetching, isLoading, isError, error, data } = useRedirectionHosts(["owner", "certificate"]);

	const handleDelete = useCallback(
		(id: number) =>
			showDeleteConfirmModal({
				title: <T id="object.delete" tData={{ object: "redirection-host" }} />,
				onConfirm: async () => {
					await deleteRedirectionHost(id);
					showObjectSuccess("redirection-host", "deleted");
				},
				invalidations: [["redirection-hosts"], ["redirection-host", id]],
				children: <T id="object.delete.content" tData={{ object: "redirection-host" }} />,
			}),
		[],
	);

	const handleDisableToggle = useCallback(
		async (id: number, enabled: boolean) => {
			try {
				await toggleRedirectionHost(id, enabled);
				showObjectSuccess("redirection-host", enabled ? "enabled" : "disabled");
			} catch (err) {
				showError(err instanceof Error ? err.message : String(err));
			} finally {
				queryClient.invalidateQueries({ queryKey: ["redirection-hosts"] });
				queryClient.invalidateQueries({ queryKey: ["redirection-host", id] });
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
			return (
				item.domainNames.some((domain: string) => domain.toLowerCase().includes(search)) ||
				item.forwardDomainName.toLowerCase().includes(search)
			);
		});
	} else if (search !== "") {
		// list became empty (e.g. last matching item deleted) - drop the stale filter
		setSearch("");
	}

	return (
		<div className="card platform-admin-card">
			<div className="card-status-top bg-yellow" />
			<div className="card-table">
				<div className="card-header">
					<div className="platform-admin-header">
						<div>
							<h2 className="platform-admin-title">
								<T id="redirection-hosts" />
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
							<Button size="sm" onClick={() => showHelpModal("RedirectionHosts", "yellow")}>
								<IconHelp size={20} />
							</Button>
							<HasPermission section={REDIRECTION_HOSTS} permission={MANAGE} hideError>
								{data?.length ? (
									<Button
										size="sm"
										className="btn-yellow"
										onClick={() => showRedirectionHostModal("new")}
									>
										<T id="object.add" tData={{ object: "redirection-host" }} />
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
					onEdit={showRedirectionHostModal}
					onDelete={handleDelete}
					onDisableToggle={handleDisableToggle}
					onNew={() => showRedirectionHostModal("new")}
				/>
			</div>
		</div>
	);
}
