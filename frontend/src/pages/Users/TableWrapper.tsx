import { IconSearch } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { deleteUser, toggleUser } from "src/api/backend";
import { Button, LoadingPage } from "src/components";
import { useAuthState } from "src/context";
import { useUser, useUsers } from "src/hooks";
import { T } from "src/locale";
import { showDeleteConfirmModal, showPermissionsModal, showSetPasswordModal, showUserModal } from "src/modals";
import { showError, showObjectSuccess } from "src/notifications";
import Table from "./Table";

export default function TableWrapper() {
	const queryClient = useQueryClient();
	const { loginAs } = useAuthState();
	const [search, setSearch] = useState("");
	const { isFetching, isLoading, isError, error, data } = useUsers(["permissions"]);
	const { data: currentUser } = useUser("me");

	const handleDelete = useCallback(
		(id: number) =>
			showDeleteConfirmModal({
				title: <T id="object.delete" tData={{ object: "user" }} />,
				onConfirm: async () => {
					await deleteUser(id);
					showObjectSuccess("user", "deleted");
				},
				invalidations: [["users"], ["user", id]],
				children: <T id="object.delete.content" tData={{ object: "user" }} />,
			}),
		[],
	);

	const handleDisableToggle = useCallback(
		async (id: number, enabled: boolean) => {
			try {
				await toggleUser(id, enabled);
				showObjectSuccess("user", enabled ? "enabled" : "disabled");
			} catch (err) {
				showError(err instanceof Error ? err.message : String(err));
			} finally {
				queryClient.invalidateQueries({ queryKey: ["users"] });
				queryClient.invalidateQueries({ queryKey: ["user", id] });
			}
		},
		[queryClient],
	);

	const handleLoginAs = useCallback(
		async (id: number) => {
			try {
				await loginAs(id);
			} catch (err) {
				if (err instanceof Error) {
					showError(err.message);
				}
			}
		},
		[loginAs],
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
				item.name.toLowerCase().includes(search) ||
				item.nickname.toLowerCase().includes(search) ||
				item.email.toLowerCase().includes(search)
			);
		});
	} else if (search !== "") {
		// list became empty (e.g. last matching item deleted) - drop the stale filter
		setSearch("");
	}

	return (
		<div className="card platform-admin-card">
			<div className="card-status-top bg-orange" />
			<div className="card-table">
				<div className="card-header">
					<div className="platform-admin-header">
						<div>
							<h2 className="platform-admin-title">
								<T id="users" />
							</h2>
						</div>
						{data?.length ? (
							<div className="platform-admin-tools">
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

								<Button size="sm" className="btn-orange" onClick={() => showUserModal("new")}>
									<T id="object.add" tData={{ object: "user" }} />
								</Button>
							</div>
						) : null}
					</div>
				</div>
				<Table
					data={filtered ?? data ?? []}
					isFiltered={!!search}
					isFetching={isFetching}
					currentUserId={currentUser?.id}
					onEditUser={showUserModal}
					onEditPermissions={showPermissionsModal}
					onSetPassword={showSetPasswordModal}
					onDeleteUser={handleDelete}
					onDisableToggle={handleDisableToggle}
					onNewUser={() => showUserModal("new")}
					onLoginAs={handleLoginAs}
				/>
			</div>
		</div>
	);
}
