import { IconHelp, IconSearch } from "@tabler/icons-react";
import { useCallback, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { deleteCertificate, downloadCertificate } from "src/api/backend";
import { Button, HasPermission, LoadingPage } from "src/components";
import { useCertificates } from "src/hooks";
import { T } from "src/locale";
import { showDeleteConfirmModal, showHelpModal, showRenewCertificateModal } from "src/modals";
import { CERTIFICATES, MANAGE } from "src/modules/Permissions";
import { showError, showObjectSuccess } from "src/notifications";
import AddCertificateDropdown from "./AddCertificateDropdown";
import Table from "./Table";

export default function TableWrapper() {
	const [search, setSearch] = useState("");
	const { isFetching, isLoading, isError, error, data } = useCertificates([
		"owner",
		"dead_hosts",
		"proxy_hosts",
		"redirection_hosts",
		"streams",
	]);

	const handleDelete = useCallback(
		(id: number) =>
			showDeleteConfirmModal({
				title: <T id="object.delete" tData={{ object: "certificate" }} />,
				onConfirm: async () => {
					await deleteCertificate(id);
					showObjectSuccess("certificate", "deleted");
				},
				invalidations: [["certificates"], ["certificate", id]],
				children: <T id="object.delete.content" tData={{ object: "certificate" }} />,
			}),
		[],
	);

	const handleDownload = useCallback(async (id: number) => {
		try {
			await downloadCertificate(id);
		} catch (err: any) {
			showError(err.message);
		}
	}, []);

	if (isLoading) {
		return <LoadingPage />;
	}

	if (isError) {
		return <Alert variant="danger">{error?.message || "Unknown error"}</Alert>;
	}

	let filtered = null;
	if (search && data?.length) {
		filtered = data?.filter(
			(item) =>
				item.domainNames.some((domain: string) => domain.toLowerCase().includes(search)) ||
				item.niceName.toLowerCase().includes(search),
		);
	} else if (search !== "") {
		// list became empty (e.g. last matching item deleted) - drop the stale filter
		setSearch("");
	}

	return (
		<div className="card platform-admin-card">
			<div className="card-status-top bg-pink" />
			<div className="card-table">
				<div className="card-header">
					<div className="platform-admin-header">
						<div>
							<h2 className="platform-admin-title">
								<T id="certificates" />
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
							<Button size="sm" onClick={() => showHelpModal("Certificates", "pink")}>
								<IconHelp size={20} />
							</Button>
							<HasPermission section={CERTIFICATES} permission={MANAGE} hideError>
								{data?.length ? <AddCertificateDropdown className="btn-sm mt-1" /> : null}
							</HasPermission>
						</div>
					</div>
				</div>
				<Table
					data={filtered ?? data ?? []}
					isFiltered={!!search}
					isFetching={isFetching}
					onRenew={showRenewCertificateModal}
					onDownload={handleDownload}
					onDelete={handleDelete}
				/>
			</div>
		</div>
	);
}
