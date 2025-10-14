import Alert from "react-bootstrap/Alert";
import { LoadingPage } from "src/components";
import { useAuditLogs } from "src/hooks";
import { T } from "src/locale";
import { showEventDetailsModal } from "src/modals";
import Table from "./Table";

export default function TableWrapper() {
	const { isFetching, isLoading, isError, error, data } = useAuditLogs(["user"]);

	if (isLoading) {
		return <LoadingPage />;
	}

	if (isError) {
		return <Alert variant="danger">{error?.message || "Unknown error"}</Alert>;
	}

	return (
		<div className="card platform-admin-card">
			<div className="card-status-top bg-purple" />
			<div className="card-table">
				<div className="card-header">
					<div className="platform-admin-header">
						<div>
							<h2 className="platform-admin-title">
								<T id="auditlogs" />
							</h2>
						</div>
					</div>
				</div>
				<Table data={data ?? []} isFetching={isFetching} onSelectItem={showEventDetailsModal} />
			</div>
		</div>
	);
}
