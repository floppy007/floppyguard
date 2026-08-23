import { Alert } from "react-bootstrap";
import { Button, Loading } from "src/components";
import { useApplicationUpdate, useCheckVersion, useStartApplicationUpdate } from "src/hooks";

const activeStates = new Set(["queued", "running", "restarting"]);

export default function ApplicationUpdate() {
	const version = useCheckVersion();
	const status = useApplicationUpdate();
	const start = useStartApplicationUpdate();
	const updateAvailable = version.data?.updateAvailable === true;
	const updateActive = activeStates.has(status.data?.state || "");

	const beginUpdate = () => {
		if (
			!window.confirm(
				"FloppyGuard will download the update from the configured Git branch, install the locked dependencies, rebuild the interface, and restart the service. Start now?",
			)
		) {
			return;
		}
		start.mutate();
	};

	return (
		<div className="card-body">
			<div className="d-flex align-items-start justify-content-between gap-3 flex-wrap mb-4">
				<div>
					<h3 className="card-title mb-1">Application update</h3>
					<div className="text-secondary small">
						Updates are started deliberately by administrators only and are loaded from the configured Git branch.
					</div>
				</div>
				<Button
					color={updateAvailable ? "green" : "blue"}
					disabled={!updateAvailable || updateActive || start.isPending}
					isLoading={start.isPending}
					onClick={beginUpdate}
				>
					{updateActive ? "Update in progress" : "Install update"}
				</Button>
			</div>

			{version.isLoading ? (
				<Loading noLogo />
			) : version.isError ? (
				<Alert variant="warning">The version check could not be reached.</Alert>
			) : (
				<Alert variant={updateAvailable ? "success" : "secondary"}>
					<div className="fw-bold">
						{updateAvailable ? "An update is available." : "FloppyGuard is up to date."}
					</div>
					<div className="small mt-1">
						Installed: {version.data?.current || "unknown"}
						{updateAvailable ? ` · New version: ${version.data?.latest || "unknown"}` : ""}
					</div>
				</Alert>
			)}

			{status.data && status.data.state !== "idle" && (
				<Alert variant={status.data.state === "failed" ? "danger" : status.data.state === "completed" ? "success" : "info"}>
					<div className="fw-bold">{status.data.message}</div>
					<div className="small mt-1 text-secondary">
						Status: {status.data.step}
						{status.data.target ? ` · Target: ${status.data.target}` : ""}
					</div>
				</Alert>
			)}

			{start.error && <Alert variant="danger">{start.error.message}</Alert>}
			<div className="text-secondary small">
				The service remains available until the controlled restart. Progress is updated here automatically.
			</div>
		</div>
	);
}
