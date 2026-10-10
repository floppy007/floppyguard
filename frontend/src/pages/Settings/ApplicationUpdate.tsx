import { useEffect, useRef } from "react";
import { Alert } from "react-bootstrap";
import { Button, Loading } from "src/components";
import { useApplicationUpdate, useCheckVersion, useStartApplicationUpdate } from "src/hooks";
import { intl } from "src/locale/IntlProvider";

const activeStates = new Set(["queued", "running", "restarting"]);

/** Delay before reloading into the new bundle, so the "completed" message is visible. */
const RELOAD_DELAY_MS = 3_000;

const t = (id: string, values?: Record<string, string>) => intl.formatMessage({ id: `settings.update.${id}` }, values);

export default function ApplicationUpdate() {
	const version = useCheckVersion();
	const status = useApplicationUpdate();
	const start = useStartApplicationUpdate();
	const updateAvailable = version.data?.updateAvailable === true;
	const state = status.data?.state || "";
	const updateActive = activeStates.has(state);
	const unknown = t("unknown");

	// The update rebuilt the interface and deleted the old chunks: once this tab saw
	// it finish, load the new bundle (only on the transition, not on every visit).
	const prevState = useRef(state);
	const reloading = activeStates.has(prevState.current) && state === "completed";
	useEffect(() => {
		const wasActive = activeStates.has(prevState.current);
		prevState.current = state;
		if (!wasActive || state !== "completed") return;
		const timer = window.setTimeout(() => window.location.reload(), RELOAD_DELAY_MS);
		return () => window.clearTimeout(timer);
	}, [state]);

	const beginUpdate = () => {
		if (!window.confirm(t("confirm"))) {
			return;
		}
		start.mutate();
	};

	return (
		<div className="card-body">
			<div className="d-flex align-items-start justify-content-between gap-3 flex-wrap mb-4">
				<div>
					<h3 className="card-title mb-1">{t("title")}</h3>
					<div className="text-secondary small">{t("intro")}</div>
				</div>
				<Button
					color={updateAvailable ? "green" : "blue"}
					disabled={!updateAvailable || updateActive || start.isPending}
					isLoading={start.isPending}
					onClick={beginUpdate}
				>
					{updateActive ? t("in-progress") : t("install")}
				</Button>
			</div>

			{version.isLoading ? (
				<Loading noLogo />
			) : version.isError ? (
				<Alert variant="warning">{t("check-failed")}</Alert>
			) : (
				<Alert variant={updateAvailable ? "success" : "secondary"}>
					<div className="fw-bold">{updateAvailable ? t("available") : t("up-to-date")}</div>
					<div className="small mt-1">
						{t("installed", { version: version.data?.current || unknown })}
						{updateAvailable ? ` · ${t("new-version", { version: version.data?.latest || unknown })}` : ""}
					</div>
				</Alert>
			)}

			{status.data && status.data.state !== "idle" && (
				<Alert
					variant={
						status.data.state === "failed"
							? "danger"
							: status.data.state === "completed"
								? "success"
								: "info"
					}
				>
					<div className="fw-bold">{status.data.message}</div>
					<div className="small mt-1 text-secondary">
						{t("status", { step: status.data.step })}
						{status.data.target ? ` · ${t("target", { target: status.data.target })}` : ""}
					</div>
					{reloading && <div className="small mt-1">{t("reloading")}</div>}
				</Alert>
			)}

			{start.error && <Alert variant="danger">{start.error.message}</Alert>}
			<div className="text-secondary small">{t("footer")}</div>
		</div>
	);
}
