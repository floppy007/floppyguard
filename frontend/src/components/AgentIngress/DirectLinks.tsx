import { IconArrowsLeftRight } from "@tabler/icons-react";
import { type FormEvent, useId, useState } from "react";
import Alert from "react-bootstrap/Alert";
import type { Agent, DirectLink, DirectLinkInput, DirectLinkSideStatus } from "src/api/backend";
import { useAgents, useDeleteDirectLink, useDirectLinks, useSaveDirectLink } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { showDeleteConfirmModal } from "src/modals";
import { errMessage, ti } from "./utils";

// ── pure helpers (exported for tests) ─────────────────────────────────────────

/** Overall state of a link for the badge. */
export type DirectLinkState = "off" | "blocked" | "waiting" | "direct" | "partly" | "hub";

export const directLinkState = (l: DirectLink): DirectLinkState => {
	if (!l.enabled) return "off";
	if (l.blocked) return "blocked";
	const sides = [l.statusA, l.statusB];
	if (sides.some((s) => !s.publicKeyKnown || s.stale || !s.up)) return "waiting";
	const direct = sides.filter((s) => s.path === "direct").length;
	return direct === 2 ? "direct" : direct === 1 ? "partly" : "hub";
};

const stateBadge: Record<DirectLinkState, string> = {
	off: "bg-secondary-lt",
	blocked: "bg-red-lt",
	waiting: "bg-yellow-lt",
	direct: "bg-green-lt",
	partly: "bg-orange-lt",
	hub: "bg-orange-lt",
};

/** LAN address the agent reports in its hostname ("VM-Docker (192.168.20.7)"). */
export const agentLanIp = (agent: Pick<Agent, "hostname"> | undefined): string | null =>
	agent?.hostname?.match(/\((\d{1,3}(?:\.\d{1,3}){3})\)\s*$/)?.[1] ?? null;

/** First free /30 in 10.10.9.0/24 that no link uses yet. */
export const suggestTunnelSubnet = (links: Pick<DirectLink, "tunnelSubnet">[]): string => {
	const used = new Set(links.map((l) => l.tunnelSubnet));
	for (let n = 0; n < 256; n += 4) {
		const cidr = `10.10.9.${n}/30`;
		if (!used.has(cidr)) return cidr;
	}
	return "";
};

/** Site agents = bound to a link; road-warrior links are filtered by the backend. */
const siteAgents = (agents: Agent[]) => agents.filter((a) => a.wgLinkName);

const emptyForm = (links: DirectLink[]): DirectLinkInput => ({
	name: "",
	agentAId: 0,
	agentBId: 0,
	listenPort: 51830,
	endpointHost: "",
	tunnelSubnet: suggestTunnelSubnet(links),
	mtu: 1300,
	enabled: false,
	natA: false,
	natB: false,
});

const toForm = (l: DirectLink): DirectLinkInput => ({
	name: l.name,
	agentAId: l.agentAId,
	agentBId: l.agentBId,
	listenPort: l.listenPort,
	endpointHost: l.endpointHost,
	tunnelSubnet: l.tunnelSubnet,
	mtu: l.mtu,
	enabled: l.enabled,
	natA: l.natA,
	natB: l.natB,
});

function SideStatus({ name, status }: { name: string | null; status: DirectLinkSideStatus }) {
	let text: string;
	if (!status.publicKeyKnown) text = ti("direct.side.no-key");
	else if (status.stale) text = ti("direct.side.stale");
	else if (!status.up) text = ti("direct.side.down");
	else if (status.path === "direct") text = ti("direct.side.direct");
	else text = ti("direct.side.hub");
	const details = [
		status.rttMs != null ? `${status.rttMs} ms` : null,
		status.handshakeAge != null && status.handshakeAge >= 0
			? ti("direct.side.handshake", { s: status.handshakeAge })
			: null,
	].filter(Boolean);
	return (
		<div className="small">
			<span className="fw-medium">{name ?? "?"}</span>: {text}
			{details.length > 0 && <span className="text-secondary"> · {details.join(" · ")}</span>}
			{status.error && <div className="text-danger text-break">{status.error}</div>}
		</div>
	);
}

function LinkForm({
	initial,
	editId,
	agents,
	onDone,
}: {
	initial: DirectLinkInput;
	editId: number | null;
	agents: Agent[];
	onDone: () => void;
}) {
	const [f, setF] = useState<DirectLinkInput>(initial);
	const [error, setError] = useState<string | null>(null);
	const save = useSaveDirectLink();
	const id = useId();
	const set = <K extends keyof DirectLinkInput>(k: K, v: DirectLinkInput[K]) => setF((p) => ({ ...p, [k]: v }));
	const a = agents.find((x) => x.id === f.agentAId);
	const b = agents.find((x) => x.id === f.agentBId);
	const lanA = agentLanIp(a);

	const submit = async (e: FormEvent) => {
		e.preventDefault();
		setError(null);
		try {
			await save.mutateAsync({ id: editId ?? undefined, data: f });
			onDone();
		} catch (err) {
			setError(errMessage(err));
		}
	};

	const agentSelect = (key: "agentAId" | "agentBId", label: string, help: string) => (
		<div className="col-md-6">
			<label className="form-label" htmlFor={`${id}-${key}`}>
				{label}
			</label>
			<select
				id={`${id}-${key}`}
				className="form-select"
				value={f[key] || ""}
				onChange={(e) => set(key, Number(e.target.value))}
				required
				data-testid={`direct-form-${key}`}
			>
				<option value="">{ti("direct.form.choose")}</option>
				{agents.map((ag) => (
					<option key={ag.id} value={ag.id}>
						{ag.wgLinkName ?? ag.name}
					</option>
				))}
			</select>
			<div className="form-text">{help}</div>
		</div>
	);

	return (
		<form className="border rounded p-3 d-flex flex-column gap-3" onSubmit={submit} data-testid="direct-form">
			<div className="fw-medium">{ti(editId ? "direct.form.edit-title" : "direct.form.new-title")}</div>
			<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible className="mb-0">
				{error}
			</Alert>
			<div className="row g-3">
				<div className="col-md-6">
					<label className="form-label" htmlFor={`${id}-name`}>
						{ti("direct.form.name")}
					</label>
					<input
						id={`${id}-name`}
						className="form-control"
						value={f.name}
						maxLength={64}
						onChange={(e) => set("name", e.target.value)}
						required
					/>
				</div>
				<div className="col-md-6" />
				{agentSelect("agentAId", ti("direct.form.agent-a"), ti("direct.form.agent-a-help"))}
				{agentSelect("agentBId", ti("direct.form.agent-b"), ti("direct.form.agent-b-help"))}
				<div className="col-md-6">
					<label className="form-label" htmlFor={`${id}-host`}>
						{ti("direct.form.endpoint")}
					</label>
					<input
						id={`${id}-host`}
						className="form-control font-monospace"
						value={f.endpointHost}
						placeholder="203.0.113.10"
						onChange={(e) => set("endpointHost", e.target.value.trim())}
						required
					/>
					<div className="form-text">{ti("direct.form.endpoint-help")}</div>
				</div>
				<div className="col-md-3">
					<label className="form-label" htmlFor={`${id}-port`}>
						{ti("direct.form.port")}
					</label>
					<input
						id={`${id}-port`}
						type="number"
						min={1024}
						max={65535}
						className="form-control"
						value={f.listenPort}
						onChange={(e) => set("listenPort", Number(e.target.value))}
						required
					/>
				</div>
				<div className="col-md-3">
					<label className="form-label" htmlFor={`${id}-mtu`}>
						MTU
					</label>
					<input
						id={`${id}-mtu`}
						type="number"
						min={1280}
						max={1500}
						className="form-control"
						value={f.mtu ?? ""}
						onChange={(e) => set("mtu", e.target.value ? Number(e.target.value) : null)}
					/>
				</div>
				<div className="col-md-6">
					<label className="form-label" htmlFor={`${id}-subnet`}>
						{ti("direct.form.subnet")}
					</label>
					<input
						id={`${id}-subnet`}
						className="form-control font-monospace"
						value={f.tunnelSubnet}
						onChange={(e) => set("tunnelSubnet", e.target.value.trim())}
						required
					/>
					<div className="form-text">{ti("direct.form.subnet-help")}</div>
				</div>
				<div className="col-md-6 d-flex flex-column gap-2">
					<label className="form-check mb-0">
						<input
							type="checkbox"
							className="form-check-input"
							checked={f.natA}
							onChange={(e) => set("natA", e.target.checked)}
						/>
						<span className="form-check-label">
							{ti("direct.form.nat", { site: a?.wgLinkName ?? ti("direct.form.side-a") })}
						</span>
					</label>
					<label className="form-check mb-0">
						<input
							type="checkbox"
							className="form-check-input"
							checked={f.natB}
							onChange={(e) => set("natB", e.target.checked)}
						/>
						<span className="form-check-label">
							{ti("direct.form.nat", { site: b?.wgLinkName ?? ti("direct.form.side-b") })}
						</span>
					</label>
					<div className="form-text mt-0">{ti("direct.form.nat-help")}</div>
					<label className="form-check mb-0">
						<input
							type="checkbox"
							className="form-check-input"
							checked={f.enabled}
							onChange={(e) => set("enabled", e.target.checked)}
						/>
						<span className="form-check-label">{ti("direct.form.enabled")}</span>
					</label>
				</div>
			</div>
			<Alert variant="info" className="mb-0 small" data-testid="direct-form-portforward">
				{ti("direct.form.portforward", {
					site: a?.wgLinkName ?? ti("direct.form.side-a"),
					port: f.listenPort || "?",
					ip: lanA ?? ti("direct.form.lan-ip-unknown"),
				})}
			</Alert>
			<div className="d-flex gap-2 justify-content-end">
				<button type="button" className="btn" onClick={onDone} disabled={save.isPending}>
					{intl.formatMessage({ id: "cancel" })}
				</button>
				<button
					type="submit"
					className="btn btn-primary"
					disabled={save.isPending}
					data-testid="direct-form-save"
				>
					{intl.formatMessage({ id: "save" })}
				</button>
			</div>
		</form>
	);
}

/** "Direktverbindungen": tunnels between two sites, the hub stays the fallback. */
export function DirectLinksCard() {
	const links = useDirectLinks();
	const agents = useAgents();
	const save = useSaveDirectLink();
	const remove = useDeleteDirectLink();
	const [form, setForm] = useState<{ editId: number | null; initial: DirectLinkInput } | null>(null);
	const [error, setError] = useState<string | null>(null);
	const titleId = useId();

	// older backend without the endpoint: hide the card entirely
	if (links.isError && /not found|404/i.test(links.error?.message ?? "")) return null;

	const list = links.data ?? [];
	const sites = siteAgents(agents.data ?? []);

	const toggle = async (l: DirectLink) => {
		setError(null);
		try {
			await save.mutateAsync({ id: l.id, data: { enabled: !l.enabled } });
		} catch (err) {
			setError(errMessage(err));
		}
	};

	const askDelete = (l: DirectLink) =>
		showDeleteConfirmModal({
			title: ti("direct.delete-title", { name: l.name }),
			confirmLabel: ti("direct.delete-button"),
			onConfirm: async () => {
				setError(null);
				try {
					await remove.mutateAsync(l.id);
				} catch (err) {
					setError(errMessage(err));
				}
			},
			children: <p className="mb-0">{ti("direct.delete-text")}</p>,
		});

	const directCount = list.filter((l) => directLinkState(l) === "direct").length;

	return (
		<section className="card" aria-labelledby={titleId} data-testid="direct-links">
			<div className="card-header d-flex flex-wrap align-items-center gap-2">
				<IconArrowsLeftRight size={20} className="text-secondary" aria-hidden />
				<h2 className="card-title h3 mb-0 me-auto" id={titleId}>
					{ti("direct.title")}
				</h2>
				{list.length > 0 && (
					<span className="small text-secondary" data-testid="direct-links-summary">
						{ti("direct.summary", { direct: directCount, total: list.length })}
					</span>
				)}
				{!form && (
					<button
						type="button"
						className="btn btn-sm"
						onClick={() => setForm({ editId: null, initial: emptyForm(list) })}
						disabled={sites.length < 2}
						data-testid="direct-links-add"
					>
						{ti("direct.add")}
					</button>
				)}
			</div>
			<div className="card-body d-flex flex-column gap-3">
				<p className="text-secondary mb-0">{ti("direct.lead")}</p>
				<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible className="mb-0">
					{error}
				</Alert>
				{links.isError && (
					<Alert variant="warning" className="mb-0">
						{links.error?.message}
					</Alert>
				)}
				{form && (
					<LinkForm
						key={form.editId ?? "new"}
						initial={form.initial}
						editId={form.editId}
						agents={sites}
						onDone={() => setForm(null)}
					/>
				)}
				{links.isLoading ? (
					<div className="small text-secondary">{intl.formatMessage({ id: "loading" })}</div>
				) : list.length === 0 ? (
					!form && (
						<div className="small text-secondary" data-testid="direct-links-empty">
							{ti("direct.empty")}
						</div>
					)
				) : (
					<div className="list-group" data-testid="direct-links-list">
						{list.map((l) => {
							const state = directLinkState(l);
							return (
								<div key={l.id} className="list-group-item" data-testid={`direct-link-${l.id}`}>
									<div className="d-flex flex-wrap align-items-center gap-2">
										<span className="fw-medium text-break">{l.name}</span>
										<span className={`badge ${stateBadge[state]}`} data-testid="direct-link-state">
											{ti(`direct.state.${state}`)}
										</span>
										<span className="small text-secondary font-monospace">{l.iface}</span>
										<div className="ms-auto d-flex gap-1">
											<button
												type="button"
												className="btn btn-sm"
												onClick={() => toggle(l)}
												disabled={save.isPending}
											>
												{ti(l.enabled ? "direct.disable" : "direct.enable")}
											</button>
											<button
												type="button"
												className="btn btn-sm"
												onClick={() => setForm({ editId: l.id, initial: toForm(l) })}
											>
												{ti("direct.edit")}
											</button>
											<button
												type="button"
												className="btn btn-sm btn-ghost-danger"
												onClick={() => askDelete(l)}
												disabled={remove.isPending}
											>
												{ti("direct.delete")}
											</button>
										</div>
									</div>
									<div className="small text-secondary mt-1">
										{ti("direct.route", {
											a: l.agentAName ?? "?",
											b: l.agentBName ?? "?",
											endpoint: `${l.endpointHost}:${l.listenPort}`,
											subnet: l.tunnelSubnet,
										})}
									</div>
									{l.blocked && (
										<div className="small text-danger mt-1">
											{ti(`direct.blocked.${l.blocked}`)}
										</div>
									)}
									{l.enabled && !l.blocked && (
										<div className="mt-1">
											<SideStatus name={l.agentAName} status={l.statusA} />
											<SideStatus name={l.agentBName} status={l.statusB} />
										</div>
									)}
								</div>
							);
						})}
					</div>
				)}
			</div>
		</section>
	);
}
