import { IconAlertTriangle, IconHandStop, IconLock, IconPlugConnected } from "@tabler/icons-react";
import { useQueryClient } from "@tanstack/react-query";
import { type ReactNode, useEffect, useRef, useState } from "react";
import Alert from "react-bootstrap/Alert";
import { useLocation } from "react-router-dom";
import type {
	SiteIsolationManualPair,
	SiteIsolationOverview,
	SiteIsolationPair,
	SiteIsolationPairInput,
	SiteIsolationSite,
	SiteIsolationWarning,
} from "src/api/backend";
import { useSetSiteIsolation, useSiteIsolation } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { showDeleteConfirmModal } from "src/modals";
import { errMessage, ti } from "./utils";

/** Anchor of the card; the per-site banner links here and the card then opens. */
export const SITE_ISOLATION_ANCHOR = "site-isolation";

// ── pure helpers (exported for tests) ─────────────────────────────────────────

/** Order-independent key of a site pair. */
export const sitePairKey = (a: string, b: string) => (a < b ? `${a}|${b}` : `${b}|${a}`);

/** Stored pairs whose two links are both current sites (the only ones the backend accepts on PUT). */
export const currentSitePairs = (data: Pick<SiteIsolationOverview, "sites" | "pairs">): SiteIsolationPair[] => {
	const ids = new Set(data.sites.map((s) => s.linkId));
	return data.pairs.filter((p) => ids.has(p.linkA) && ids.has(p.linkB));
};

/** Keys of all blocked pairs among the current sites. */
export const blockedSitePairKeys = (data: Pick<SiteIsolationOverview, "sites" | "pairs">): Set<string> =>
	new Set(currentSitePairs(data).map((p) => sitePairKey(p.linkA, p.linkB)));

const keysToPairs = (keys: Iterable<string>): SiteIsolationPairInput[] =>
	[...keys].sort().map((k) => {
		const [linkA, linkB] = k.split("|");
		return { linkA, linkB };
	});

/**
 * The FULL pair set after blocking (block=true) or allowing one pair. Pairs of
 * links that no longer exist are left out — the backend rejects them, and they
 * are not enforced anyway. Normalized (linkA < linkB) and sorted.
 */
export const nextSitePairs = (
	data: Pick<SiteIsolationOverview, "sites" | "pairs">,
	a: string,
	b: string,
	block: boolean,
): SiteIsolationPairInput[] => {
	const keys = blockedSitePairKeys(data);
	const key = sitePairKey(a, b);
	if (block) keys.add(key);
	else keys.delete(key);
	return keysToPairs(keys);
};

/** Current pairs plus the pairs that manual hub rules separate (to take them over into FloppyGuard). */
export const adoptManualPairs = (
	data: Pick<SiteIsolationOverview, "sites" | "pairs" | "manualPairs">,
): SiteIsolationPairInput[] => {
	const ids = new Set(data.sites.map((s) => s.linkId));
	const keys = blockedSitePairKeys(data);
	for (const m of data.manualPairs ?? []) {
		if (ids.has(m.linkA) && ids.has(m.linkB)) keys.add(sitePairKey(m.linkA, m.linkB));
	}
	return keysToPairs(keys);
};

/** Manual pairs not (yet) stored in FloppyGuard. */
export const unadoptedManualPairs = (
	data: Pick<SiteIsolationOverview, "sites" | "pairs" | "manualPairs">,
): SiteIsolationManualPair[] => {
	const ids = new Set(data.sites.map((s) => s.linkId));
	const stored = blockedSitePairKeys(data);
	return (data.manualPairs ?? []).filter(
		(m) => ids.has(m.linkA) && ids.has(m.linkB) && !stored.has(sitePairKey(m.linkA, m.linkB)),
	);
};

/** Names of the sites the given link is isolated from (for the per-site banner). */
export const isolatedSiteNames = (
	data: Pick<SiteIsolationOverview, "sites" | "pairs"> | undefined,
	linkId: string | null | undefined,
): string[] => {
	if (!data || !linkId) return [];
	const nameOf = (id: string) => data.sites.find((s) => s.linkId === id)?.name ?? id;
	return currentSitePairs(data)
		.filter((p) => p.linkA === linkId || p.linkB === linkId)
		.map((p) => nameOf(p.linkA === linkId ? p.linkB : p.linkA))
		.sort((x, y) => x.localeCompare(y));
};

/**
 * Link id of a site, found by the agent's WireGuard link name (or id): first
 * among the current sites, then among the stored pairs' names. null = unknown.
 */
export const siteLinkIdForName = (
	data: Pick<SiteIsolationOverview, "sites" | "pairs"> | undefined,
	linkName: string | null | undefined,
): string | null => {
	const name = linkName?.trim();
	if (!data || !name) return null;
	const site = data.sites.find((s) => s.name === name || s.linkId === name);
	if (site) return site.linkId;
	for (const p of data.pairs) {
		if (p.nameA === name) return p.linkA;
		if (p.nameB === name) return p.linkB;
	}
	return null;
};

/**
 * Sites the given site is separated from at the hub: by its link id when known
 * (catalog), else by the agent's link name.
 */
export const isolatedSiteNamesFor = (
	data: Pick<SiteIsolationOverview, "sites" | "pairs"> | undefined,
	linkId: string | null | undefined,
	linkName?: string | null,
): string[] => isolatedSiteNames(data, linkId || siteLinkIdForName(data, linkName));

/** localStorage key of the user's collapse choice for the card (per browser only). */
export const SITE_ISOLATION_COLLAPSED_KEY = "floppyguard.site-isolation.collapsed";

const readCollapsed = (): boolean => {
	try {
		return window.localStorage.getItem(SITE_ISOLATION_COLLAPSED_KEY) === "1";
	} catch {
		return false;
	}
};

const writeCollapsed = (collapsed: boolean) => {
	try {
		if (collapsed) window.localStorage.setItem(SITE_ISOLATION_COLLAPSED_KEY, "1");
		else window.localStorage.removeItem(SITE_ISOLATION_COLLAPSED_KEY);
	} catch {
		// storage unavailable (private mode): the choice simply is not remembered
	}
};

/** Every pair of distinct sites once, in site order (rows of the narrow list). */
export const allSitePairs = (sites: SiteIsolationSite[]): Array<[SiteIsolationSite, SiteIsolationSite]> => {
	const out: Array<[SiteIsolationSite, SiteIsolationSite]> = [];
	for (let i = 0; i < sites.length; i++) {
		for (let j = i + 1; j < sites.length; j++) out.push([sites[i], sites[j]]);
	}
	return out;
};

/** Cell state of one site pair. */
export type SitePairState = "open" | "blocked" | "not-enforced" | "manual";

export const sitePairState = (pair: SiteIsolationPair | undefined, manual: boolean): SitePairState => {
	if (pair) return pair.enforced === false ? "not-enforced" : "blocked";
	return manual ? "manual" : "open";
};

/** Something on the card needs attention → it opens even when the user collapsed it before. */
export const siteIsolationNeedsAttention = (
	data: Pick<SiteIsolationOverview, "sites" | "pairs" | "applied" | "warnings" | "manualPairs">,
) =>
	Boolean(data.applied.error) ||
	data.warnings.length > 0 ||
	(data.manualPairs?.length ?? 0) > 0 ||
	currentSitePairs(data).some((p) => p.enforced === false);

const formatTime = (unix: number) =>
	intl.formatDate(new Date(unix * 1000), { dateStyle: "medium", timeStyle: "short" });

/** A warning in the user's language; codes without a translation keep the backend text. */
export const siteIsolationWarningText = (
	w: SiteIsolationWarning,
	data: Pick<SiteIsolationOverview, "sites" | "pairs">,
) => {
	const nameOf = (id?: string) => {
		if (!id) return "?";
		const site = data.sites.find((s) => s.linkId === id);
		if (site) return site.name;
		const pair = data.pairs.find((p) => p.linkA === id || p.linkB === id);
		return (pair?.linkA === id ? pair?.nameA : pair?.nameB) ?? id;
	};
	const networks = (w.networks ?? []).join(", ");
	switch (w.code) {
		case "route-dropped":
			return ti("sites.warning.route-dropped", {
				agent: w.agentName ?? "?",
				site: w.otherName ?? nameOf(w.otherLinkId),
				networks,
			});
		case "no-networks": {
			const other = w.pair ? (w.pair.a === w.linkId ? w.pair.b : w.pair.a) : undefined;
			return ti("sites.warning.no-networks", { site: nameOf(w.linkId), other: nameOf(other) });
		}
		case "overlap":
			return ti("sites.warning.overlap", { a: nameOf(w.pair?.a), b: nameOf(w.pair?.b), networks });
		case "link-missing":
			return ti("sites.warning.link-missing");
		case "link-missing-held":
			return ti("sites.warning.link-missing-held", { site: w.name ?? nameOf(w.linkId) });
		case "link-not-site":
			return ti("sites.warning.link-not-site", { site: w.name ?? nameOf(w.linkId) });
		case "network-skipped": {
			const reason = ["invalid", "default-route", "ipv6-unsupported"].includes(w.reason ?? "")
				? w.reason
				: "invalid";
			return ti(`sites.warning.network-skipped.${reason}`, {
				site: w.name ?? nameOf(w.linkId),
				value: w.value ?? "?",
			});
		}
		case "persist-failed":
			return ti("sites.warning.persist-failed");
		case "boot-include-missing":
			return ti("sites.warning.boot-include-missing");
		case "manual-drop": {
			const chains = [...new Set((w.rules ?? []).map((r) => `${r.family} ${r.table} ${r.chain}`))].join(", ");
			return ti("sites.warning.manual-drop", { chains: chains || "?" });
		}
		default:
			return w.message;
	}
};

// ── components ────────────────────────────────────────────────────────────────

/** Apply status in the card header: a dot + "aktiv" (time in the tooltip), or the error. */
function AppliedStatus({ data, pending }: { data: SiteIsolationOverview; pending: boolean }) {
	if (pending) {
		return (
			<span
				className="small text-secondary d-inline-flex align-items-center gap-2"
				data-testid="site-isolation-status"
			>
				<span className="spinner-border spinner-border-sm" aria-hidden />
				{ti("sites.applying")}
			</span>
		);
	}
	const { applied } = data;
	if (applied.error) {
		return (
			<span className="badge bg-red-lt text-red" data-testid="site-isolation-status" data-state="error">
				{ti("sites.applied-error-short")}
			</span>
		);
	}
	if (applied.at) {
		const when = ti("sites.applied-at", { time: formatTime(applied.at) });
		return (
			<span
				className="small text-secondary d-inline-flex align-items-center gap-2"
				data-testid="site-isolation-status"
				data-state="applied"
				title={when}
			>
				<span className="status-dot status-green" aria-hidden />
				{ti("sites.active")}
				<span className="visually-hidden">({when})</span>
			</span>
		);
	}
	return (
		<span className="small text-secondary" data-testid="site-isolation-status" data-state="none">
			{ti("sites.applied-never")}
		</span>
	);
}

/** Packets the hub dropped for a blocked pair ("1.234 Pakete verworfen"). */
const droppedText = (pair: SiteIsolationPair | undefined) =>
	pair?.dropped
		? ti("sites.dropped", { count: pair.dropped.packets, packets: intl.formatNumber(pair.dropped.packets) })
		: null;

const STATE_CLASS: Record<SitePairState, string> = {
	open: "bg-secondary-lt text-secondary",
	blocked: "bg-red-lt text-red",
	"not-enforced": "bg-yellow-lt site-isolation-cell-warn",
	manual: "bg-orange-lt text-orange",
};

const STATE_ICON: Record<SitePairState, ReactNode> = {
	open: <IconPlugConnected size={14} className="me-1 flex-shrink-0" aria-hidden />,
	blocked: <IconLock size={14} className="me-1 flex-shrink-0" aria-hidden />,
	"not-enforced": <IconAlertTriangle size={14} className="me-1 flex-shrink-0" aria-hidden />,
	manual: <IconHandStop size={14} className="me-1 flex-shrink-0" aria-hidden />,
};

interface CellProps {
	a: SiteIsolationSite;
	b: SiteIsolationSite;
	pair: SiteIsolationPair | undefined;
	manual: boolean;
	disabled: boolean;
	onToggle: (a: SiteIsolationSite, b: SiteIsolationSite) => void;
}

function MatrixCell({ a, b, pair, manual, disabled, onToggle }: CellProps) {
	const state = sitePairState(pair, manual);
	const label = ti(`sites.state.${state}`);
	const title = [
		`${a.name} ↔ ${b.name}: ${label}`,
		state === "not-enforced" ? ti("sites.not-enforced") : null,
		pair && manual ? ti("sites.also-manual") : null,
		droppedText(pair),
		ti(pair ? "sites.action.allow" : "sites.action.block"),
	]
		.filter(Boolean)
		.join(" · ");
	return (
		<button
			type="button"
			className={`btn btn-sm w-100 border-0 site-isolation-cell ${STATE_CLASS[state]}`}
			title={title}
			aria-label={title}
			disabled={disabled}
			onClick={() => onToggle(a, b)}
			data-testid="site-isolation-cell"
			data-a={a.linkId}
			data-b={b.linkId}
			data-state={state}
		>
			{STATE_ICON[state]}
			{label}
		</button>
	);
}

function SiteName({ site }: { site: SiteIsolationSite }) {
	return (
		<span className="d-inline-flex align-items-center gap-2" style={{ minWidth: 0 }}>
			<span
				className={`status-dot flex-shrink-0 ${site.online ? "status-green" : "status-secondary"}`}
				title={ti(site.online ? "sites.online" : "sites.offline")}
				aria-hidden
			/>
			<span className="text-break">{site.name}</span>
			{!site.online && <span className="visually-hidden">({ti("sites.offline")})</span>}
		</span>
	);
}

/** Networks of a site for the confirm dialog: imported networks + tunnel addresses. */
function SiteNets({ site }: { site: SiteIsolationSite }) {
	const nets = [...site.networks, ...site.tunnel];
	return (
		<div className="text-start" style={{ minWidth: 0 }}>
			<div className="fw-medium text-break">{site.name}</div>
			{nets.length ? (
				<ul className="list-unstyled mb-0 small font-monospace">
					{nets.map((n) => (
						<li key={n}>{n}</li>
					))}
				</ul>
			) : (
				<div className="small text-secondary">{ti("sites.confirm-no-networks")}</div>
			)}
		</div>
	);
}

/**
 * "Trennung zwischen Standorten (am Hub)": which sites may reach each other
 * through the hub. Separation happens on the hub (own nft table), independent
 * of the per-site ingress filter. Expanded by default; a collapse is remembered
 * in this browser (attention still opens it); upper
 * triangle of the matrix on wide screens (each pair once), a list of pairs with
 * switches on narrow ones.
 */
export function SiteIsolationCard() {
	const query = useSiteIsolation();
	const save = useSetSiteIsolation();
	const queryClient = useQueryClient();
	const location = useLocation();
	const [error, setError] = useState<string | null>(null);
	// null = no choice in this view yet (expanded, unless collapsed before and calm), else the user's choice
	const [open, setOpen] = useState<boolean | null>(null);
	const [storedCollapsed] = useState(readCollapsed);
	const ref = useRef<HTMLElement>(null);
	const titleId = "site-isolation-title";
	const bodyId = "site-isolation-body";

	// the per-site banner links to #site-isolation: open the card and bring it into
	// view — on every navigation (the whole location), also a repeated click
	useEffect(() => {
		if (location.hash === `#${SITE_ISOLATION_ANCHOR}`) {
			setOpen(true);
			ref.current?.scrollIntoView?.({ behavior: "smooth", block: "start" });
		}
	}, [location]);

	const header = (extra?: ReactNode) => (
		<div className="card-header d-flex flex-wrap align-items-center gap-2">
			<h2 className="card-title h3 mb-0" id={titleId}>
				{ti("sites.title")}
			</h2>
			{extra}
		</div>
	);

	if (query.isLoading) {
		return (
			<section
				className="card"
				aria-labelledby={titleId}
				data-testid="site-isolation"
				id={SITE_ISOLATION_ANCHOR}
				ref={ref}
			>
				{header(<span className="small text-secondary">{intl.formatMessage({ id: "loading" })}</span>)}
			</section>
		);
	}
	if (query.isError || !query.data) {
		return (
			<section
				className="card"
				aria-labelledby={titleId}
				data-testid="site-isolation"
				id={SITE_ISOLATION_ANCHOR}
				ref={ref}
			>
				{header()}
				<div className="card-body small text-secondary" data-testid="site-isolation-unavailable">
					{ti("sites.unavailable", { error: query.error?.message ?? "" })}
				</div>
			</section>
		);
	}

	const data = query.data;
	// the overview as of now (a refetch may have landed while a dialog was open)
	const latest = () => queryClient.getQueryData<SiteIsolationOverview>(["site-isolation"]) ?? data;
	const sites = data.sites;
	const pairByKey = new Map(currentSitePairs(data).map((p) => [sitePairKey(p.linkA, p.linkB), p]));
	const manualKeys = new Set((data.manualPairs ?? []).map((m) => sitePairKey(m.linkA, m.linkB)));
	const pairOf = (a: SiteIsolationSite, b: SiteIsolationSite) => pairByKey.get(sitePairKey(a.linkId, b.linkId));
	const isManual = (a: SiteIsolationSite, b: SiteIsolationSite) => manualKeys.has(sitePairKey(a.linkId, b.linkId));
	const pairs = allSitePairs(sites);
	const busy = save.isPending;
	const expanded = open ?? (!storedCollapsed || siteIsolationNeedsAttention(data));
	const toAdopt = unadoptedManualPairs(data);
	const hasStale = data.pairs.length > currentSitePairs(data).length;

	// the PUT replaces the full pair set: resolve it on confirm, not when the
	// dialog opens, so a change that arrived meanwhile is not overwritten
	const submit = (next: () => SiteIsolationPairInput[]) => async () => {
		setError(null);
		try {
			await save.mutateAsync(next());
		} catch (err) {
			// shown in the card (the dialog closes either way)
			setError(errMessage(err));
		}
	};

	const toggle = (a: SiteIsolationSite, b: SiteIsolationSite) => {
		if (busy) return;
		const block = !pairOf(a, b);
		showDeleteConfirmModal({
			title: ti(block ? "sites.confirm-block-title" : "sites.confirm-allow-title", { a: a.name, b: b.name }),
			confirmLabel: ti(block ? "sites.confirm-block-button" : "sites.confirm-allow-button"),
			onConfirm: submit(() => nextSitePairs(latest(), a.linkId, b.linkId, block)),
			children: block ? (
				<div data-testid="site-isolation-confirm">
					<p>{ti("sites.confirm-block", { a: a.name, b: b.name })}</p>
					<div className="fw-medium mb-2">{ti("sites.confirm-affected")}</div>
					<div className="d-flex gap-3 justify-content-center align-items-start">
						<SiteNets site={a} />
						<span className="fs-3 text-secondary" aria-hidden>
							↔
						</span>
						<SiteNets site={b} />
					</div>
					<p className="small text-secondary mt-3 mb-0">{ti("sites.clients-unaffected")}</p>
				</div>
			) : (
				<div data-testid="site-isolation-confirm">
					<p className="mb-0">{ti("sites.confirm-allow", { a: a.name, b: b.name })}</p>
					{isManual(a, b) && <p className="text-orange mt-2 mb-0">{ti("sites.confirm-allow-manual")}</p>}
				</div>
			),
		});
	};

	const adopt = () => {
		if (busy) return;
		showDeleteConfirmModal({
			title: ti("sites.adopt-title"),
			confirmLabel: ti("sites.adopt-button"),
			onConfirm: submit(() => adoptManualPairs(latest())),
			children: <p className="mb-0">{ti("sites.adopt-text")}</p>,
		});
	};

	const summary =
		pairs.length > 0
			? ti("sites.summary", { blocked: pairByKey.size, total: pairs.length })
			: ti("sites.too-few-short");

	return (
		<section
			className="card"
			aria-labelledby={titleId}
			data-testid="site-isolation"
			data-expanded={expanded}
			id={SITE_ISOLATION_ANCHOR}
			ref={ref}
		>
			{header(
				<>
					<span className="small text-secondary me-auto" data-testid="site-isolation-summary">
						{summary}
					</span>
					<AppliedStatus data={data} pending={busy} />
					<button
						type="button"
						className="btn btn-sm"
						aria-expanded={expanded}
						aria-controls={bodyId}
						onClick={() => {
							writeCollapsed(expanded);
							setOpen(!expanded);
						}}
						data-testid="site-isolation-toggle"
					>
						{ti(expanded ? "sites.collapse" : "sites.edit")}
					</button>
				</>,
			)}
			{expanded && (
				<div className="card-body d-flex flex-column gap-3" id={bodyId}>
					<div>
						<p className="text-secondary mb-1">{ti("sites.lead")}</p>
						{data.lastChange?.at && (
							<div className="small text-secondary" data-testid="site-isolation-last-change">
								{data.lastChange.by
									? ti("sites.last-change-by", {
											time: formatTime(data.lastChange.at),
											user: data.lastChange.by,
										})
									: ti("sites.last-change", { time: formatTime(data.lastChange.at) })}
							</div>
						)}
					</div>

					<Alert variant="danger" show={!!error} onClose={() => setError(null)} dismissible className="mb-0">
						{error}
					</Alert>

					{data.applied.error && (
						<Alert
							variant="danger"
							className="d-block py-2 px-3 small mb-0"
							data-testid="site-isolation-error"
						>
							<div className="fw-medium">
								{ti("sites.applied-error", {
									time: data.applied.errorAt ? formatTime(data.applied.errorAt) : "–",
								})}
							</div>
							{data.applied.errorCode === "links-unresolved" ? (
								<div className="mt-1">{ti("sites.error.links-unresolved")}</div>
							) : (
								<div className="font-monospace text-break mt-1">{data.applied.error}</div>
							)}
						</Alert>
					)}

					{sites.length < 2 ? (
						<div className="text-secondary small" data-testid="site-isolation-too-few">
							{ti("sites.too-few")}
						</div>
					) : (
						<>
							<div className="table-responsive d-none d-md-block">
								<table
									className="table table-sm table-borderless mb-0 site-isolation-matrix"
									data-testid="site-isolation-matrix"
								>
									<caption className="visually-hidden">{ti("sites.matrix-caption")}</caption>
									<thead>
										<tr>
											<td />
											{sites.slice(1).map((s) => (
												<th
													key={s.linkId}
													scope="col"
													className="text-center small fw-medium text-body align-bottom"
												>
													{s.name}
												</th>
											))}
										</tr>
									</thead>
									<tbody>
										{sites.slice(0, -1).map((row, i) => (
											<tr key={row.linkId}>
												<th scope="row" className="small fw-medium text-body align-middle">
													<SiteName site={row} />
												</th>
												{sites.slice(1).map((col, j) => (
													<td key={col.linkId} className="text-center align-middle p-1">
														{j + 1 > i ? (
															<MatrixCell
																a={row}
																b={col}
																pair={pairOf(row, col)}
																manual={isManual(row, col)}
																disabled={busy}
																onToggle={toggle}
															/>
														) : (
															<span
																className="site-isolation-diag"
																data-testid="site-isolation-diag"
																aria-hidden
															/>
														)}
													</td>
												))}
											</tr>
										))}
									</tbody>
								</table>
							</div>

							<ul className="list-group list-group-flush d-md-none" data-testid="site-isolation-list">
								{pairs.map(([a, b]) => {
									const pair = pairOf(a, b);
									const blocked = !!pair;
									const state = sitePairState(pair, isManual(a, b));
									const switchId = `site-isolation-switch-${sitePairKey(a.linkId, b.linkId).replace(/[^A-Za-z0-9_-]/g, "_")}`;
									return (
										<li
											key={sitePairKey(a.linkId, b.linkId)}
											className="list-group-item px-0 d-flex align-items-center gap-3"
											data-testid="site-isolation-row"
											data-state={state}
										>
											<label
												className="flex-fill mb-0"
												htmlFor={switchId}
												style={{ minWidth: 0 }}
											>
												<span className="d-block fw-medium text-break">
													{a.name} ↔ {b.name}
												</span>
												<span
													className={`d-flex flex-wrap align-items-center gap-1 small ${
														state === "blocked"
															? "text-red"
															: state === "not-enforced"
																? "site-isolation-cell-warn"
																: state === "manual"
																	? "text-orange"
																	: "text-secondary"
													}`}
												>
													{STATE_ICON[state]}
													{ti(`sites.state.${state}`)}
													{droppedText(pair) && (
														<span className="text-secondary">· {droppedText(pair)}</span>
													)}
												</span>
											</label>
											<div className="form-check form-switch m-0 flex-shrink-0">
												<input
													id={switchId}
													type="checkbox"
													role="switch"
													className="form-check-input"
													checked={!blocked}
													aria-checked={!blocked}
													disabled={busy}
													onChange={() => toggle(a, b)}
													data-testid="site-isolation-switch"
												/>
											</div>
										</li>
									);
								})}
							</ul>
							<div className="small text-secondary d-md-none">{ti("sites.switch-hint")}</div>
						</>
					)}

					{data.warnings.length > 0 && (
						<Alert
							variant="warning"
							className="d-block py-2 px-3 small mb-0"
							data-testid="site-isolation-warnings"
						>
							<div className="fw-medium mb-1">
								{ti("sites.warnings-title", { count: data.warnings.length })}
							</div>
							<ul className="mb-0 ps-3">
								{data.warnings.map((w) => (
									// no id: code + text identify a warning (the backend emits each once)
									<li key={`${w.code}:${w.message}`} data-code={w.code}>
										{siteIsolationWarningText(w, data)}
										{w.code === "manual-drop" && toAdopt.length > 0 && (
											<div className="mt-1">
												<button
													type="button"
													className="btn btn-sm"
													onClick={adopt}
													disabled={busy}
													data-testid="site-isolation-adopt"
												>
													{ti("sites.adopt-button")}
												</button>
											</div>
										)}
										{w.code === "link-missing" && hasStale && (
											<div className="mt-1">
												<button
													type="button"
													className="btn btn-sm"
													onClick={submit(() => keysToPairs(blockedSitePairKeys(data)))}
													disabled={busy}
													data-testid="site-isolation-cleanup"
												>
													{ti("sites.cleanup-button")}
												</button>
											</div>
										)}
									</li>
								))}
							</ul>
						</Alert>
					)}
				</div>
			)}
		</section>
	);
}
