import { IconAlertTriangle, IconRefresh, IconSearch, IconWorld, IconWorldCheck, IconX } from "@tabler/icons-react";
import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import { Alert } from "react-bootstrap";
import type { GeoFilterStatus } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useGeoFilter, useRefreshGeoFilter, useUpdateGeoFilter } from "src/hooks";
import { intl, T } from "src/locale";
import { showObjectSuccess } from "src/notifications";
import CountryFlag from "./geo/CountryFlag";
import { countryName, norm, sameList } from "./geo/countries";

// Karte (Umrisse ~100 kB) erst laden, wenn die Übersicht offen ist
const WorldMap = lazy(() => import("./geo/WorldMap"));

const t = (id: string, values?: Record<string, string | number>) => intl.formatMessage({ id }, values);
const QUICK = ["CH", "NO", "IS", "LI", "GB", "AD", "MC", "SM", "VA", "AL", "BA", "ME", "MK", "RS", "MD", "UA", "TR"];
const formatDate = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "–");
const formatDay = (day: string) => {
	const [y, m, d] = day.split("-").map(Number);
	return new Date(y, m - 1, d).toLocaleDateString(undefined, { day: "2-digit", month: "2-digit" });
};

type Tab = "overview" | "countries" | "hosts";

export default function GeoFilter() {
	const { data, isLoading, error } = useGeoFilter();
	const [tab, setTab] = useState<Tab>("overview");

	if (isLoading) {
		return (
			<div className="card-body">
				<Loading noLogo />
			</div>
		);
	}
	if (error || !data) {
		return (
			<div className="card-body">
				<Alert variant="danger">{error?.message || "Unknown error"}</Alert>
			</div>
		);
	}

	const state = data.fallback
		? { cls: "bg-red-lt", id: "settings.geo-filter.state.fallback" }
		: data.lastError
			? { cls: "bg-yellow-lt", id: "settings.geo-filter.state.warning" }
			: data.hosts.length
				? { cls: "bg-green-lt", id: "settings.geo-filter.state.active" }
				: { cls: "bg-secondary-lt", id: "settings.geo-filter.state.unused" };

	const tabs: { id: Tab; label: string; badge?: number }[] = [
		{ id: "overview", label: "settings.geo-filter.tab.overview" },
		{ id: "countries", label: "settings.geo-filter.tab.countries", badge: data.countries.length },
		{ id: "hosts", label: "settings.geo-filter.tab.hosts", badge: data.hosts.length },
	];

	return (
		<div className="d-flex flex-column flex-fill">
			<div className="card-body pb-0">
				<div className="d-flex align-items-start justify-content-between gap-3 flex-wrap">
					<div>
						<span className="platform-kicker">
							<IconWorldCheck size={14} />
							<T id="settings.geo-filter.kicker" />
						</span>
						<h3 className="card-title mt-2 mb-1">
							<T id="settings.geo-filter" />
						</h3>
						<div className="text-secondary" style={{ maxWidth: "62ch" }}>
							<T id="settings.geo-filter.description" />
						</div>
					</div>
					<span className={`badge ${state.cls}`}>
						<T id={state.id} />
					</span>
				</div>

				{data.fallback ? (
					<Alert variant="danger" className="d-flex gap-2 mt-3 mb-0">
						<IconAlertTriangle size={20} className="flex-shrink-0" />
						<T id="settings.geo-filter.fallback" />
					</Alert>
				) : null}
				{data.lastError ? (
					<Alert variant="warning" className="d-flex gap-2 mt-3 mb-0">
						<IconAlertTriangle size={20} className="flex-shrink-0" />
						<span>{t("settings.geo-filter.last-error", { error: data.lastError })}</span>
					</Alert>
				) : null}

				<ul className="nav nav-tabs mt-4">
					{tabs.map((x) => (
						<li key={x.id} className="nav-item">
							<button
								type="button"
								aria-pressed={tab === x.id}
								className={`nav-link ${tab === x.id ? "active" : ""}`}
								onClick={() => setTab(x.id)}
							>
								<T id={x.label} />
								{x.badge !== undefined ? (
									<span className="badge bg-secondary-lt ms-2">{x.badge}</span>
								) : null}
							</button>
						</li>
					))}
				</ul>
			</div>

			{tab === "overview" ? <Overview data={data} /> : null}
			{tab === "countries" ? <Countries data={data} /> : null}
			{tab === "hosts" ? <Hosts data={data} /> : null}
		</div>
	);
}

/* ── Übersicht: Karte + Kennzahlen der letzten 30 Tage ──────────────────── */
function Overview({ data }: { data: GeoFilterStatus }) {
	const s = data.stats;
	const counts = useMemo(() => Object.fromEntries(s.countries.map((c) => [c.code, c.count])), [s]);
	const [showAll, setShowAll] = useState(false);
	const top = showAll ? s.countries : s.countries.slice(0, 8);
	const topMax = Math.max(1, ...s.countries.map((c) => c.count));
	const dayMax = Math.max(1, ...s.perDay.map((d) => d.count));
	const today = s.perDay[s.perDay.length - 1]?.count || 0;

	return (
		<div className="card-body">
			<div className="row row-cards mb-3">
				{[
					{ id: "settings.geo-filter.kpi.blocked", value: s.total.toLocaleString() },
					{ id: "settings.geo-filter.kpi.today", value: today.toLocaleString() },
					{
						id: "settings.geo-filter.kpi.countries",
						value: s.countries.filter((c) => c.code !== "ZZ").length,
					},
					{ id: "settings.geo-filter.kpi.hosts", value: data.hosts.length },
				].map((k) => (
					<div key={k.id} className="col-6 col-lg-3">
						<div className="card card-sm h-100 platform-stat-card">
							<div className="card-body">
								<div className="text-secondary small">
									<T id={k.id} />
								</div>
								<div className="platform-stat-value">{k.value}</div>
							</div>
						</div>
					</div>
				))}
			</div>

			<div className="card platform-elevated-card mb-3">
				<div className="card-header">
					<h4 className="card-title mb-0">
						<T id="settings.geo-filter.map.title" />
					</h4>
					<span className="ms-auto text-secondary small">
						{t("settings.geo-filter.map.days", { days: s.days })}
					</span>
				</div>
				<div className="card-body">
					{s.total ? (
						<Suspense fallback={<Loading noLogo />}>
							<WorldMap counts={counts} allowed={data.activeCountries} total={s.total} />
						</Suspense>
					) : (
						<div className="geo-empty">
							<IconWorld size={40} className="text-secondary mb-2" />
							<div className="fw-semibold">
								<T id="settings.geo-filter.map.empty" />
							</div>
							<div className="text-secondary small">
								<T id="settings.geo-filter.map.empty.hint" />
							</div>
						</div>
					)}
				</div>
			</div>

			{s.total ? (
				<div className="row row-cards">
					<div className="col-lg-6">
						<div className="card platform-elevated-card h-100">
							<div className="card-header">
								<h4 className="card-title mb-0">
									<T id="settings.geo-filter.top.countries" />
								</h4>
							</div>
							<div className="card-body">
								{top.map((c) => (
									<div key={c.code} className="geo-bar-row">
										<CountryFlag code={c.code} />
										<span className="geo-bar-label text-truncate">{countryName(c.code)}</span>
										<span className="geo-bar-track">
											<span
												className="geo-bar-fill"
												style={{ width: `${(c.count / topMax) * 100}%` }}
											/>
										</span>
										<span className="geo-bar-value">{c.count.toLocaleString()}</span>
									</div>
								))}
								{s.countries.length > 8 ? (
									<button
										type="button"
										className="btn btn-link btn-sm px-0 mt-2"
										onClick={() => setShowAll((v) => !v)}
									>
										{showAll
											? t("settings.geo-filter.top.less")
											: t("settings.geo-filter.top.all", { count: s.countries.length })}
									</button>
								) : null}
							</div>
						</div>
					</div>
					<div className="col-lg-6">
						<div className="card platform-elevated-card h-100">
							<div className="card-header">
								<h4 className="card-title mb-0">
									<T id="settings.geo-filter.top.days" />
								</h4>
							</div>
							<div className="card-body d-flex flex-column">
								<div className="geo-days" role="img" aria-label={t("settings.geo-filter.top.days")}>
									{s.perDay.map((d) => (
										<span
											key={d.day}
											className="geo-day"
											title={`${formatDay(d.day)}: ${d.count.toLocaleString()}`}
										>
											<span
												className="geo-day-bar"
												style={{
													height: d.count ? `${Math.max(4, (d.count / dayMax) * 100)}%` : 0,
												}}
											/>
										</span>
									))}
								</div>
								<div className="d-flex justify-content-between text-secondary small mt-1">
									<span>{formatDay(s.perDay[0]?.day || "")}</span>
									<span>
										{t("settings.geo-filter.top.days.max", { max: dayMax.toLocaleString() })}
									</span>
									<span>
										<T id="settings.geo-filter.today" />
									</span>
								</div>
							</div>
						</div>
					</div>
					<div className="col-lg-6">
						<div className="card platform-elevated-card h-100">
							<div className="card-header">
								<h4 className="card-title mb-0">
									<T id="settings.geo-filter.top.ips" />
								</h4>
							</div>
							<div className="table-responsive">
								<table className="table table-vcenter card-table mb-0">
									<tbody>
										{s.topIps.map((x) => (
											<tr key={x.ip}>
												<td className="font-monospace small">{x.ip}</td>
												<td className="small">
													<span className="d-inline-flex align-items-center gap-2">
														<CountryFlag code={x.code} size={16} />
														{countryName(x.code)}
													</span>
												</td>
												<td className="text-end fw-semibold">{x.count.toLocaleString()}</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						</div>
					</div>
					<div className="col-lg-6">
						<div className="card platform-elevated-card h-100">
							<div className="card-header">
								<h4 className="card-title mb-0">
									<T id="settings.geo-filter.top.hosts" />
								</h4>
							</div>
							<div className="table-responsive">
								<table className="table table-vcenter card-table mb-0">
									<tbody>
										{s.hosts.map((x) => (
											<tr key={x.host}>
												<td className="small text-truncate">{x.host}</td>
												<td className="text-end fw-semibold">{x.count.toLocaleString()}</td>
											</tr>
										))}
									</tbody>
								</table>
							</div>
						</div>
					</div>
				</div>
			) : null}
		</div>
	);
}

/* ── Länder: Auswahl + Stand der Liste ──────────────────────────────────── */
function Countries({ data }: { data: GeoFilterStatus }) {
	const save = useUpdateGeoFilter();
	const refresh = useRefreshGeoFilter();
	const [selected, setSelected] = useState<string[]>(norm(data.countries));
	const [query, setQuery] = useState("");

	useEffect(() => setSelected(norm(data.countries)), [data.countries]);

	const eu = useMemo(() => norm(data.euCountries), [data.euCountries]);
	const presets = [
		{ id: "eu", list: eu },
		{ id: "eu-ch", list: [...eu, "CH"] },
		{ id: "europe-west", list: [...eu, "CH", "NO", "IS", "LI", "GB"] },
		{ id: "dach", list: ["AT", "CH", "DE"] },
	];
	const matches = useMemo(() => {
		const q = query.trim().toLowerCase();
		if (!q) return [];
		return data.allCountries
			.filter((c) => !selected.includes(c))
			.filter((c) => c.toLowerCase() === q || countryName(c).toLowerCase().includes(q))
			.slice(0, 8);
	}, [query, data.allCountries, selected]);

	const dirty = !sameList(selected, data.countries);
	const added = selected.filter((c) => !data.countries.includes(c));
	const removed = data.countries.filter((c) => !selected.includes(c));
	const add = (c: string) => {
		setSelected((p) => norm([...p, c]));
		setQuery("");
	};
	const remove = (c: string) => setSelected((p) => p.filter((x) => x !== c));

	return (
		<>
			<div className="card-body">
				{save.error ? (
					<Alert variant="danger" dismissible onClose={() => save.reset()}>
						{save.error.message}
					</Alert>
				) : null}

				<div className="form-label">
					<T id="settings.geo-filter.presets" />
				</div>
				<div className="geo-presets mb-4">
					{presets.map((p) => {
						const active = sameList(selected, p.list);
						return (
							<button
								key={p.id}
								type="button"
								className={`geo-preset ${active ? "active" : ""}`}
								onClick={() => setSelected(norm(p.list))}
								aria-pressed={active}
							>
								<span className="geo-preset-title">
									<T id={`settings.geo-filter.preset.${p.id}`} />
								</span>
								<span className="geo-preset-meta">
									{t("settings.geo-filter.countries-n", { count: norm(p.list).length })}
								</span>
							</button>
						);
					})}
				</div>

				<div className="d-flex align-items-baseline justify-content-between">
					<div className="form-label">
						<T id="settings.geo-filter.allowed" />
					</div>
					<span className="text-secondary small">
						{t("settings.geo-filter.selected-count", { count: selected.length })}
					</span>
				</div>
				<div className="geo-chips mb-3">
					{selected.length ? (
						selected.map((c) => (
							<span key={c} className={`geo-chip ${added.includes(c) ? "is-new" : ""}`}>
								<CountryFlag code={c} size={16} />
								{countryName(c)}
								<span className="geo-chip-code">{c}</span>
								<button
									type="button"
									className="geo-chip-remove"
									onClick={() => remove(c)}
									aria-label={t("settings.geo-filter.remove", { country: countryName(c) })}
								>
									<IconX size={12} />
								</button>
							</span>
						))
					) : (
						<span className="text-danger small">
							<T id="settings.geo-filter.none-selected" />
						</span>
					)}
				</div>

				<div className="position-relative mb-3" style={{ maxWidth: 440 }}>
					<div className="input-icon">
						<span className="input-icon-addon">
							<IconSearch size={16} />
						</span>
						<input
							type="text"
							className="form-control"
							autoComplete="off"
							spellCheck={false}
							placeholder={t("settings.geo-filter.search")}
							value={query}
							onChange={(e) => setQuery(e.target.value)}
							onKeyDown={(e) => {
								if (e.key === "Enter" && matches.length) {
									e.preventDefault();
									add(matches[0]);
								}
								if (e.key === "Escape") setQuery("");
							}}
						/>
					</div>
					{matches.length ? (
						<div className="dropdown-menu show w-100 geo-search-menu">
							{matches.map((c) => (
								<button key={c} type="button" className="dropdown-item gap-2" onClick={() => add(c)}>
									<CountryFlag code={c} size={16} />
									{countryName(c)}
									<span className="ms-auto text-secondary small">{c}</span>
								</button>
							))}
						</div>
					) : query.trim() ? (
						<div className="form-hint">
							<T id="settings.geo-filter.search.none" />
						</div>
					) : null}
				</div>

				<div className="text-secondary small mb-1">
					<T id="settings.geo-filter.quick" />
				</div>
				<div className="geo-quick mb-4">
					{QUICK.map((c) => (
						<button
							key={c}
							type="button"
							className={`geo-quick-item ${selected.includes(c) ? "active" : ""}`}
							onClick={() => (selected.includes(c) ? remove(c) : add(c))}
							title={countryName(c)}
						>
							<CountryFlag code={c} size={14} /> {c}
						</button>
					))}
				</div>

				<div className="platform-inline-panel d-flex align-items-center gap-3 flex-wrap">
					<div className="small">
						<div>
							<span className="text-secondary">
								<T id="settings.geo-filter.stat.updated" />:
							</span>{" "}
							<strong>{formatDate(data.updatedAt)}</strong> ·{" "}
							{t("settings.geo-filter.stat.networks-n", { count: data.ranges.toLocaleString() })}
						</div>
						<div className="text-secondary">
							<T id="settings.geo-filter.stat.auto" /> ·{" "}
							<a href="https://db-ip.com" target="_blank" rel="noreferrer">
								IP Geolocation by DB-IP
							</a>{" "}
							(CC BY 4.0)
						</div>
					</div>
					<Button
						type="button"
						size="sm"
						className="ms-auto"
						isLoading={refresh.isPending}
						disabled={refresh.isPending || dirty}
						onClick={() => refresh.mutate()}
					>
						<IconRefresh size={16} className="me-1" />
						<T id="settings.geo-filter.refresh" />
					</Button>
				</div>
				{refresh.error ? (
					<Alert variant="danger" className="py-2 mt-2 mb-0">
						{refresh.error.message}
					</Alert>
				) : null}
			</div>

			{dirty ? (
				<div className="card-footer geo-savebar mt-auto">
					<div className="d-flex align-items-center gap-3 flex-wrap">
						<div className="small">
							<strong>
								<T id="settings.geo-filter.unsaved" />
							</strong>
							{added.length ? <span className="text-green ms-2">+ {added.join(", ")}</span> : null}
							{removed.length ? <span className="text-red ms-2">− {removed.join(", ")}</span> : null}
						</div>
						<div className="btn-list ms-auto">
							<button type="button" className="btn" onClick={() => setSelected(norm(data.countries))}>
								<T id="settings.geo-filter.discard" />
							</button>
							<Button
								type="button"
								actionType="primary"
								isLoading={save.isPending}
								disabled={save.isPending || !selected.length}
								onClick={() =>
									save.mutate(
										{ countries: selected },
										{ onSuccess: () => showObjectSuccess("setting", "saved") },
									)
								}
							>
								<T id="save" />
							</Button>
						</div>
					</div>
				</div>
			) : null}
		</>
	);
}

/* ── Hosts: welche Proxy-Hosts filtern ──────────────────────────────────── */
function Hosts({ data }: { data: GeoFilterStatus }) {
	const byHost = useMemo(
		() => Object.fromEntries(data.stats.hosts.map((h) => [h.host, h.count])),
		[data.stats.hosts],
	);
	return (
		<div className="card-body">
			{data.hosts.length ? (
				<div className="list-group list-group-flush border rounded">
					{data.hosts.map((h) => {
						const blocked = h.domainNames.reduce((n, d) => n + (byHost[d.toLowerCase()] || 0), 0);
						return (
							<div key={h.id} className="list-group-item d-flex align-items-center gap-3">
								<span className="avatar avatar-sm bg-blue-lt">
									<IconWorld size={18} />
								</span>
								<div className="flex-fill text-truncate">
									<div className="fw-semibold text-truncate">{h.domainNames.join(", ")}</div>
									<div className="text-secondary small">
										{t("settings.geo-filter.host.blocked", {
											count: blocked.toLocaleString(),
											days: data.stats.days,
										})}
									</div>
								</div>
								<span className={`badge ${h.enabled ? "bg-green-lt" : "bg-secondary-lt"}`}>
									<T
										id={h.enabled ? "settings.geo-filter.host.on" : "settings.geo-filter.host.off"}
									/>
								</span>
							</div>
						);
					})}
				</div>
			) : (
				<div className="geo-empty">
					<IconWorld size={40} className="text-secondary mb-2" />
					<div className="text-secondary">
						<T id="settings.geo-filter.no-hosts" />
					</div>
				</div>
			)}
			<div className="text-secondary small mt-3">
				<T id="settings.geo-filter.hosts.hint" />
			</div>
		</div>
	);
}
