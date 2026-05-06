import { IconArrowsExchange2, IconRoute2, IconShieldHalfFilled, IconTopologyStar3 } from "@tabler/icons-react";
import type { WireGuardLink } from "src/api/backend";
import { Loading } from "src/components";
import { useWireGuardStatus } from "src/hooks";
import { intl } from "src/locale/IntlProvider";

const KNOWN_WARNINGS = new Set([
	"remote-endpoint-missing",
	"imported-network-missing-live-route",
	"nat-likely-needed",
	"exported-networks-missing",
	"return-path-mode-undefined",
	"remote-management-mode-undefined",
	"link-not-currently-active",
]);
const fmtWarning = (w: string) => (KNOWN_WARNINGS.has(w) ? intl.formatMessage({ id: `wireguard.warning.${w}` }) : w);

const KNOWN_NEXT_ACTIONS = new Set([
	"verify-return-path",
	"model-exported-networks",
	"define-remote-management-mode",
	"fix-return-path",
	"decide-nat-or-static-route",
	"define-return-path-mode",
	"verify-live-tunnel-state",
	"mount-wireguard-config-directory",
]);
const fmtNextAction = (a: string) =>
	KNOWN_NEXT_ACTIONS.has(a) ? intl.formatMessage({ id: `wireguard.next.${a}` }) : a;

const byteFmt = (value?: number) => {
	const bytes = Number(value) || 0;
	if (bytes < 1024) return `${bytes} B`;
	const units = ["KB", "MB", "GB", "TB"];
	let current = bytes;
	let idx = -1;
	do {
		current /= 1024;
		idx += 1;
	} while (current >= 1024 && idx < units.length - 1);
	return `${current < 10 ? current.toFixed(2) : current < 100 ? current.toFixed(1) : Math.round(current)} ${units[idx]}`;
};

const getPlanBadge = (link: WireGuardLink) => {
	switch (link.planState) {
		case "ready":
			return { labelId: "platform.plan.ready", className: "bg-green-lt text-green" };
		case "validate":
			return { labelId: "platform.plan.validate", className: "bg-yellow-lt text-yellow" };
		case "shape":
			return { labelId: "platform.plan.shaping", className: "bg-blue-lt text-blue" };
		case "discover":
			return { labelId: "platform.plan.discover", className: "bg-secondary-lt text-secondary" };
		default:
			return { labelId: "platform.plan.unplanned", className: "bg-secondary-lt text-secondary" };
	}
};

const hasRouteHintForLink = (link: WireGuardLink, networks: { network: string }[]) =>
	networks.some((item) => link.importedNetworks.includes(item.network));

const getReachabilityBadge = (
	link: WireGuardLink,
	missingReturnRoutes: { network: string }[],
	natCandidates: { network: string }[],
) => {
	if (hasRouteHintForLink(link, missingReturnRoutes))
		return { labelId: "gateway.reach.return-missing", className: "bg-red-lt text-red" };
	if (hasRouteHintForLink(link, natCandidates))
		return { labelId: "gateway.reach.check-nat", className: "bg-yellow-lt text-yellow" };
	return { labelId: "gateway.reach.reachable", className: "bg-green-lt text-green" };
};

const getLinkTypeBadge = (link: WireGuardLink) => {
	switch (link.type) {
		case "client":
			return { labelId: "platform.link-type.client", className: "bg-green-lt text-green" };
		case "site-to-site":
			return { labelId: "platform.link-type.site", className: "bg-blue-lt text-blue" };
		case "hub-link":
			return { labelId: "platform.link-type.hub", className: "bg-cyan-lt text-cyan" };
		default:
			return { labelId: "platform.link-type.other", className: "bg-secondary-lt text-secondary" };
	}
};

const getGatewayGaps = (
	link: WireGuardLink,
	missingReturnRoutes: { network: string }[],
	natCandidates: { network: string }[],
) => {
	const gaps: string[] = [];
	if (!link.exportedNetworks.length) gaps.push("gateway.gap.no-exported");
	if (!link.importedNetworks.length) gaps.push("gateway.gap.no-imported");
	if (link.remoteManagementMode === "none" || link.remoteManagementMode === "unknown")
		gaps.push("gateway.gap.mgmt-undefined");
	if (link.returnPathMode === "auto" || link.returnPathMode === "unknown") gaps.push("gateway.gap.return-undecided");
	if (hasRouteHintForLink(link, missingReturnRoutes)) gaps.push("gateway.gap.missing-route");
	if (hasRouteHintForLink(link, natCandidates)) gaps.push("gateway.gap.nat-required");
	return gaps.length ? gaps : ["gateway.gap.no-blocking"];
};

const Gateway = () => {
	const { data, isLoading, isError, error } = useWireGuardStatus();

	if (isLoading) {
		return <Loading />;
	}

	if (isError) {
		return (
			<div className="alert alert-danger">
				{intl.formatMessage({ id: "gateway.error" }, { error: error.message })}
			</div>
		);
	}

	if (!data?.available || !data.summary) {
		return <div className="alert alert-warning">{intl.formatMessage({ id: "gateway.unavailable" })}</div>;
	}

	const summary = data.summary;
	const routeRows = data.routes.privateRoutes.slice(0, 20);
	const linkRows = (data.links || []).slice(0, 12);
	const missingReturnRoutes = data.routes.missingReturnRoutes || [];
	const natCandidates = data.routes.natCandidates || [];
	const observations = data.routes.observations || [];
	const networkRows = data.interfaces.flatMap((item) =>
		(item.exportedNetworks || item.peerNetworks).map((network) => ({
			iface: item.name,
			network,
			active: item.active,
			role: item.role || "unknown",
		})),
	);

	return (
		<div className="platform-page">
			<div className="platform-page-header">
				<div>
					<div className="platform-kicker">{intl.formatMessage({ id: "gateway.kicker" })}</div>
					<h1 className="platform-title">Gateway</h1>
					<p className="platform-subtitle">{intl.formatMessage({ id: "gateway.subtitle" })}</p>
				</div>
			</div>

			<div className="row row-cards">
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-blue text-white avatar">
								<IconShieldHalfFilled />
							</span>
							<div>
								<div className="text-secondary">
									{intl.formatMessage({ id: "gateway.stat.wireguard-routes" })}
								</div>
								<div className="platform-stat-value">{summary.wireguardRouteCount}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-cyan text-white avatar">
								<IconRoute2 />
							</span>
							<div>
								<div className="text-secondary">
									{intl.formatMessage({ id: "gateway.stat.private-routes" })}
								</div>
								<div className="platform-stat-value">{summary.privateRouteCount}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-yellow text-white avatar">
								<IconArrowsExchange2 />
							</span>
							<div>
								<div className="text-secondary">
									{intl.formatMessage({ id: "gateway.stat.peer-networks" })}
								</div>
								<div className="platform-stat-value">{summary.peerNetworkCount}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-green text-white avatar">
								<IconTopologyStar3 />
							</span>
							<div>
								<div className="text-secondary">
									{intl.formatMessage({ id: "gateway.stat.logical-links" })}
								</div>
								<div className="platform-stat-value">{summary.linkCount}</div>
							</div>
						</div>
					</div>
				</div>
			</div>

			<div className="d-flex gap-2 flex-wrap mb-4">
				<span className="badge bg-emerald-lt text-emerald">client {summary.clientLinkCount}</span>
				<span className="badge bg-indigo-lt text-indigo">site {summary.siteLinkCount}</span>
				<span className="badge bg-cyan-lt text-cyan">hub {summary.hubLinkCount}</span>
			</div>

			<div className="card platform-elevated-card mb-4">
				<div className="card-header">
					<h3 className="card-title">{intl.formatMessage({ id: "gateway.reachability.title" })}</h3>
				</div>
				<div className="card-body d-flex flex-column gap-3">
					{linkRows.length ? (
						linkRows.map((link) => {
							const planBadge = getPlanBadge(link);
							const reachabilityBadge = getReachabilityBadge(link, missingReturnRoutes, natCandidates);
							const typeBadge = getLinkTypeBadge(link);
							const gaps = getGatewayGaps(link, missingReturnRoutes, natCandidates);
							return (
								<div key={link.id} className="platform-list-item">
									<div className="d-flex justify-content-between gap-3 align-items-start flex-wrap">
										<div>
											<div className="fw-bold">{link.name}</div>
											<div className="text-secondary small">
												{link.interfaceName} ·{" "}
												{link.remoteEndpoint ||
													intl.formatMessage({ id: "gateway.link.endpoint-unknown" })}{" "}
												·{" "}
												{link.active
													? intl.formatMessage({ id: "gateway.link.active" })
													: intl.formatMessage({ id: "gateway.link.idle" })}
											</div>
										</div>
										<div className="d-flex gap-2 flex-wrap">
											<span className={`badge ${typeBadge.className}`}>
												{intl.formatMessage({ id: typeBadge.labelId })}
											</span>
											<span className={`badge ${planBadge.className}`}>
												{intl.formatMessage({ id: planBadge.labelId })}
											</span>
											<span className={`badge ${reachabilityBadge.className}`}>
												{intl.formatMessage({ id: reachabilityBadge.labelId })}
											</span>
										</div>
									</div>

									<div className="d-flex gap-2 flex-wrap mt-2">
										<span className="badge bg-indigo-lt text-indigo">
											intent {link.planIntent || link.type}
										</span>
										{link.exportedNetworks.slice(0, 4).map((network) => (
											<span
												key={`${link.id}-export-${network}`}
												className="badge bg-azure-lt text-azure"
											>
												export {network}
											</span>
										))}
										{link.importedNetworks.slice(0, 4).map((network) => (
											<span
												key={`${link.id}-import-${network}`}
												className="badge bg-blue-lt text-blue"
											>
												import {network}
											</span>
										))}
										<span className="badge bg-secondary-lt text-secondary">
											mgmt {link.remoteManagementMode}
										</span>
										<span className="badge bg-purple-lt text-purple">
											return {link.returnPathMode}
										</span>
									</div>

									<div className="small text-secondary d-flex flex-column gap-1 mt-3">
										{gaps.slice(0, 3).map((id) => (
											<div key={id}>• {intl.formatMessage({ id })}</div>
										))}
									</div>
									{link.warnings.length ? (
										<div className="small text-secondary d-flex flex-column gap-1 mt-2">
											{link.warnings.slice(0, 3).map((w) => (
												<div key={w}>⚠ {fmtWarning(w)}</div>
											))}
										</div>
									) : null}
									{link.nextActions.length ? (
										<div className="small text-secondary d-flex flex-column gap-1 mt-2">
											{link.nextActions.slice(0, 3).map((a) => (
												<div key={a}>• {fmtNextAction(a)}</div>
											))}
										</div>
									) : null}

									<div className="small text-secondary mt-3">
										Traffic: {byteFmt(link.rxBytes)} / {byteFmt(link.txBytes)}
									</div>
								</div>
							);
						})
					) : (
						<div className="text-secondary small">{intl.formatMessage({ id: "gateway.no-links" })}</div>
					)}
				</div>
			</div>

			<div className="row row-cards mb-4">
				<div className="col-lg-6">
					<div className="card h-100 platform-table-card">
						<div className="card-header">
							<h3 className="card-title">{intl.formatMessage({ id: "gateway.private-routes.title" })}</h3>
						</div>
						<div className="table-responsive">
							<table className="table table-vcenter card-table">
								<thead>
									<tr>
										<th>{intl.formatMessage({ id: "gateway.col-destination" })}</th>
										<th>{intl.formatMessage({ id: "gateway.col-device" })}</th>
										<th>{intl.formatMessage({ id: "gateway.col-via" })}</th>
									</tr>
								</thead>
								<tbody>
									{routeRows.length ? (
										routeRows.map((route) => (
											<tr key={route.raw}>
												<td className="fw-medium">{route.destination}</td>
												<td>
													{route.device || (
														<span className="text-secondary">
															{intl.formatMessage({ id: "gateway.col-na" })}
														</span>
													)}
												</td>
												<td>
													{route.via || (
														<span className="text-secondary">
															{intl.formatMessage({ id: "gateway.col-direct" })}
														</span>
													)}
												</td>
											</tr>
										))
									) : (
										<tr>
											<td colSpan={3} className="text-secondary">
												{intl.formatMessage({ id: "gateway.no-private-routes" })}
											</td>
										</tr>
									)}
								</tbody>
							</table>
						</div>
					</div>
				</div>
				<div className="col-lg-6">
					<div className="card h-100 platform-table-card">
						<div className="card-header">
							<h3 className="card-title">{intl.formatMessage({ id: "gateway.peer-networks.title" })}</h3>
						</div>
						<div className="table-responsive">
							<table className="table table-vcenter card-table">
								<thead>
									<tr>
										<th>{intl.formatMessage({ id: "wireguard.routing.col-interface" })}</th>
										<th>{intl.formatMessage({ id: "gateway.col-network" })}</th>
										<th>{intl.formatMessage({ id: "gateway.col-role" })}</th>
									</tr>
								</thead>
								<tbody>
									{networkRows.length ? (
										networkRows.map((row) => (
											<tr key={`${row.iface}-${row.network}`}>
												<td>{row.iface}</td>
												<td className="fw-medium">{row.network}</td>
												<td>
													<span
														className={`badge ${row.active ? "bg-green-lt text-green" : "bg-secondary-lt text-secondary"}`}
													>
														{row.role}
													</span>
												</td>
											</tr>
										))
									) : (
										<tr>
											<td colSpan={3} className="text-secondary">
												{intl.formatMessage({ id: "gateway.no-peer-networks" })}
											</td>
										</tr>
									)}
								</tbody>
							</table>
						</div>
					</div>
				</div>
			</div>

			<div className="row row-cards">
				<div className="col-lg-5">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title">{intl.formatMessage({ id: "gateway.routing-hints.title" })}</h3>
						</div>
						<div className="card-body d-flex flex-column gap-3">
							<div>
								<div className="fw-medium mb-2">
									{intl.formatMessage({ id: "gateway.missing-return.title" })}
								</div>
								{missingReturnRoutes.length ? (
									missingReturnRoutes.slice(0, 6).map((hint) => (
										<div key={`${hint.network}-${hint.reason}`} className="small mb-2">
											<div className="fw-medium">{hint.network}</div>
											<div className="text-secondary">{hint.reason}</div>
										</div>
									))
								) : (
									<div className="text-secondary small">
										{intl.formatMessage({ id: "gateway.missing-return.none" })}
									</div>
								)}
							</div>
							<div>
								<div className="fw-medium mb-2">
									{intl.formatMessage({ id: "gateway.nat-candidates.title" })}
								</div>
								{natCandidates.length ? (
									natCandidates.slice(0, 6).map((hint) => (
										<div key={`${hint.network}-${hint.reason}`} className="small mb-2">
											<div className="fw-medium">{hint.network}</div>
											<div className="text-secondary">{hint.reason}</div>
										</div>
									))
								) : (
									<div className="text-secondary small">
										{intl.formatMessage({ id: "gateway.nat-candidates.none" })}
									</div>
								)}
							</div>
						</div>
					</div>
				</div>
				<div className="col-lg-7">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title">{intl.formatMessage({ id: "gateway.observations.title" })}</h3>
						</div>
						<div className="card-body d-flex flex-column gap-2">
							{observations.length ? (
								observations.slice(0, 8).map((item) => (
									<div key={item} className="small text-secondary">
										• {item}
									</div>
								))
							) : (
								<div className="text-secondary small">
									{intl.formatMessage({ id: "gateway.no-observations" })}
								</div>
							)}
						</div>
					</div>
				</div>
			</div>
		</div>
	);
};

export default Gateway;
