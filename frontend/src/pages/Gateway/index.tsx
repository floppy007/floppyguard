import { IconArrowsExchange2, IconRoute2, IconShieldHalfFilled, IconTopologyStar3 } from "@tabler/icons-react";
import type { WireGuardLink } from "src/api/backend";
import { Loading } from "src/components";
import { useWireGuardStatus } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import { byteFmt } from "src/pages/WireGuard/topology";
import { fmtNextAction, fmtWarning, getLinkTypeBadge, getPlanBadge } from "src/pages/WireGuard/linkLabels";

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

	// Only block without data: a failed background refetch keeps the last status
	if (isError && !data) {
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
	const routeRows = data.routes.privateRoutes;
	const linkRows = data.links || [];
	const missingReturnRoutes = data.routes.missingReturnRoutes || [];
	const natCandidates = data.routes.natCandidates || [];
	const observations = data.routes.observations || [];
	const networkRows = data.interfaces.flatMap((item) =>
		(item.exportedNetworks?.length ? item.exportedNetworks : (item.peerNetworks ?? [])).map((network) => ({
			iface: item.name,
			network,
			active: item.active,
			role: item.role || "unknown",
		})),
	);

	return (
		<div className="platform-page">
			{isError && (
				<div className="alert alert-warning">
					{intl.formatMessage({ id: "gateway.error" }, { error: error?.message ?? "" })}
				</div>
			)}
			<div className="platform-page-header">
				<div>
					<div className="platform-kicker">{intl.formatMessage({ id: "gateway.kicker" })}</div>
					<h1 className="platform-title">{intl.formatMessage({ id: "gateway" })}</h1>
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
				<span className="badge bg-emerald-lt text-emerald">
					{intl.formatMessage({ id: "platform.link-type.client" })} {summary.clientLinkCount}
				</span>
				<span className="badge bg-indigo-lt text-indigo">
					{intl.formatMessage({ id: "platform.link-type.site" })} {summary.siteLinkCount}
				</span>
				<span className="badge bg-cyan-lt text-cyan">
					{intl.formatMessage({ id: "platform.link-type.hub" })} {summary.hubLinkCount}
				</span>
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
										{link.exportedNetworks.map((network) => (
											<span
												key={`${link.id}-export-${network}`}
												className="badge bg-azure-lt text-azure"
											>
												{intl.formatMessage({ id: "wireguard.link.export" })} {network}
											</span>
										))}
										{link.importedNetworks.map((network) => (
											<span
												key={`${link.id}-import-${network}`}
												className="badge bg-blue-lt text-blue"
											>
												{intl.formatMessage({ id: "wireguard.link.import" })} {network}
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
										{gaps.map((id) => (
											<div key={id}>• {intl.formatMessage({ id })}</div>
										))}
									</div>
									{link.warnings.length ? (
										<div className="small text-secondary d-flex flex-column gap-1 mt-2">
											{link.warnings.map((w) => (
												<div key={w}>⚠ {fmtWarning(w)}</div>
											))}
										</div>
									) : null}
									{link.nextActions.length ? (
										<div className="small text-secondary d-flex flex-column gap-1 mt-2">
											{link.nextActions.map((a) => (
												<div key={a}>• {fmtNextAction(a)}</div>
											))}
										</div>
									) : null}

									<div className="small text-secondary mt-3">
										{intl.formatMessage({ id: "wireguard.link.traffic" })}: {byteFmt(link.rxBytes)}{" "}
										/ {byteFmt(link.txBytes)}
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
									missingReturnRoutes.map((hint) => (
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
									natCandidates.map((hint) => (
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
								observations.map((item) => (
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
