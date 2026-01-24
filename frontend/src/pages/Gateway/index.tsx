import { IconArrowsExchange2, IconRoute2, IconShieldHalfFilled, IconTopologyStar3 } from "@tabler/icons-react";
import { Loading } from "src/components";
import { useWireGuardStatus } from "src/hooks";
import type { WireGuardLink } from "src/api/backend";

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
			return { label: "Ready", className: "bg-green-lt text-green" };
		case "validate":
			return { label: "Validate", className: "bg-yellow-lt text-yellow" };
		case "shape":
			return { label: "Shaping", className: "bg-blue-lt text-blue" };
		case "discover":
			return { label: "Discover", className: "bg-secondary-lt text-secondary" };
		default:
			return { label: "Unplanned", className: "bg-secondary-lt text-secondary" };
	}
};

const hasRouteHintForLink = (link: WireGuardLink, networks: { network: string }[]) =>
	networks.some((item) => link.importedNetworks.includes(item.network));

const getReachabilityBadge = (
	link: WireGuardLink,
	missingReturnRoutes: { network: string }[],
	natCandidates: { network: string }[],
) => {
	if (hasRouteHintForLink(link, missingReturnRoutes)) return { label: "Return path missing", className: "bg-red-lt text-red" };
	if (hasRouteHintForLink(link, natCandidates)) return { label: "Check NAT", className: "bg-yellow-lt text-yellow" };
	return { label: "Reachable", className: "bg-green-lt text-green" };
};

const getLinkTypeBadge = (link: WireGuardLink) => {
	switch (link.type) {
		case "client":
			return { label: "Client", className: "bg-green-lt text-green" };
		case "site-to-site":
			return { label: "Site", className: "bg-blue-lt text-blue" };
		case "hub-link":
			return { label: "Hub", className: "bg-cyan-lt text-cyan" };
		default:
			return { label: "Other", className: "bg-secondary-lt text-secondary" };
	}
};

const getGatewayGaps = (
	link: WireGuardLink,
	missingReturnRoutes: { network: string }[],
	natCandidates: { network: string }[],
) => {
	const gaps = [];
	if (!link.exportedNetworks.length) gaps.push("No local exported networks are defined for this link yet.");
	if (!link.importedNetworks.length) gaps.push("No remote imported networks are defined for this link yet.");
	if (link.remoteManagementMode === "none" || link.remoteManagementMode === "unknown") gaps.push("Remote management path is still undefined.");
	if (link.returnPathMode === "auto" || link.returnPathMode === "unknown") gaps.push("Return path mode is still undecided.");
	if (hasRouteHintForLink(link, missingReturnRoutes)) gaps.push("At least one imported network has no matching live WireGuard route.");
	if (hasRouteHintForLink(link, natCandidates)) gaps.push("Gateway runtime suggests NAT may still be required.");
	return gaps.length ? gaps : ["Current gateway view does not show a blocking routing gap for this link."];
};

const Gateway = () => {
	const { data, isLoading, isError, error } = useWireGuardStatus();

	if (isLoading) {
		return <Loading />;
	}

	if (isError) {
		return <div className="alert alert-danger">Failed to load gateway status: {error.message}</div>;
	}

	if (!data?.available || !data.summary) {
		return <div className="alert alert-warning">Gateway data is not available in this runtime yet.</div>;
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
					<div className="platform-kicker">Network View</div>
					<h1 className="platform-title">Gateway</h1>
					<p className="platform-subtitle">
						Reachability, return-path risk and link readiness for the emerging FloppyGuard control plane.
					</p>
				</div>
			</div>

			<div className="row row-cards">
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-blue text-white avatar"><IconShieldHalfFilled /></span>
							<div>
								<div className="text-secondary">WireGuard Routes</div>
								<div className="platform-stat-value">{summary.wireguardRouteCount}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-cyan text-white avatar"><IconRoute2 /></span>
							<div>
								<div className="text-secondary">Private Routes</div>
								<div className="platform-stat-value">{summary.privateRouteCount}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-yellow text-white avatar"><IconArrowsExchange2 /></span>
							<div>
								<div className="text-secondary">Peer Networks</div>
								<div className="platform-stat-value">{summary.peerNetworkCount}</div>
							</div>
						</div>
					</div>
				</div>
				<div className="col-sm-6 col-xl-3">
					<div className="card card-sm h-100 platform-stat-card">
						<div className="card-body d-flex align-items-center gap-3">
							<span className="bg-green text-white avatar"><IconTopologyStar3 /></span>
							<div>
								<div className="text-secondary">Logical Links</div>
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
					<h3 className="card-title">Gateway Reachability Map</h3>
				</div>
				<div className="card-body d-flex flex-column gap-3">
					{linkRows.length ? linkRows.map((link) => {
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
											{link.interfaceName} · {link.remoteEndpoint || "endpoint unknown"} · {link.active ? "active" : "idle"}
										</div>
									</div>
									<div className="d-flex gap-2 flex-wrap">
										<span className={`badge ${typeBadge.className}`}>{typeBadge.label}</span>
										<span className={`badge ${planBadge.className}`}>{planBadge.label}</span>
										<span className={`badge ${reachabilityBadge.className}`}>{reachabilityBadge.label}</span>
									</div>
								</div>

								<div className="d-flex gap-2 flex-wrap mt-2">
									<span className="badge bg-indigo-lt text-indigo">intent {link.planIntent || link.type}</span>
									{link.exportedNetworks.slice(0, 4).map((network) => <span key={`${link.id}-export-${network}`} className="badge bg-azure-lt text-azure">export {network}</span>)}
									{link.importedNetworks.slice(0, 4).map((network) => <span key={`${link.id}-import-${network}`} className="badge bg-blue-lt text-blue">import {network}</span>)}
									<span className="badge bg-secondary-lt text-secondary">mgmt {link.remoteManagementMode}</span>
									<span className="badge bg-purple-lt text-purple">return {link.returnPathMode}</span>
								</div>

								<div className="small text-secondary d-flex flex-column gap-1 mt-3">
									{gaps.slice(0, 3).map((item) => <div key={item}>• {item}</div>)}
								</div>
								{link.warnings.length ? (
									<div className="small text-secondary d-flex flex-column gap-1 mt-2">
										{link.warnings.slice(0, 3).map((item) => <div key={item}>warning: {item}</div>)}
									</div>
								) : null}
								{link.nextActions.length ? (
									<div className="small text-secondary d-flex flex-column gap-1 mt-2">
										{link.nextActions.slice(0, 3).map((item) => <div key={item}>next: {item}</div>)}
									</div>
								) : null}

								<div className="small text-secondary mt-3">
									Traffic: {byteFmt(link.rxBytes)} / {byteFmt(link.txBytes)}
								</div>
							</div>
						);
					}) : <div className="text-secondary small">No derived links available yet.</div>}
				</div>
			</div>

			<div className="row row-cards mb-4">
				<div className="col-lg-6">
					<div className="card h-100 platform-table-card">
						<div className="card-header">
							<h3 className="card-title">Private Route Inventory</h3>
						</div>
						<div className="table-responsive">
							<table className="table table-vcenter card-table">
								<thead>
									<tr>
										<th>Destination</th>
										<th>Device</th>
										<th>Via</th>
									</tr>
								</thead>
								<tbody>
									{routeRows.length ? routeRows.map((route) => (
										<tr key={route.raw}>
											<td className="fw-medium">{route.destination}</td>
											<td>{route.device || <span className="text-secondary">n/a</span>}</td>
											<td>{route.via || <span className="text-secondary">direct</span>}</td>
										</tr>
									)) : (
										<tr>
											<td colSpan={3} className="text-secondary">No private route inventory available yet.</td>
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
							<h3 className="card-title">Peer Network Inventory</h3>
						</div>
						<div className="table-responsive">
							<table className="table table-vcenter card-table">
								<thead>
									<tr>
										<th>Interface</th>
										<th>Network</th>
										<th>Role</th>
									</tr>
								</thead>
								<tbody>
									{networkRows.length ? networkRows.map((row) => (
										<tr key={`${row.iface}-${row.network}`}>
											<td>{row.iface}</td>
											<td className="fw-medium">{row.network}</td>
											<td>
												<span className={`badge ${row.active ? "bg-green-lt text-green" : "bg-secondary-lt text-secondary"}`}>
													{row.role}
												</span>
											</td>
										</tr>
									)) : (
										<tr>
											<td colSpan={3} className="text-secondary">No peer networks detected from current WireGuard configs.</td>
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
							<h3 className="card-title">Routing Hints</h3>
						</div>
						<div className="card-body d-flex flex-column gap-3">
							<div>
								<div className="fw-medium mb-2">Missing Return Routes</div>
								{missingReturnRoutes.length ? missingReturnRoutes.slice(0, 6).map((hint) => (
									<div key={`${hint.network}-${hint.reason}`} className="small mb-2">
										<div className="fw-medium">{hint.network}</div>
										<div className="text-secondary">{hint.reason}</div>
									</div>
								)) : <div className="text-secondary small">No missing return routes detected right now.</div>}
							</div>
							<div>
								<div className="fw-medium mb-2">NAT Candidates</div>
								{natCandidates.length ? natCandidates.slice(0, 6).map((hint) => (
									<div key={`${hint.network}-${hint.reason}`} className="small mb-2">
										<div className="fw-medium">{hint.network}</div>
										<div className="text-secondary">{hint.reason}</div>
									</div>
								)) : <div className="text-secondary small">No obvious NAT candidates detected right now.</div>}
							</div>
						</div>
					</div>
				</div>
				<div className="col-lg-7">
					<div className="card h-100 platform-elevated-card">
						<div className="card-header">
							<h3 className="card-title">Observations</h3>
						</div>
						<div className="card-body d-flex flex-column gap-2">
							{observations.length ? observations.slice(0, 8).map((item) => (
								<div key={item} className="small text-secondary">• {item}</div>
							)) : <div className="text-secondary small">No additional route observations available.</div>}
						</div>
					</div>
				</div>
			</div>
		</div>
	);
};

export default Gateway;
