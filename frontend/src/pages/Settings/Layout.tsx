import { useState } from "react";
import { T } from "src/locale";
import ApplicationUpdate from "./ApplicationUpdate";
import DefaultSite from "./DefaultSite";
import SsoSettings from "./SsoSettings";

type Tab = "default-site" | "sso" | "application-update";

const initialTab = (): Tab => {
	const hash = window.location.hash.replace("#", "");
	return hash === "sso" || hash === "application-update" ? hash : "default-site";
};

export default function Layout() {
	// Taken from https://preview.tabler.io/settings.html
	// Refer to that when updating this content
	const [activeTab, setActiveTab] = useState<Tab>(initialTab);

	return (
		<div className="card platform-admin-card">
			<div className="card-status-top bg-teal" />
			<div className="card-table">
				<div className="card-header">
					<div className="platform-admin-header">
						<h2 className="platform-admin-title">
							<T id="settings" />
						</h2>
					</div>
				</div>
				<div className="row g-0">
					<div className="col-12 col-md-3 border-end platform-settings-nav">
						<div className="card-body mt-0 pt-0">
							<div className="list-group list-group-transparent">
								<a
									href="#"
									className={`list-group-item list-group-item-action d-flex align-items-center ${activeTab === "default-site" ? "active" : ""}`}
									onClick={(e) => {
										e.preventDefault();
										setActiveTab("default-site");
									}}
								>
									<T id="settings.default-site" />
								</a>
								<a
									href="#sso"
									className={`list-group-item list-group-item-action d-flex align-items-center ${activeTab === "sso" ? "active" : ""}`}
									onClick={(e) => {
										e.preventDefault();
										setActiveTab("sso");
									}}
								>
									<T id="settings.sso" />
								</a>
								<a
									href="#application-update"
									className={`list-group-item list-group-item-action d-flex align-items-center ${activeTab === "application-update" ? "active" : ""}`}
									onClick={(e) => {
										e.preventDefault();
										setActiveTab("application-update");
									}}
								>
									<T id="settings.application-update" />
								</a>
							</div>
						</div>
					</div>
					<div className="col-12 col-md-9 d-flex flex-column">
						{activeTab === "default-site" ? (
							<DefaultSite />
						) : activeTab === "sso" ? (
							<SsoSettings />
						) : (
							<ApplicationUpdate />
						)}
					</div>
				</div>
			</div>
		</div>
	);
}
