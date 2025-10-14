import { T } from "src/locale";
import DefaultSite from "./DefaultSite";

export default function Layout() {
	// Taken from https://preview.tabler.io/settings.html
	// Refer to that when updating this content

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
									className="list-group-item list-group-item-action d-flex align-items-center active"
									onClick={(e) => e.preventDefault()}
								>
									<T id="settings.default-site" />
								</a>
							</div>
						</div>
					</div>
					<div className="col-12 col-md-9 d-flex flex-column">
						<DefaultSite />
					</div>
				</div>
			</div>
		</div>
	);
}
