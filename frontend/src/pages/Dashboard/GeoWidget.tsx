import { IconArrowRight, IconWorld } from "@tabler/icons-react";
import { lazy, Suspense, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Loading } from "src/components";
import { useGeoFilter } from "src/hooks";
import { intl } from "src/locale/IntlProvider";
import CountryFlag from "src/pages/Settings/geo/CountryFlag";
import { countryName } from "src/pages/Settings/geo/countries";

const WorldMap = lazy(() => import("src/pages/Settings/geo/WorldMap"));
const t = (id: string, values?: Record<string, string | number>) => intl.formatMessage({ id }, values);

/** Dashboard-Block „Länder-Filter“: Weltkarte der gesperrten Zugriffe (30 Tage) + Top-Länder. Nur Admins. */
export default function GeoWidget() {
	const { data } = useGeoFilter();
	const navigate = useNavigate();
	const s = data?.stats;
	const counts = useMemo(() => Object.fromEntries((s?.countries || []).map((c) => [c.code, c.count])), [s]);
	if (!data || !s) return null;
	const top = s.countries.slice(0, 6);
	const max = Math.max(1, ...top.map((c) => c.count));
	const today = s.perDay[s.perDay.length - 1]?.count || 0;
	const open = () => navigate("/settings#geo-filter");

	return (
		<div className="row row-cards">
			<div className="col-12">
				<div className="card platform-elevated-card">
					<div className="card-header">
						<h3 className="card-title d-flex align-items-center gap-2">
							<IconWorld size={18} /> {t("dashboard.geo.title")}
						</h3>
						<div className="card-options">
							<a
								href="/settings#geo-filter"
								className="btn btn-sm btn-ghost-secondary"
								onClick={(e) => {
									e.preventDefault();
									open();
								}}
							>
								{t("dashboard.geo.details")} <IconArrowRight size={14} />
							</a>
						</div>
					</div>
					<div className="card-body">
						{!data.hosts.length ? (
							<div className="text-secondary">{t("dashboard.geo.no-hosts")}</div>
						) : (
							<div className="row g-4 align-items-center">
								<div className="col-lg-8">
									{s.total ? (
										<Suspense fallback={<Loading noLogo />}>
											<WorldMap counts={counts} allowed={data.activeCountries} total={s.total} />
										</Suspense>
									) : (
										<div className="geo-empty">
											<IconWorld size={36} className="text-secondary mb-2" />
											<div className="text-secondary">{t("settings.geo-filter.map.empty")}</div>
										</div>
									)}
								</div>
								<div className="col-lg-4">
									<div className="d-flex gap-4 mb-3">
										<div>
											<div className="text-secondary small">
												{t("settings.geo-filter.kpi.blocked")}
											</div>
											<div className="platform-stat-value">{s.total.toLocaleString()}</div>
										</div>
										<div>
											<div className="text-secondary small">
												{t("settings.geo-filter.kpi.today")}
											</div>
											<div className="platform-stat-value">{today.toLocaleString()}</div>
										</div>
									</div>
									{top.map((c) => (
										<div key={c.code} className="geo-bar-row">
											<CountryFlag code={c.code} />
											<span className="geo-bar-label text-truncate">{countryName(c.code)}</span>
											<span className="geo-bar-track">
												<span
													className="geo-bar-fill"
													style={{ width: `${(c.count / max) * 100}%` }}
												/>
											</span>
											<span className="geo-bar-value">{c.count.toLocaleString()}</span>
										</div>
									))}
									<div className="text-secondary small mt-2">
										{t("dashboard.geo.hosts", { count: data.hosts.length })}
									</div>
								</div>
							</div>
						)}
					</div>
				</div>
			</div>
		</div>
	);
}
