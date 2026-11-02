import cn from "classnames";
import { useFormikContext } from "formik";
import { T } from "src/locale";

interface Props {
	// Hauptschlüssel unter Einstellungen → Cloudflare vorhanden und für diesen Benutzer freigegeben
	available?: boolean;
}

/**
 * Cloudflare-Schalter im Details-Tab (gleiche Zeilen wie Länder-Filter & Co.): DNS-Records eintragen und
 * Cloudflare-Proxy. Proxy an schaltet das Eintragen mit ein, Eintragen aus schaltet den Proxy mit aus.
 */
export function CloudflareDnsFields({ available }: Props) {
	const { values, setFieldValue } = useFormikContext<any>();
	const config = values.meta?.cloudflareDns || {};
	const enabled = Boolean(config.enabled);
	const proxied = Boolean(config.proxied);

	const setEnabled = (on: boolean) => {
		setFieldValue("meta.cloudflareDns.enabled", on);
		if (!on) setFieldValue("meta.cloudflareDns.proxied", false);
	};
	const setProxied = (on: boolean) => {
		setFieldValue("meta.cloudflareDns.proxied", on);
		if (on) setFieldValue("meta.cloudflareDns.enabled", true);
	};

	return (
		<>
			<div>
				<label className="row" htmlFor="cloudflareDns">
					<span className="col">
						<T id="host.flags.cloudflare-dns" />
						<span className="form-hint d-block mt-0">
							{config.status === "error" && config.error ? (
								<span className="text-danger">{config.error}</span>
							) : enabled && config.status === "synced" ? (
								<span className="text-green">
									<T id="host.flags.cloudflare-dns.synced" />
								</span>
							) : available === false && enabled ? (
								<T id="host.flags.cloudflare-dns.no-token" />
							) : (
								<T id="host.flags.cloudflare-dns.hint" />
							)}
						</span>
					</span>
					<span className="col-auto">
						<label className="form-check form-check-single form-switch">
							<input
								id="cloudflareDns"
								className={cn("form-check-input", { "bg-lime": enabled })}
								type="checkbox"
								checked={enabled}
								onChange={(e) => setEnabled(e.target.checked)}
							/>
						</label>
					</span>
				</label>
			</div>
			<div>
				<label className="row" htmlFor="cloudflareProxied">
					<span className="col">
						<T id="host.flags.cloudflare-proxied" />
						<span className="form-hint d-block mt-0">
							<T id="host.flags.cloudflare-proxied.hint" />
						</span>
					</span>
					<span className="col-auto">
						<label className="form-check form-check-single form-switch">
							<input
								id="cloudflareProxied"
								className={cn("form-check-input", { "bg-orange": proxied })}
								type="checkbox"
								checked={proxied}
								onChange={(e) => setProxied(e.target.checked)}
							/>
						</label>
					</span>
				</label>
			</div>
		</>
	);
}
