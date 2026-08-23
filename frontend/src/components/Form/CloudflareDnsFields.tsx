import { Field, useFormikContext } from "formik";

export function CloudflareDnsFields() {
	const { values, setFieldValue } = useFormikContext<any>();
	const config = values.meta?.cloudflareDns || {};

	return (
		<div className="mt-4 pt-3 border-top">
			<div className="d-flex justify-content-between align-items-center mb-2">
				<div>
					<div className="form-label mb-0">Cloudflare DNS</div>
					<div className="text-secondary small">Synchronizes explicit A/AAAA records when this Proxy Host is saved.</div>
				</div>
				{config.status ? <span className={`badge ${config.status === "synced" ? "bg-green-lt" : "bg-red-lt"}`}>{config.status}</span> : null}
			</div>
			<Field name="meta.cloudflareDns.enabled">
				{({ field }: any) => (
					<label className="form-check form-switch mb-2">
						<input
							{...field}
							className="form-check-input"
							type="checkbox"
							checked={Boolean(field.value)}
							onChange={(event) => setFieldValue(field.name, event.target.checked)}
						/>
						<span className="form-check-label">Manage DNS records automatically</span>
					</label>
				)}
			</Field>
			<Field name="meta.cloudflareDns.proxied">
				{({ field }: any) => (
					<label className="form-check form-switch">
						<input
							{...field}
							className="form-check-input"
							type="checkbox"
							disabled={!config.enabled}
							checked={Boolean(field.value)}
							onChange={(event) => setFieldValue(field.name, event.target.checked)}
						/>
						<span className="form-check-label">Proxy through Cloudflare</span>
					</label>
				)}
			</Field>
			{config.error ? <div className="text-danger small mt-2">{config.error}</div> : null}
		</div>
	);
}
