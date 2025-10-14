import { IconSettings } from "@tabler/icons-react";
import CodeEditor from "@uiw/react-textarea-code-editor/nohighlight";
import cn from "classnames";
import { useFormikContext } from "formik";
import { useState } from "react";
import type { ProxyLocation } from "src/api/backend";
import { intl, T } from "src/locale";
import styles from "./LocationsFields.module.css";

interface Props {
	initialValues: ProxyLocation[];
	name?: string;
}
export function LocationsFields({ initialValues, name = "locations" }: Props) {
	const [values, setValues] = useState<ProxyLocation[]>(initialValues || []);
	const { setFieldValue } = useFormikContext();
	const [advVisible, setAdvVisible] = useState<number[]>([]);

	const blankItem: ProxyLocation = {
		path: "",
		advancedConfig: "",
		forwardScheme: "http",
		forwardHost: "",
		forwardPort: 80,
	};

	const toggleAdvVisible = (idx: number) => {
		setAdvVisible(advVisible.includes(idx) ? advVisible.filter((i) => i !== idx) : [...advVisible, idx]);
	};

	const handleAdd = () => {
		setValues([...values, blankItem]);
	};

	const handleRemove = (idx: number) => {
		const newValues = values.filter((_: ProxyLocation, i: number) => i !== idx);
		setValues(newValues);
		setFormField(newValues);
	};

	const handleChange = (idx: number, field: string, fieldValue: string) => {
		const newValues = values.map((v: ProxyLocation, i: number) => (i === idx ? { ...v, [field]: fieldValue } : v));
		setValues(newValues);
		setFormField(newValues);
	};

	const setFormField = (newValues: ProxyLocation[]) => {
		const filtered = newValues.filter((v: ProxyLocation) => v?.path?.trim() !== "");
		setFieldValue(name, filtered);
	};

	if (values.length === 0) {
		return (
			<div className={styles.addRow}>
				<button type="button" className="btn btn-primary my-3" onClick={handleAdd}>
					<T id="action.add-location" />
				</button>
			</div>
		);
	}

	return (
		<>
			{values.map((item: ProxyLocation, idx: number) => (
				<div key={idx} className={cn("card", "card-active", "mb-3", styles.locationCard)}>
					<div className="card-body">
						<div className={styles.locationHeader}>
							<h4 className={styles.locationTitle}>
								<T id="column.custom-locations" /> #{idx + 1}
							</h4>
							<button
								type="button"
								className={styles.settingsButton}
								title="Advanced"
								onClick={() => toggleAdvVisible(idx)}
							>
								<IconSettings size={20} />
							</button>
						</div>
						<div className="row">
							<div className="col-md-12">
								<div className="input-group mb-3">
									<span className="input-group-text">Location</span>
									<input
										type="text"
										className="form-control"
										placeholder="/path"
										autoComplete="off"
										value={item.path}
										onChange={(e) => handleChange(idx, "path", e.target.value)}
									/>
								</div>
							</div>
						</div>
						<div className="row">
							<div className="col-md-3">
								<div className="mb-3">
									<label className="form-label" htmlFor="forwardScheme">
										<T id="host.forward-scheme" />
									</label>
									<select
										id="forwardScheme"
										className="form-control"
										value={item.forwardScheme}
										onChange={(e) => handleChange(idx, "forwardScheme", e.target.value)}
									>
										<option value="http">http</option>
										<option value="https">https</option>
									</select>
								</div>
							</div>
							<div className="col-md-6">
								<div className="mb-3">
									<label className="form-label" htmlFor="forwardHost">
										<T id="proxy-host.forward-host" />
									</label>
									<input
										id="forwardHost"
										type="text"
										className="form-control"
										required
										placeholder="eg: 10.0.0.1/path/"
										value={item.forwardHost}
										onChange={(e) => handleChange(idx, "forwardHost", e.target.value)}
									/>
								</div>
							</div>
							<div className="col-md-3">
								<div className="mb-3">
									<label className="form-label" htmlFor="forwardPort">
										<T id="host.forward-port" />
									</label>
									<input
										id="forwardPort"
										type="number"
										min={1}
										max={65535}
										className="form-control"
										required
										placeholder="eg: 8081"
										value={item.forwardPort}
										onChange={(e) => handleChange(idx, "forwardPort", e.target.value)}
									/>
								</div>
							</div>
						</div>
						{advVisible.includes(idx) && (
							<div className={styles.advancedPanel}>
								<label className="form-label">
									<T id="nginx-config.label" />
								</label>
								<div className={styles.editorShell}>
									<CodeEditor
										language="nginx"
										placeholder={intl.formatMessage({ id: "nginx-config.placeholder" })}
										padding={15}
										data-color-mode="dark"
										minHeight={170}
										indentWidth={2}
										value={item.advancedConfig}
										onChange={(e) => handleChange(idx, "advancedConfig", e.target.value)}
										style={{
											fontFamily:
												"ui-monospace,SFMono-Regular,SF Mono,Consolas,Liberation Mono,Menlo,monospace",
											minHeight: "170px",
											backgroundColor: "transparent",
										}}
									/>
								</div>
							</div>
						)}
						<div className="mt-1">
							<a
								className={styles.deleteAction}
								href="#"
								onClick={(e) => {
									e.preventDefault();
									handleRemove(idx);
								}}
							>
								<T id="action.delete" />
							</a>
						</div>
					</div>
				</div>
			))}
			<div className={styles.addRow}>
				<button type="button" className="btn btn-sm btn-primary" onClick={handleAdd}>
					<T id="action.add-location" />
				</button>
			</div>
		</>
	);
}
