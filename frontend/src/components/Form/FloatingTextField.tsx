import { Field } from "formik";
import { intl, T } from "src/locale";

interface Props {
	name: string;
	labelId: string;
	type?: string;
	autoComplete?: string;
	required?: boolean;
	validate?: (value: any) => string | undefined | Promise<string | undefined>;
}

// Bootstrap floating-label text input bound to a Formik field, with the
// validation message shown once the field has been touched.
export function FloatingTextField({ name, labelId, type = "text", autoComplete, required, validate }: Props) {
	return (
		<Field name={name} validate={validate}>
			{({ field, form }: any) => {
				const invalid = form.errors[name] && form.touched[name];
				return (
					<div className="form-floating mb-3">
						<input
							id={name}
							type={type}
							autoComplete={autoComplete}
							required={required}
							className={`form-control ${invalid ? "is-invalid" : ""}`}
							placeholder={intl.formatMessage({ id: labelId })}
							{...field}
						/>
						<label htmlFor={name}>
							<T id={labelId} />
						</label>
						{form.errors[name] ? (
							<div className="invalid-feedback">{invalid ? form.errors[name] : null}</div>
						) : null}
					</div>
				);
			}}
		</Field>
	);
}
