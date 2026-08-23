import CodeEditor from "@uiw/react-textarea-code-editor/nohighlight";
import { Field } from "formik";
import { intl, T } from "src/locale";

interface Props {
	id?: string;
	name?: string;
	label?: string;
}
export function NginxConfigField({
	name = "advancedConfig",
	label = "nginx-config.label",
	id = "advancedConfig",
}: Props) {
	return (
		<Field name={name}>
			{({ field }: any) => {
				const lineCount = Math.max(1, String(field.value ?? "").split("\n").length);

				return (
					<div>
					<label htmlFor={id} className="form-label">
						<T id={label} />
					</label>
					<div className="platform-code-editor">
						<div className="platform-code-editor-gutter" aria-hidden="true">
							{Array.from({ length: lineCount }, (_, index) => (
								<span key={index}>{index + 1}</span>
							))}
						</div>
						<CodeEditor
							id={id}
							language="nginx"
							placeholder={intl.formatMessage({ id: "nginx-config.placeholder" })}
							padding={15}
							data-color-mode="dark"
							minHeight={200}
							indentWidth={2}
							style={{
								fontFamily:
									"ui-monospace,SFMono-Regular,SF Mono,Consolas,Liberation Mono,Menlo,monospace",
								minHeight: "200px",
								backgroundColor: "transparent",
							}}
							{...field}
						/>
					</div>
				</div>
				);
			}}
		</Field>
	);
}
