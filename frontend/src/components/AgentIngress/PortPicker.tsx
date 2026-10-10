import { useEffect, useRef, useState } from "react";
import type { AgentIngressPortPreset } from "src/api/backend";
import { portsToPresetSelection, selectionToPorts } from "./catalog";
import { formatPorts, parsePorts, ti } from "./utils";

interface Props {
	id: string;
	/**
	 * Ports in the formatPorts syntax ("tcp/443, udp/53"); "" = all ports;
	 * null = nothing chosen yet (wizards make "all ports" an explicit choice).
	 */
	value: string | null;
	onChange: (value: string | null) => void;
	presets: AgentIngressPortPreset[];
	/** id of the element that labels the preset group */
	labelledBy?: string;
	disabled?: boolean;
}

const fromValue = (value: string | null, presets: AgentIngressPortPreset[]) => {
	if (value === null) return { presetIds: [] as string[], custom: "" };
	// keep invalid entries as typed: validation reports them
	const { ports, invalid } = parsePorts(value);
	if (!ports.length && !invalid.length) return portsToPresetSelection([], presets);
	const sel = portsToPresetSelection(ports, presets);
	return { presetIds: sel.presetIds, custom: [sel.custom, ...invalid].filter(Boolean).join(", ") };
};

/**
 * Port presets as pills ("Web (80/443)", "SSH", …, "All ports", exclusive)
 * plus a free field for further ports. Emits the formatPorts text, so the rule
 * form keeps its string value and validation.
 */
export function PortPicker({ id, value, onChange, presets, labelledBy, disabled }: Props) {
	const [state, setState] = useState(() => fromValue(value, presets));
	const lastEmitted = useRef<string | null | undefined>(undefined);

	// An outside change (not our own echo) re-derives the selection
	useEffect(() => {
		if (value === lastEmitted.current) return;
		setState(fromValue(value, presets));
	}, [value, presets]);

	const emit = (presetIds: string[], custom: string) => {
		setState({ presetIds, custom });
		let out: string | null;
		if (presetIds.includes("all")) {
			out = "";
		} else {
			const fromPresets = formatPorts(selectionToPorts(presetIds, "", presets));
			const text = [fromPresets, custom.trim()].filter(Boolean).join(", ");
			out = text ? text : null;
		}
		lastEmitted.current = out;
		onChange(out);
	};

	const toggle = (presetId: string, checked: boolean) => {
		if (presetId === "all") {
			emit(checked ? ["all"] : [], checked ? "" : state.custom);
			return;
		}
		const others = state.presetIds.filter((p) => p !== "all" && p !== presetId);
		emit(checked ? [...others, presetId] : others, state.custom);
	};

	const allChecked = state.presetIds.includes("all");

	return (
		<div>
			<div className="form-selectgroup form-selectgroup-pills" role="group" aria-labelledby={labelledBy}>
				{presets.map((p) => (
					<label key={p.id} className="form-selectgroup-item">
						<input
							type="checkbox"
							className="form-selectgroup-input"
							id={`${id}-preset-${p.id}`}
							checked={state.presetIds.includes(p.id)}
							disabled={disabled}
							onChange={(e) => toggle(p.id, e.target.checked)}
						/>
						<span className="form-selectgroup-label py-1 px-2 small">{ti(`preset.${p.id}`)}</span>
					</label>
				))}
			</div>
			<input
				id={id}
				type="text"
				className="form-control form-control-sm font-monospace mt-2"
				value={state.custom}
				placeholder={ti("ports.custom")}
				aria-describedby={`${id}-hint`}
				disabled={disabled || allChecked}
				onChange={(e) =>
					emit(
						state.presetIds.filter((p) => p !== "all"),
						e.target.value,
					)
				}
			/>
			<div id={`${id}-hint`} className="form-text small">
				{ti("ports.custom-hint")}
			</div>
		</div>
	);
}
