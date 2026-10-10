import { IconBuilding, IconDeviceLaptop, IconNetwork, IconServer, IconWorldWww } from "@tabler/icons-react";
import type { AgentIngressCatalog, AgentIngressCatalogKind } from "src/api/backend";
import type { GroupBase, MultiValue, SingleValue, StylesConfig } from "react-select";
import CreatableSelect from "react-select/creatable";
import { canonCidr, collapseCidrs, entryLabel, type PickerEntry, shortCidr } from "./catalog";
import { isIpv4OrCidr, splitList, ti } from "./utils";

/** Tabler icon per catalog kind (aria-hidden: the label carries the meaning). */
export function KindIcon({ kind, size = 14 }: { kind: AgentIngressCatalogKind | "other"; size?: number }) {
	const props = { size, "aria-hidden": true as const, className: "text-secondary flex-shrink-0" };
	switch (kind) {
		case "hub":
		case "hub-egress":
			return <IconWorldWww {...props} />;
		case "site":
		case "site-net":
			return <IconBuilding {...props} />;
		case "client":
			return <IconDeviceLaptop {...props} />;
		case "proxy-host":
		case "stream":
		case "manual":
		case "service":
			return <IconServer {...props} />;
		default:
			return <IconNetwork {...props} />;
	}
}

type GroupId = "hub" | "sites" | "clients" | "tunnel" | "published" | "services" | "networks";
const GROUP_ORDER: GroupId[] = ["hub", "sites", "clients", "tunnel", "published", "services", "networks"];

const groupOf = (e: PickerEntry): GroupId => {
	switch (e.kind) {
		case "hub":
			return "hub";
		case "hub-egress":
			return e.id.startsWith("egress:") ? "hub" : "published";
		case "site":
		case "site-net":
			return "sites";
		case "client":
			return "clients";
		case "tunnel":
			return "tunnel";
		case "proxy-host":
		case "stream":
		case "manual":
			return "published";
		case "service":
			return "services";
		default:
			return "networks";
	}
};

export interface PickerOption {
	value: string;
	label: string;
	cidrs: string[];
	entry?: PickerEntry;
	__isNew__?: boolean;
}

type Group = GroupBase<PickerOption>;

// The menu is portalled to <body> (it must escape modals and cards), so the
// .react-select-container theme rules in App.css do not reach it: theme it
// with the same Tabler variables here.
const STYLES: StylesConfig<PickerOption, boolean, Group> = {
	menuPortal: (base) => ({ ...base, zIndex: 1060 }),
	menu: (base) => ({
		...base,
		backgroundColor: "var(--tblr-bg-forms)",
		color: "var(--tblr-body-color)",
		border: "var(--tblr-border-width) solid var(--tblr-border-color)",
	}),
	// The current choice stays marked when the menu reopens (single pickers);
	// App.css carries the same for the portal rules, which win on specificity.
	option: (base, state) => ({
		...base,
		color: "inherit",
		fontWeight: state.isSelected ? 600 : base.fontWeight,
		backgroundColor: state.isSelected
			? "rgba(var(--tblr-primary-rgb), .2)"
			: state.isFocused
				? "rgba(var(--tblr-primary-rgb), .12)"
				: "transparent",
	}),
	groupHeading: (base) => ({ ...base, color: "var(--tblr-secondary)" }),
	noOptionsMessage: (base) => ({ ...base, color: "var(--tblr-secondary)" }),
};

interface Props {
	id: string;
	label?: string;
	/** comma list of CIDRs, as in RuleFormValues */
	value: string;
	onChange: (value: string) => void;
	entries: PickerEntry[];
	catalog?: AgentIngressCatalog | null;
	multi?: boolean;
	placeholder?: string;
	disabled?: boolean;
}

/**
 * Pick known sources/destinations by name (sites, clients, hosts, networks) or
 * type a free IPv4/CIDR. The value stays a CIDR comma list: whole entries are
 * shown as one chip, everything else as a CIDR chip.
 */
export function CatalogPicker({
	id,
	label,
	value,
	onChange,
	entries,
	catalog,
	multi = true,
	placeholder,
	disabled,
}: Props) {
	const toOption = (e: PickerEntry): PickerOption => ({
		value: e.id,
		label: entryLabel(e, catalog),
		cidrs: e.cidrs.map(canonCidr),
		entry: e,
	});

	const grouped = new Map<GroupId, PickerOption[]>();
	for (const e of entries) {
		const g = groupOf(e);
		if (!grouped.has(g)) grouped.set(g, []);
		grouped.get(g)?.push(toOption(e));
	}
	const options: Group[] = GROUP_ORDER.filter((g) => grouped.has(g)).map((g) => ({
		label: ti(`catalog.group.${g}`),
		options: grouped.get(g) ?? [],
	}));

	const { entries: whole, rest } = collapseCidrs(splitList(value), entries);
	const selected: PickerOption[] = [
		...whole.map(toOption),
		...rest.map((c) => ({ value: `cidr:${c}`, label: shortCidr(c), cidrs: [canonCidr(c)] })),
	];

	const emit = (opts: PickerOption[]) => {
		const out: string[] = [];
		for (const o of opts) {
			for (const c of o.cidrs) if (!out.includes(c)) out.push(c);
		}
		onChange(out.map(shortCidr).join(", "));
	};

	const handleChange = (v: MultiValue<PickerOption> | SingleValue<PickerOption>) => {
		if (Array.isArray(v)) emit(v as PickerOption[]);
		else emit(v ? [v as PickerOption] : []);
	};

	return (
		<CreatableSelect<PickerOption, boolean, Group>
			className="react-select-container"
			classNamePrefix="react-select"
			inputId={id}
			aria-label={label}
			isMulti={multi}
			isClearable={!multi}
			isDisabled={disabled}
			closeMenuOnSelect={!multi}
			options={options}
			value={multi ? selected : (selected[0] ?? null)}
			onChange={handleChange}
			placeholder={placeholder}
			menuPortalTarget={typeof document === "undefined" ? undefined : document.body}
			menuPlacement="auto"
			styles={STYLES}
			noOptionsMessage={() => ti("picker.no-options")}
			isValidNewOption={(input) => isIpv4OrCidr(input.trim())}
			getNewOptionData={(input) => ({
				value: `cidr:${input.trim()}`,
				label: input.trim(),
				cidrs: [canonCidr(input.trim())],
				__isNew__: true,
			})}
			formatCreateLabel={(input) => ti("picker.custom", { value: input.trim() })}
			filterOption={(option, input) => {
				const q = input.trim().toLowerCase();
				if (!q) return true;
				const d = option.data;
				const hay = [d.label, ...(d.entry?.names ?? []), ...(d.entry?.cidrs ?? []), d.entry?.label ?? ""];
				return hay.some((h) => h.toLowerCase().includes(q));
			}}
			formatOptionLabel={(o, meta) =>
				meta.context === "menu" && o.entry ? (
					<div className="d-flex align-items-start gap-2">
						<span className="mt-1">
							<KindIcon kind={o.entry.kind} />
						</span>
						<span className="min-w-0">
							<span className="d-block text-truncate">{o.label}</span>
							<span className="d-block small font-monospace text-secondary text-truncate">
								{o.entry.cidrs.map(shortCidr).join(", ")}
							</span>
							{(o.entry.hint === "snat-hub-lan" || o.entry.hint === "masquerade") && (
								<span className="d-block small text-secondary text-wrap">
									{ti(o.entry.hint === "masquerade" ? "catalog.masquerade-hint" : "catalog.hub-snat-hint")}
								</span>
							)}
						</span>
					</div>
				) : (
					<span className="d-inline-flex align-items-center gap-1">
						{o.entry && <KindIcon kind={o.entry.kind} size={12} />}
						<span className={o.entry ? undefined : "font-monospace"}>{o.label}</span>
					</span>
				)
			}
		/>
	);
}
