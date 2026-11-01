import {
	IconArrowDown,
	IconArrowUp,
	IconCheck,
	IconEye,
	IconEyeOff,
	IconGripVertical,
	IconLayoutDashboard,
	IconRestore,
} from "@tabler/icons-react";
import { type DragEvent, type ReactNode, useMemo, useState } from "react";
import { intl } from "src/locale/IntlProvider";
import { safeLocal } from "src/modules/safeStorage";

export interface DashboardSection {
	id: string;
	node: ReactNode;
	adminOnly?: boolean;
}

interface Layout {
	order: string[];
	hidden: string[];
}

const t = (id: string) => intl.formatMessage({ id });

/** Gespeicherte Anordnung mit den aktuell vorhandenen Blöcken abgleichen (neue Blöcke an ihrer Standardstelle). */
export const mergeLayout = (stored: Partial<Layout> | null, defaults: string[]): Layout => {
	const known = new Set(defaults);
	const order = (Array.isArray(stored?.order) ? stored.order : []).filter((id) => known.has(id));
	for (const id of defaults) {
		if (order.includes(id)) continue;
		// hinter den Vorgänger aus der Standardreihenfolge einsortieren
		const prev = defaults
			.slice(0, defaults.indexOf(id))
			.reverse()
			.find((p) => order.includes(p));
		order.splice(prev ? order.indexOf(prev) + 1 : 0, 0, id);
	}
	const hidden = (Array.isArray(stored?.hidden) ? stored.hidden : []).filter((id) => known.has(id));
	return { order: [...new Set(order)], hidden: [...new Set(hidden)] };
};

const load = (key: string, defaults: string[]): Layout => {
	try {
		return mergeLayout(JSON.parse(safeLocal.get(key) || "null"), defaults);
	} catch {
		return mergeLayout(null, defaults);
	}
};

interface Props {
	sections: DashboardSection[];
	admin: boolean;
	/** pro Benutzer, z. B. fg.dashboard.layout.<userId> */
	storageKey: string;
}

/**
 * Dashboard-Blöcke in einer vom Benutzer gewählten Reihenfolge. „Dashboard anpassen“: ziehen oder Pfeile zum
 * Sortieren, Auge zum Aus-/Einblenden. Gespeichert im Browser (je Benutzer). Außerhalb des Bearbeitens sind die
 * Hüllen `display: contents` – das Seitenlayout bleibt exakt wie ohne Sortierung.
 */
export default function DashboardLayout({ sections, admin, storageKey }: Props) {
	const usable = useMemo(() => sections.filter((s) => !s.adminOnly || admin), [sections, admin]);
	const defaults = useMemo(() => usable.map((s) => s.id), [usable]);
	// Anordnung je Schlüssel: beim ersten Rendern ist der Benutzer oft noch nicht geladen (Schlüssel „anon“) –
	// wechselt der Schlüssel, wird die gespeicherte Anordnung des Benutzers neu gelesen
	const [stored, setStored] = useState<{ key: string; layout: Layout }>(() => ({
		key: storageKey,
		layout: load(storageKey, defaults),
	}));
	if (stored.key !== storageKey) setStored({ key: storageKey, layout: load(storageKey, defaults) });
	const layout = stored.key === storageKey ? stored.layout : load(storageKey, defaults);
	const setLayout = (next: Layout) => setStored({ key: storageKey, layout: next });
	const [editing, setEditing] = useState(false);
	const [dragId, setDragId] = useState<string | null>(null);
	const [overId, setOverId] = useState<string | null>(null);

	const current = mergeLayout(layout, defaults);
	const byId = Object.fromEntries(usable.map((s) => [s.id, s]));
	const persist = (next: Layout) => {
		setLayout(next);
		safeLocal.set(storageKey, JSON.stringify(next));
	};
	const move = (id: string, to: number) => {
		const order = current.order.filter((x) => x !== id);
		order.splice(Math.max(0, Math.min(to, order.length)), 0, id);
		persist({ ...current, order });
	};
	const toggle = (id: string) =>
		persist({
			...current,
			hidden: current.hidden.includes(id) ? current.hidden.filter((x) => x !== id) : [...current.hidden, id],
		});
	const reset = () => {
		safeLocal.remove(storageKey);
		setLayout(mergeLayout(null, defaults));
	};

	const onDrop = (target: string) => (e: DragEvent) => {
		e.preventDefault();
		const id = dragId || e.dataTransfer.getData("text/plain");
		setDragId(null);
		setOverId(null);
		if (!id || id === target) return;
		move(id, current.order.filter((x) => x !== id).indexOf(target));
	};

	return (
		<>
			<div className="fg-dash-tools">
				{editing ? (
					<div className="fg-dash-editbar">
						<span className="small text-secondary">{t("dashboard.layout.hint")}</span>
						<div className="btn-list ms-auto">
							<button type="button" className="btn btn-sm" onClick={reset}>
								<IconRestore size={16} className="me-1" />
								{t("dashboard.layout.reset")}
							</button>
							<button type="button" className="btn btn-sm btn-primary" onClick={() => setEditing(false)}>
								<IconCheck size={16} className="me-1" />
								{t("dashboard.layout.done")}
							</button>
						</div>
					</div>
				) : (
					<button
						type="button"
						className="btn btn-sm btn-ghost-secondary ms-auto"
						onClick={() => setEditing(true)}
					>
						<IconLayoutDashboard size={16} className="me-1" />
						{t("dashboard.layout.customize")}
					</button>
				)}
			</div>

			{current.order.map((id, idx) => {
				const s = byId[id];
				if (!s) return null;
				const hidden = current.hidden.includes(id);
				if (!editing)
					return hidden ? null : (
						<div key={id} className="fg-dash-slot">
							{s.node}
						</div>
					);
				return (
					<section
						key={id}
						className={`fg-dash-item ${hidden ? "is-hidden" : ""} ${dragId === id ? "is-dragging" : ""} ${overId === id && dragId !== id ? "is-over" : ""}`}
						draggable
						onDragStart={(e) => {
							setDragId(id);
							e.dataTransfer.effectAllowed = "move";
							e.dataTransfer.setData("text/plain", id);
						}}
						onDragEnd={() => {
							setDragId(null);
							setOverId(null);
						}}
						onDragOver={(e) => {
							e.preventDefault();
							if (overId !== id) setOverId(id);
						}}
						onDrop={onDrop(id)}
						aria-label={t(`dashboard.section.${id}`)}
					>
						<div className="fg-dash-item-bar">
							<span className="fg-dash-grip" title={t("dashboard.layout.drag")}>
								<IconGripVertical size={18} />
							</span>
							<span className="fw-semibold">{t(`dashboard.section.${id}`)}</span>
							{hidden ? (
								<span className="badge bg-secondary-lt">{t("dashboard.layout.hidden")}</span>
							) : null}
							<div className="btn-list ms-auto">
								<button
									type="button"
									className="btn btn-sm btn-icon"
									disabled={idx === 0}
									onClick={() => move(id, idx - 1)}
									aria-label={t("dashboard.layout.up")}
									title={t("dashboard.layout.up")}
								>
									<IconArrowUp size={16} />
								</button>
								<button
									type="button"
									className="btn btn-sm btn-icon"
									disabled={idx === current.order.length - 1}
									onClick={() => move(id, idx + 1)}
									aria-label={t("dashboard.layout.down")}
									title={t("dashboard.layout.down")}
								>
									<IconArrowDown size={16} />
								</button>
								<button
									type="button"
									className="btn btn-sm btn-icon"
									onClick={() => toggle(id)}
									aria-label={t(hidden ? "dashboard.layout.show" : "dashboard.layout.hide")}
									title={t(hidden ? "dashboard.layout.show" : "dashboard.layout.hide")}
								>
									{hidden ? <IconEye size={16} /> : <IconEyeOff size={16} />}
								</button>
							</div>
						</div>
						{hidden ? null : <div className="fg-dash-item-body">{s.node}</div>}
					</section>
				);
			})}
		</>
	);
}
