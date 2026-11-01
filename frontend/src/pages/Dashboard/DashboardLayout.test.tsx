import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import DashboardLayout, { mergeLayout } from "./DashboardLayout";

const sections = [
	{ id: "stats", node: <div>STATS</div> },
	{ id: "gateway", node: <div>GATEWAY</div>, adminOnly: true },
	{ id: "geo", node: <div>GEO</div>, adminOnly: true },
	{ id: "hosts", node: <div>HOSTS</div> },
];
const KEY = "fg.dashboard.layout.test";
const texts = () => [...document.querySelectorAll(".fg-dash-slot, .fg-dash-item")].map((n) => n.textContent || "");

describe("mergeLayout", () => {
	it("behält gespeicherte Reihenfolge, setzt neue Blöcke an ihre Standardstelle, wirft Unbekanntes raus", () => {
		const r = mergeLayout({ order: ["hosts", "stats", "alt"], hidden: ["alt", "stats"] }, [
			"stats",
			"gateway",
			"geo",
			"hosts",
		]);
		expect(r.order).toEqual(["hosts", "stats", "gateway", "geo"]);
		expect(r.hidden).toEqual(["stats"]);
		expect(mergeLayout(null, ["a", "b"]).order).toEqual(["a", "b"]);
	});
});

describe("DashboardLayout", () => {
	beforeEach(() => localStorage.clear());
	afterEach(cleanup);

	it("zeigt Admin-Blöcke nur Admins", () => {
		render(<DashboardLayout sections={sections} admin={false} storageKey={KEY} />);
		expect(screen.queryByText("GATEWAY")).toBeNull();
		expect(screen.getByText("STATS")).toBeTruthy();
	});

	it("sortiert per Pfeil, blendet aus und merkt sich das je Schlüssel", () => {
		const { unmount } = render(<DashboardLayout sections={sections} admin storageKey={KEY} />);
		fireEvent.click(screen.getByRole("button", { name: /anpassen|customize/i }));
		const down = screen.getAllByRole("button", { name: /nach unten|down/i });
		fireEvent.click(down[0]); // stats eins runter
		const hide = screen.getAllByRole("button", { name: /ausblenden|hide/i });
		fireEvent.click(hide[hide.length - 1]); // hosts aus
		fireEvent.click(screen.getByRole("button", { name: /fertig|done/i }));
		expect(texts()).toEqual(["GATEWAY", "STATS", "GEO"]);
		unmount();
		render(<DashboardLayout sections={sections} admin storageKey={KEY} />);
		expect(texts()).toEqual(["GATEWAY", "STATS", "GEO"]);
		expect(JSON.parse(localStorage.getItem(KEY) || "{}").hidden).toEqual(["hosts"]);
	});

	it("Zurücksetzen stellt die Standardreihenfolge her", () => {
		localStorage.setItem(KEY, JSON.stringify({ order: ["hosts", "geo", "gateway", "stats"], hidden: ["geo"] }));
		render(<DashboardLayout sections={sections} admin storageKey={KEY} />);
		expect(texts()).toEqual(["HOSTS", "GATEWAY", "STATS"]);
		fireEvent.click(screen.getByRole("button", { name: /anpassen|customize/i }));
		fireEvent.click(screen.getByRole("button", { name: /zurücksetzen|reset/i }));
		fireEvent.click(screen.getByRole("button", { name: /fertig|done/i }));
		expect(texts()).toEqual(["STATS", "GATEWAY", "GEO", "HOSTS"]);
	});

	it("liest die Anordnung neu, wenn der Benutzer erst nach dem ersten Rendern bekannt ist", () => {
		localStorage.setItem(
			"fg.dashboard.layout.7",
			JSON.stringify({ order: ["hosts", "stats", "gateway", "geo"], hidden: [] }),
		);
		const { rerender } = render(
			<DashboardLayout sections={sections} admin storageKey="fg.dashboard.layout.anon" />,
		);
		expect(texts()[0]).toBe("STATS");
		rerender(<DashboardLayout sections={sections} admin storageKey="fg.dashboard.layout.7" />);
		expect(texts()).toEqual(["HOSTS", "STATS", "GATEWAY", "GEO"]);
	});
});
