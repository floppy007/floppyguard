import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AuditLog } from "src/api/backend";
import { EventFormatter } from "./EventFormatter";

vi.mock("src/context", () => ({ useLocaleState: () => ({ locale: "en" }) }));

const row = (over: Partial<AuditLog>): AuditLog =>
	({
		id: 1,
		createdOn: "2026-10-10T08:00:00.000Z",
		modifiedOn: "2026-10-10T08:00:00.000Z",
		userId: 1,
		objectType: "proxy-host",
		objectId: 1,
		action: "created",
		meta: {},
		...over,
	}) as AuditLog;

describe("EventFormatter", () => {
	afterEach(() => cleanup());

	it("renders an app-update row without object_type (formatMessage must not get an empty id)", () => {
		render(
			<EventFormatter
				row={row({ objectType: "", action: "floppyguard.update", meta: { source: "admin-ui" } })}
			/>,
		);
		expect(screen.getByText(/Started application update/)).toBeTruthy();
		expect(screen.getByText("FloppyGuard")).toBeTruthy();
	});

	it("renders the new app-update row with object_type floppyguard", () => {
		render(<EventFormatter row={row({ objectType: "floppyguard", action: "floppyguard.update" })} />);
		expect(screen.getByText(/Started application update/)).toBeTruthy();
	});

	it("does not throw for any other row with an empty object_type", () => {
		render(<EventFormatter row={row({ objectType: "", action: "updated", meta: { name: "x" } })} />);
		expect(screen.getByText("x")).toBeTruthy();
	});
});
