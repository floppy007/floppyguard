import { ACCESS_LISTS, ADMIN, CERTIFICATES, VIEW } from "src/modules/Permissions";
import { describe, expect, it } from "vitest";
import { filterMenu } from "./SiteMenu";

const settings = {
	label: "settings",
	items: [
		{ to: "/access", label: "access-lists", permissionSection: ACCESS_LISTS, permission: VIEW },
		{ to: "/certificates", label: "certificates", permissionSection: CERTIFICATES, permission: VIEW },
		{ to: "/users", label: "users", permissionSection: ADMIN },
	],
} as const;
const menu = [{ to: "/", label: "dashboard" }, settings] as any;

describe("filterMenu", () => {
	it("drops a dropdown group whose sub-items are all hidden", () => {
		const perms = { accessLists: "hidden", certificates: "hidden" } as any;
		expect(filterMenu(menu, perms, ["user"]).map((i) => i.label)).toEqual(["dashboard"]);
	});

	it("keeps only the visible sub-items for a standard user", () => {
		const perms = { accessLists: "view", certificates: "hidden" } as any;
		const out = filterMenu(menu, perms, ["user"]);
		expect(out.find((i) => i.label === "settings")?.items?.map((i) => i.label)).toEqual(["access-lists"]);
	});

	it("shows everything to an admin", () => {
		const out = filterMenu(menu, {} as any, ["admin"]);
		expect(out.find((i) => i.label === "settings")?.items).toHaveLength(3);
	});

	it("hides permission-gated entries while the user is still loading", () => {
		expect(filterMenu(menu, undefined, undefined).map((i) => i.label)).toEqual(["dashboard"]);
	});
});
