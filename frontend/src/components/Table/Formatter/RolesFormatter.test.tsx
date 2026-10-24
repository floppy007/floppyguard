import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("src/locale", () => ({ T: ({ id }: { id: string }) => <>{id}</> }));

import { RolesFormatter } from "./RolesFormatter";

describe("RolesFormatter", () => {
	afterEach(() => cleanup());

	it("shows standard-user for an empty role list without mutating the prop", () => {
		const roles: string[] = [];
		const { container } = render(<RolesFormatter roles={roles} />);
		expect(container.textContent).toBe("role.standard-user");
		expect(roles).toEqual([]);
	});

	it("renders the given roles", () => {
		const { container } = render(<RolesFormatter roles={["admin"]} />);
		expect(container.textContent).toBe("role.admin");
	});
});
