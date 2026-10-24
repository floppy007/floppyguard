import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("src/context", () => ({ useLocaleState: () => ({ locale: "en" }) }));
vi.mock("src/locale", () => ({ T: ({ id }: { id: string }) => <>{id}</>, formatDateTime: (v: string) => v }));

import { DomainsFormatter } from "./DomainsFormatter";

describe("DomainsFormatter", () => {
	afterEach(() => cleanup());

	it("opens domain links in a new tab without handing window.opener to the target", () => {
		const { container } = render(<DomainsFormatter domains={["a.example.com"]} />);
		const link = container.querySelector("a");
		expect(link?.getAttribute("href")).toBe("http://a.example.com");
		expect(link?.getAttribute("target")).toBe("_blank");
		expect(link?.getAttribute("rel")).toContain("noopener");
	});
});
