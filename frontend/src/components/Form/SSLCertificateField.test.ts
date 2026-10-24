import { describe, expect, it, vi } from "vitest";
import { resetDependentSslFields } from "./SSLCertificateField";

const dnsValues = () => ({
	sslForced: true,
	http2Support: true,
	hstsEnabled: false,
	hstsSubdomains: false,
	meta: {
		dnsChallenge: true,
		dnsProvider: "cloudflare",
		dnsProviderCredentials: "dns_cloudflare_api_token = secret",
		propagationSeconds: 30,
	},
});

describe("resetDependentSslFields", () => {
	it("clears the DNS challenge fields under meta.* when switching to an existing certificate", () => {
		const set = vi.fn();
		resetDependentSslFields(dnsValues(), 5, true, set);
		expect(set).toHaveBeenCalledWith("meta.dnsChallenge", undefined);
		expect(set).toHaveBeenCalledWith("meta.dnsProvider", undefined);
		expect(set).toHaveBeenCalledWith("meta.dnsProviderCredentials", undefined);
		expect(set).toHaveBeenCalledWith("meta.propagationSeconds", undefined);
		// an existing cert keeps the HTTP/SSL toggles
		expect(set).not.toHaveBeenCalledWith("sslForced", false);
	});

	it("keeps the DNS fields while a new certificate is requested", () => {
		const set = vi.fn();
		resetDependentSslFields(dnsValues(), "new", true, set);
		expect(set).not.toHaveBeenCalled();
	});

	it("drops SSL toggles and DNS fields when the certificate is removed", () => {
		const set = vi.fn();
		resetDependentSslFields(dnsValues(), null, true, set);
		expect(set).toHaveBeenCalledWith("sslForced", false);
		expect(set).toHaveBeenCalledWith("http2Support", false);
		expect(set).toHaveBeenCalledWith("meta.dnsProviderCredentials", undefined);
	});

	it("tolerates values without meta", () => {
		const set = vi.fn();
		resetDependentSslFields({}, 5, true, set);
		expect(set).not.toHaveBeenCalled();
	});
});
