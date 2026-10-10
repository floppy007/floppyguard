// The backend port is reachable from the tunnel: only the agent API (and the
// status probe agents use) may be served to non-loopback clients.
import assert from "node:assert/strict";
import { describe, it } from "node:test";

const { isLoopbackAddress, remoteRequestAllowed } = await import("../lib/express/remote-guard.js");

describe("remote guard", () => {
	it("recognises loopback addresses", () => {
		for (const a of ["127.0.0.1", "::1", "::ffff:127.0.0.1", "127.1.2.3"])
			assert.equal(isLoopbackAddress(a), true, a);
		for (const a of ["10.10.0.1", "::ffff:10.10.0.5", "", undefined, "127.0.0.1.evil"])
			assert.equal(isLoopbackAddress(a), false, String(a));
	});
	it("serves everything to the local nginx", () => {
		assert.equal(remoteRequestAllowed("127.0.0.1", "POST", "/api/tokens"), true);
	});
	it("serves only agent endpoints and the status probe to remote clients", () => {
		assert.equal(remoteRequestAllowed("10.10.0.5", "GET", "/api/agent/config"), true);
		assert.equal(remoteRequestAllowed("10.10.0.5", "POST", "/api/agent/heartbeat"), true);
		assert.equal(remoteRequestAllowed("10.10.0.5", "GET", "/api"), true);
		assert.equal(remoteRequestAllowed("10.10.0.5", "GET", "/api/"), true);
		assert.equal(remoteRequestAllowed("10.10.0.5", "POST", "/api/tokens"), false);
		assert.equal(remoteRequestAllowed("10.10.0.5", "GET", "/api/agents"), false);
		assert.equal(remoteRequestAllowed("10.10.0.5", "GET", "/api/agents/1"), false);
		assert.equal(remoteRequestAllowed("10.10.0.5", "GET", "/api/users"), false);
		assert.equal(remoteRequestAllowed("10.10.0.5", "GET", "/api/oidc/callback"), false);
		assert.equal(remoteRequestAllowed("10.10.0.5", "POST", "/api"), false);
		assert.equal(remoteRequestAllowed("10.10.0.5", "GET", "/api/agent/"), false);
	});
});
