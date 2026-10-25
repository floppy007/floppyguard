import { type DirectLink, type DirectLinkSideStatus, directLinkBody } from "src/api/backend";
import { describe, expect, it } from "vitest";
import { agentLanIp, directLinkState, suggestTunnelSubnet } from "./DirectLinks";

const side = (over: Partial<DirectLinkSideStatus> = {}): DirectLinkSideStatus => ({
	publicKeyKnown: true,
	seen: 1,
	stale: false,
	up: true,
	path: "direct",
	...over,
});

const link = (over: Partial<DirectLink> = {}): DirectLink => ({
	id: 1,
	name: "Floppy ↔ Hinderlich",
	iface: "fgd1",
	agentAId: 2,
	agentBId: 1,
	agentAName: "Hinderlich Office",
	agentBName: "Floppy Home Gateway",
	listenPort: 51830,
	endpointHost: "203.0.113.10",
	tunnelSubnet: "10.10.9.0/30",
	addressA: "10.10.9.1",
	addressB: "10.10.9.2",
	mtu: 1300,
	enabled: true,
	natA: false,
	natB: true,
	blocked: null,
	statusA: side(),
	statusB: side(),
	createdOn: 0,
	modifiedOn: 0,
	...over,
});

describe("direct links helpers", () => {
	it("derives the overall state from both sides", () => {
		expect(directLinkState(link())).toBe("direct");
		expect(directLinkState(link({ enabled: false }))).toBe("off");
		expect(directLinkState(link({ blocked: "sites-isolated" }))).toBe("blocked");
		expect(directLinkState(link({ statusB: side({ publicKeyKnown: false }) }))).toBe("waiting");
		expect(directLinkState(link({ statusA: side({ stale: true }) }))).toBe("waiting");
		expect(directLinkState(link({ statusA: side({ path: "hub" }) }))).toBe("partly");
		expect(directLinkState(link({ statusA: side({ path: "hub" }), statusB: side({ path: "hub" }) }))).toBe("hub");
	});

	it("reads the agent LAN IP from the reported hostname", () => {
		expect(agentLanIp({ hostname: "VM-Docker (192.168.20.7)" })).toBe("192.168.20.7");
		expect(agentLanIp({ hostname: "gw" })).toBeNull();
		expect(agentLanIp(undefined)).toBeNull();
	});

	it("suggests the first free /30", () => {
		expect(suggestTunnelSubnet([])).toBe("10.10.9.0/30");
		expect(suggestTunnelSubnet([{ tunnelSubnet: "10.10.9.0/30" }, { tunnelSubnet: "10.10.9.8/30" }])).toBe(
			"10.10.9.4/30",
		);
	});

	it("sends the agent ids under the keys the backend reads", () => {
		const decamelize = (v: string) => v.replace(/([a-z\d])([A-Z])/g, "$1_$2").toLowerCase();
		const body = directLinkBody({ agentAId: 2, agentBId: 1, natA: true, endpointHost: "h", listenPort: 51830 });
		const keys = Object.keys(body).map(decamelize).sort();
		expect(keys).toEqual(["agent_a_id", "agent_b_id", "endpoint_host", "listen_port", "nat_a"]);
		expect(directLinkBody({ enabled: false })).toEqual({ enabled: false });
	});
});
