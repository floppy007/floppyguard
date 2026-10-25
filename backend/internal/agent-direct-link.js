// Direct links ("Direktverbindungen") — DB, payload and API layer.
// Pure logic (validation, wg-quick config, hooks, status parsing) lives in
// agent-direct-link-rules.js; the model is described there.
//
// The agent payload is computed on every /agent/config poll (nothing is stored
// in config_text), so a changed ACL, a new network on either site, a newly
// reported partner key or a site separation reaches both agents on their next
// poll without a resync trigger. The networks a side routes through the link are
// exactly its hub-side reach (the same computation as its hub peer AllowedIPs,
// passed in by agent.js) restricted to the partner site's own networks.

import { wireguard as logger } from "../logger.js";
import error from "../lib/error.js";
import Agent from "../models/agent.js";
import AgentDirectLink from "../models/agent_direct_link.js";
import AgentIngressRule from "../models/agent_ingress_rule.js";
import SiteIsolation from "../models/site_isolation.js";
import {
	assertDirectLinkFits,
	directIface,
	directPayloadEntry,
	directPeerNets,
	MAX_DIRECT_LINK_ID,
	natRestrictedConflict,
	sanitizeDirectLinkInput,
	sanitizeDirectStatus,
	tunnelAddresses,
} from "./agent-direct-link-rules.js";
import { assertTotalLineCount, rowToRule } from "./agent-ingress-rules.js";
import internalAuditLog from "./audit-log.js";
import internalWireGuard, { canonicalizeIpv4Network, isAcceptableNetworkPrefix } from "./wireguard.js";

const OBJECT_TYPE = "direct-link";

const parseStatus = (raw) => {
	if (!raw) return null;
	try {
		const v = JSON.parse(raw);
		return v && typeof v === "object" ? v : null;
	} catch {
		return null;
	}
};

const pairKey = (x, y) => (x < y ? `${x}|${y}` : `${y}|${x}`);

/**
 * Mesh view used by validation and payloads: site link id per agent (only for
 * an unambiguous, non-client link name), isolation pairs, all site networks.
 */
async function loadMeshContext() {
	const [metadata, pairs] = await Promise.all([
		internalWireGuard.readMetadataStore(),
		SiteIsolation.query().select("link_a", "link_b"),
	]);
	const links = Object.entries(metadata.links || {});
	const byName = new Map();
	for (const [id, l] of links) {
		if (!l?.name) continue;
		byName.set(l.name, byName.has(l.name) ? null : [id, l]);
	}
	const siteLinkOf = (agent) => {
		const hit = agent?.wg_link_name ? byName.get(agent.wg_link_name) : null;
		return hit && hit[1].type !== "client" ? hit : null;
	};
	const isolatedKeys = new Set(pairs.map((p) => pairKey(p.link_a, p.link_b)));
	const siteNets = [
		...new Set(
			links
				.filter(([, l]) => l?.type !== "client")
				.flatMap(([, l]) => l?.importedNetworks || [])
				.filter(isAcceptableNetworkPrefix),
		),
	];
	return {
		siteLinkOf,
		siteLinkIdOf: (agent) => siteLinkOf(agent)?.[0] ?? null,
		isolated: (x, y) => isolatedKeys.has(pairKey(x, y)),
		siteNets,
	};
}

/** Tunnel subnets of the hub tunnel(s) as the agents' Address lines show them. */
function agentTunnelSubnets(agents) {
	const out = new Set();
	for (const a of agents) {
		const m = String(a.config_text || "").match(/^\s*Address\s*=\s*(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})/im);
		if (!m) continue;
		const prefix = Number(m[2]) === 32 ? 24 : Number(m[2]);
		const canon = canonicalizeIpv4Network(`${m[1]}/${prefix}`);
		if (canon) out.add(canon);
	}
	return [...out];
}

async function loadAgentsMap() {
	const agents = await Agent.query()
		.where("is_deleted", 0)
		.select("id", "name", "wg_link_name", "wg_interface", "config_text", "last_seen", "ingress_mode");
	return { agents, byId: new Map(agents.map((a) => [a.id, a])) };
}

async function audit(access, action, link, meta = {}) {
	if (!access) return;
	try {
		await internalAuditLog.add(access, {
			action,
			object_type: OBJECT_TYPE,
			object_id: link.id,
			meta: { name: link.name, ...meta },
		});
	} catch (err) {
		logger.warn(`direct link audit log failed: ${err.message}`);
	}
}

const sideStatus = (row, side, nowS) => {
	const seen = Number(row[`${side}_seen`]) || null;
	return {
		public_key_known: Boolean(row[`${side}_public_key`]),
		seen,
		stale: !seen || nowS - seen > 120,
		...(parseStatus(row[`${side}_status`]) || {}),
	};
};

/** Admin view of one row (no keys, status per side, the address plan). */
function toView(row, byId, ctx, nowS = Math.floor(Date.now() / 1000)) {
	const a = byId.get(row.agent_a_id);
	const b = byId.get(row.agent_b_id);
	const la = ctx.siteLinkIdOf(a);
	const lb = ctx.siteLinkIdOf(b);
	const addrs = tunnelAddresses(row.tunnel_subnet);
	let blocked = null;
	if (!a || !b) blocked = "agent-missing";
	else if (!la || !lb) blocked = "site-link-missing";
	else if (ctx.isolated(la, lb)) blocked = "sites-isolated";
	else if (natRestrictedConflict(row, a, b)) blocked = "nat-restricted";
	return {
		id: row.id,
		name: row.name,
		iface: directIface(row.id),
		agent_a_id: row.agent_a_id,
		agent_b_id: row.agent_b_id,
		agent_a_name: a?.name ?? null,
		agent_b_name: b?.name ?? null,
		listen_port: row.listen_port,
		endpoint_host: row.endpoint_host,
		tunnel_subnet: row.tunnel_subnet,
		address_a: addrs.a,
		address_b: addrs.b,
		mtu: row.mtu ?? null,
		enabled: Boolean(row.enabled),
		nat_a: Boolean(row.nat_a),
		nat_b: Boolean(row.nat_b),
		blocked,
		status_a: sideStatus(row, "a", nowS),
		status_b: sideStatus(row, "b", nowS),
		created_on: row.created_on,
		modified_on: row.modified_on,
	};
}

async function loadRow(id) {
	const row = await AgentDirectLink.query().findById(id);
	if (!row) throw new error.ItemNotFoundError(id);
	return row;
}

async function validateComplete(link, byId, agents) {
	const ctx = await loadMeshContext();
	const others = await AgentDirectLink.query();
	assertDirectLinkFits(link, {
		agents: byId,
		siteLinkIdOf: ctx.siteLinkIdOf,
		isolated: ctx.isolated,
		siteNets: ctx.siteNets,
		agentTunnelSubnets: agentTunnelSubnets(agents),
		others,
	});
	// Every Freigaben line is repeated per direct interface: enabling a link must
	// not push either agent's FG_IN past MAX_LINES_TOTAL (it would stop building,
	// and a restricted agent then gets neither filter nor direct links).
	if (link.enabled) {
		for (const agentId of [link.agent_a_id, link.agent_b_id]) {
			const enabledOthers = others.filter(
				(o) => o.id !== link.id && o.enabled && (o.agent_a_id === agentId || o.agent_b_id === agentId),
			).length;
			const rules = (await AgentIngressRule.query().where("agent_id", agentId)).map(rowToRule);
			assertTotalLineCount(rules, 2 + enabledOthers);
		}
	}
}

const internalDirectLink = {
	async list() {
		const [rows, { byId }, ctx] = await Promise.all([
			AgentDirectLink.query().orderBy("id"),
			loadAgentsMap(),
			loadMeshContext(),
		]);
		return rows.map((r) => toView(r, byId, ctx));
	},

	async create(access, body) {
		const clean = sanitizeDirectLinkInput(body);
		const { agents, byId } = await loadAgentsMap();
		await validateComplete(clean, byId, agents);
		const row = await AgentDirectLink.query().insertAndFetch(clean);
		if (row.id > MAX_DIRECT_LINK_ID) {
			await AgentDirectLink.query().deleteById(row.id);
			throw new error.ValidationError(`direct link ids are limited to ${MAX_DIRECT_LINK_ID}`);
		}
		await audit(access, "created", row, {
			agent_a: byId.get(row.agent_a_id)?.name,
			agent_b: byId.get(row.agent_b_id)?.name,
			enabled: Boolean(row.enabled),
		});
		return toView(row, byId, await loadMeshContext());
	},

	async update(access, id, body) {
		const existing = await loadRow(id);
		const patch = sanitizeDirectLinkInput(body, { partial: true });
		const merged = { ...existing, ...patch, id: existing.id };
		if (merged.agent_a_id === merged.agent_b_id) {
			throw new error.ValidationError("a direct link needs two different agents");
		}
		const { agents, byId } = await loadAgentsMap();
		await validateComplete(merged, byId, agents);
		// A side that moves to another agent must report its own key first.
		for (const side of ["a", "b"]) {
			if (merged[`agent_${side}_id`] !== existing[`agent_${side}_id`]) {
				Object.assign(patch, {
					[`${side}_public_key`]: null,
					[`${side}_status`]: null,
					[`${side}_seen`]: null,
				});
			}
		}
		if (Object.keys(patch).length) await AgentDirectLink.query().patch(patch).where("id", existing.id);
		const row = await loadRow(existing.id);
		await audit(access, "updated", row, {
			fields: Object.keys(patch).filter((k) => !/_(public_key|status|seen)$/.test(k)),
			enabled: Boolean(row.enabled),
		});
		return toView(row, byId, await loadMeshContext());
	},

	/** Agent deleted: its links can never come up again — remove them. */
	async deleteForAgent(agentId) {
		const rows = await AgentDirectLink.query().where((q) =>
			q.where("agent_a_id", agentId).orWhere("agent_b_id", agentId),
		);
		for (const row of rows) {
			await AgentDirectLink.query().deleteById(row.id);
			logger.info(`Direct link ${row.id} (${row.name}) removed with agent ${agentId}`);
		}
	},

	async delete(access, id) {
		const row = await loadRow(id);
		await AgentDirectLink.query().deleteById(row.id);
		await audit(access, "deleted", row);
		return { deleted: true };
	},

	/**
	 * Direct interfaces of an agent's enabled links — its FG_IN filter must cover
	 * them like the hub interface (agent-ingress.js). Sorted for a stable hash.
	 */
	async ifacesFor(agentId) {
		const rows = await AgentDirectLink.query()
			.where("enabled", 1)
			.where((q) => q.where("agent_a_id", agentId).orWhere("agent_b_id", agentId))
			.select("id");
		return rows
			.map((r) => r.id)
			.sort((x, y) => x - y)
			.map(directIface);
	},

	/**
	 * `direct_links` for /agent/config: one entry per link this agent is a side
	 * of. `otherSiteNetsFor(agentRow)` = the agent's hub-side reach (agent.js).
	 */
	async payloadFor(agent, { otherSiteNetsFor }) {
		const rows = await AgentDirectLink.query().where((q) =>
			q.where("agent_a_id", agent.id).orWhere("agent_b_id", agent.id),
		);
		if (!rows.length) return [];
		const [{ byId }, ctx] = await Promise.all([loadAgentsMap(), loadMeshContext()]);
		// the full agent row (ACL columns) — loadAgentsMap selects only a few columns
		const self = agent;
		const out = [];
		for (const row of rows.sort((x, y) => x.id - y.id)) {
			const side = row.agent_a_id === agent.id ? "a" : "b";
			const partner = byId.get(side === "a" ? row.agent_b_id : row.agent_a_id);
			const ownLink = ctx.siteLinkOf(self);
			const partnerLink = ctx.siteLinkOf(partner);
			const active =
				Boolean(row.enabled) &&
				Boolean(partner && ownLink && partnerLink) &&
				ownLink[0] !== partnerLink[0] &&
				!ctx.isolated(ownLink[0], partnerLink[0]) &&
				!natRestrictedConflict(row, side === "a" ? self : partner, side === "a" ? partner : self);
			const peerNets = active
				? directPeerNets(await otherSiteNetsFor(self), partnerLink[1].importedNetworks || [], [
						...(ownLink[1].importedNetworks || []),
						...agentTunnelSubnets([self]),
					])
				: [];
			out.push(
				directPayloadEntry({
					link: { ...row, nat_a: Boolean(row.nat_a), nat_b: Boolean(row.nat_b) },
					side,
					hubIface: /^wg\d{1,3}$/.test(self.wg_interface || "") ? self.wg_interface : "wg0",
					peerPublicKey: side === "a" ? row.b_public_key : row.a_public_key,
					peerNets,
					active,
				}),
			);
		}
		return out;
	},

	/** Heartbeat hook: public keys + health the agent reports per link. */
	async recordStatus(agent, raw) {
		const rows = await AgentDirectLink.query().where((q) =>
			q.where("agent_a_id", agent.id).orWhere("agent_b_id", agent.id),
		);
		if (!rows.length) return;
		const reported = sanitizeDirectStatus(raw, new Set(rows.map((r) => r.id)));
		const now = Math.floor(Date.now() / 1000);
		const knex = AgentDirectLink.knex();
		for (const row of rows) {
			const r = reported.get(row.id);
			if (!r) continue;
			const side = row.agent_a_id === agent.id ? "a" : "b";
			const patch = { [`${side}_status`]: JSON.stringify(r.status), [`${side}_seen`]: now };
			if (r.public_key && r.public_key !== row[`${side}_public_key`]) {
				patch[`${side}_public_key`] = r.public_key;
				logger.info(
					`Direct link ${row.id} (${row.name}): new public key from agent ${agent.name} (side ${side})`,
				);
			}
			// Plain knex update: status bookkeeping must not bump modified_on.
			await knex("agent_direct_link").where("id", row.id).update(patch);
		}
	},
};

export default internalDirectLink;
export const _testExports = { toView, agentTunnelSubnets, loadMeshContext };
