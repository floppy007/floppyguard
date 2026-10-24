import express from "express";
import internalWireGuard from "../internal/wireguard.js";
import { auditOnSuccess, describeWireGuardRequest } from "../internal/audit-route.js";
import internalWireGuardPlan, { classifyChangeScope, finishMetadataWrite } from "../internal/wireguard-plan.js";
import error from "../lib/error.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import requireAdmin from "../lib/express/require-admin.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

/**
 * Bound-agent options of a link/interface delete (see internalWireGuard.deletePeer):
 * JSON body fields, or query `deleteBoundAgents=1` / `forceAgentIds=1,2` for the
 * REST DELETE routes. Anything not literally true is false.
 */
function deleteOptions(req) {
	const b = req.body && typeof req.body === "object" ? req.body : {};
	const q = req.query || {};
	const flag = (v) => v === true || v === "1" || v === "true";
	let ids = Array.isArray(b.forceAgentIds) ? b.forceAgentIds : String(q.forceAgentIds || "").split(",");
	ids = ids.map((v) => Number.parseInt(v, 10)).filter((v) => Number.isInteger(v) && v > 0);
	return {
		deleteBoundAgents: flag(b.deleteBoundAgents) || flag(q.deleteBoundAgents),
		forceAgentIds: ids,
		dryRun: b.dryRun === true,
	};
}

// ── Error mapping shared by the RPC routes and their REST aliases ──
const isPeerNotFound = (err) => err?.message?.startsWith("Link not found") || err?.message?.startsWith("Interface");
const isLinkNotFound = (err) => err?.message?.startsWith("Link not found");
const isIfaceExists = (err) => err?.message?.includes("already exists");
const isIfaceNotFound = (err) => /^Interface \S+ not found/.test(err?.message || "");

function failWg(req, next, err, { notFound, invalid } = {}) {
	if (notFound?.(err)) return next(new error.ItemNotFoundError(err.message));
	if (invalid?.(err)) return next(new error.ValidationError(err.message));
	debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
	next(err);
}

/** Trimmed string id, or "" for anything that is not a string (e.g. a JSON number). */
const trimmedId = (v) => (typeof v === "string" ? v.trim() : "");
/** The value if it is a plain object (not null/array), else null. */
const plainObject = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : null);
const bodyLinkId = (req) => req.body?.linkId || req.body?.link_id;

// Every successful WireGuard mutation and peer-config/QR download (key issuance)
// leaves an audit entry: operation, link/interface id and changed field NAMES —
// never key material. Only fires for authenticated (admin) requests.
router.use(auditOnSuccess("wireguard", describeWireGuardRequest));

router
	.route("/status")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			const status = await internalWireGuard.getStatus();
			res.status(200).send(status);
		} catch (err) {
			failWg(req, next, err);
		}
	});

router
	.route("/metadata")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			const status = await internalWireGuard.getStatus();
			res.status(200).send({ mode: status.mode, metadata: status.metadata || { interfaces: {}, links: {} } });
		} catch (err) {
			failWg(req, next, err);
		}
	})
	.put(async (req, res, next) => {
		try {
			const body = plainObject(req.body) || {};
			const interfaces = body.interfaces === undefined ? {} : plainObject(body.interfaces);
			const links = body.links === undefined ? {} : plainObject(body.links);
			if (!interfaces || !links) return next(new error.ValidationError("interfaces and links must be objects"));
			for (const [k, v] of [...Object.entries(interfaces), ...Object.entries(links)]) {
				if (!plainObject(v))
					return next(new error.ValidationError(`Metadata patch for "${k}" must be an object`));
			}
			// Sanitize once: the conflict check, the write and the change classification
			// all run on canonical values. Stored metadata is canonicalized on save
			// ('192.168.10.5/24' → '192.168.10.0/24'), so comparing raw request strings
			// would let host-bit variants slip past.
			const sIfaces = Object.fromEntries(
				Object.entries(interfaces).map(([n, p]) => [n, internalWireGuard.sanitizeInterfaceMetadataPatch(p)]),
			);
			const sLinks = Object.fromEntries(
				Object.entries(links).map(([id, p]) => [id, internalWireGuard.sanitizeLinkMetadataPatch(p)]),
			);

			const preStatus = await internalWireGuard.getStatus();
			// Only live interfaces/links may receive metadata (same rule as
			// buildPlanPreview / apply-metadata). A key for a non-existent peer
			// would create a ghost store entry that _collectSiteNetworks counts as
			// a site and advertises fleet-wide on the sync below.
			const liveIf = new Set((preStatus.interfaces || []).map((i) => i.name));
			const liveLinks = new Set((preStatus.links || []).map((l) => l.id));
			const unknown = [
				...Object.keys(sIfaces)
					.filter((n) => !liveIf.has(n))
					.map((n) => `Unknown interface "${n}"`),
				...Object.keys(sLinks)
					.filter((id) => !liveLinks.has(id))
					.map((id) => `Unknown link "${id}"`),
			];
			if (unknown.length > 0) {
				return next(new error.ValidationError(unknown.join("; ")));
			}

			// ── Pre-save conflict check ──────────────────────────────────
			// Project the metadata after applying the patch, then check for
			// subnet conflicts between non-client peers.
			const currentMeta = preStatus.metadata || { interfaces: {}, links: {} };
			// Peers that exist in the conf but have no store entry (legacy / hand-edited)
			// still own their AllowedIPs on the hub, yet they are invisible to the store.
			// Seed them from the live status (importedNetworks = their non-host private
			// AllowedIPs, see buildLinkRecord) so a patched link cannot claim a net such a
			// peer already routes — mirrors updatePeer/createPeer/plan-preview, which all
			// check against status.links. Their type is deliberately left unset: it is only
			// inferred (a single-/24 site peer on wg0 classifies as "client") and
			// findLinkNetworkConflicts must only exempt EXPLICIT clients.
			const projectedLinks = {};
			for (const l of preStatus.links || []) {
				if (currentMeta.links?.[l.id]) continue;
				projectedLinks[l.id] = { name: l.name, importedNetworks: l.importedNetworks || [] };
			}
			Object.assign(projectedLinks, currentMeta.links);
			for (const [id, patch] of Object.entries(sLinks)) {
				projectedLinks[id] = { ...(projectedLinks[id] || {}), ...patch };
			}
			// CIDR overlap (not string equality): a /16 over another site's /24
			// steals part of its traffic just like an identical net. Only pairs
			// involving a patched link count, so an old overlap does not block an
			// unrelated save.
			const conflicts = internalWireGuard.findLinkNetworkConflicts(projectedLinks, Object.keys(sLinks));
			if (conflicts.length > 0) {
				return next(new error.ValidationError(`AllowedIPs conflict: ${conflicts.join("; ")}`));
			}

			// One locked write for the whole patch: either every entry is written or
			// none is (a per-entry write left a half-applied store with no sync when a
			// later entry failed the name check).
			const { store: written, previous } = await internalWireGuard.applyMetadataPatch(
				{ interfaces: sIfaces, links: sLinks },
				{
					withPrevious: true,
					validate: (s) => {
						// Check the PROJECTED store: per-entry assertUniqueLinkName against the
						// pre-write store lets two links renamed to the same name in one patch
						// both through (no stored link has it yet) and falsely rejects a swap.
						// Effective name = stored name, else the generated `${type}-${pubkey8}`
						// (buildLinkRecord) — so a cleared name projects the generated one, not
						// the old live name (same rule as buildPlanPreview). Only pairs
						// involving a patched link block the save.
						const projected = { ...(s.links || {}) };
						for (const [id, p] of Object.entries(sLinks))
							projected[id] = { ...(projected[id] || {}), ...p };
						const live = new Map((preStatus.links || []).map((l) => [l.id, l]));
						const effectiveName = (id) => {
							const l = live.get(id);
							if (projected[id]?.name) return projected[id].name;
							if (l?.peerPublicKey)
								return `${projected[id]?.type || l.type}-${l.peerPublicKey.slice(0, 8)}`;
							return l?.name;
						};
						const owner = new Map(); // name → link id
						for (const id of new Set([...live.keys(), ...Object.keys(projected)])) {
							const name = effectiveName(id);
							if (!name) continue;
							const other = owner.get(name);
							if (other !== undefined && (Object.hasOwn(sLinks, id) || Object.hasOwn(sLinks, other))) {
								throw new error.ValidationError(
									`A link named "${name}" already exists — choose a unique name`,
								);
							}
							owner.set(name, id);
						}
					},
				},
			);
			// ── Post-save: drop cached peer configs, cascade renames to agent bindings
			// (wg_link_name / allowed_sites), then sync live WG config + agents ──
			// Same definition of "config-relevant" as apply-metadata, on the SANITIZED
			// patch (hasOwn semantics: {importedNetworks: null} is stored as [] = all
			// nets revoked, and must sync). `name` counts too: a rename with no resync
			// leaves bound agents frozen on their last config.
			const toDiff = (map) => Object.values(map).map((p) => ({ changedFields: Object.keys(p) }));
			const hasConfigChange =
				classifyChangeScope({ interfaces: toDiff(sIfaces), links: toDiff(sLinks) }) ===
				"metadata-with-config-intent";
			const { renameCascade, hubSync, agentSync, status } = await finishMetadataWrite({
				previous,
				written,
				statusBefore: preStatus,
				syncConfig: hasConfigChange,
			});
			res.status(200).send({
				saved: true,
				hubSync,
				agentSync,
				renameCascade,
				metadata: status.metadata || { interfaces: {}, links: {} },
			});
		} catch (err) {
			failWg(req, next, err);
		}
	});

router
	.route("/plan-preview")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(async (req, res, next) => {
		try {
			const preview = await internalWireGuardPlan.previewPlan(req.body || {});
			res.status(200).send(preview);
		} catch (err) {
			failWg(req, next, err);
		}
	});

router
	.route("/apply-metadata")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(async (req, res, next) => {
		try {
			const result = await internalWireGuardPlan.applyMetadata(req.body || {});
			res.status(200).send(result);
		} catch (err) {
			failWg(req, next, err, { invalid: (e) => e?.code === "preview-invalid" || e?.code === "apply-blocked" });
		}
	});

router
	.route("/apply-state")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			const state = await internalWireGuardPlan.getApplyState();
			res.status(200).send(state);
		} catch (err) {
			failWg(req, next, err);
		}
	});

router
	.route("/link-config")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			const { filename, content } = await internalWireGuard.generatePeerConfig(req.query.link_id);
			res.setHeader("Content-Type", "text/plain; charset=utf-8");
			res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
			res.status(200).send(content);
		} catch (err) {
			failWg(req, next, err, { notFound: isLinkNotFound });
		}
	});

router
	.route("/link-config-qr")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			const png = await internalWireGuard.generatePeerConfigQr(req.query.link_id);
			res.setHeader("Content-Type", "image/png");
			res.status(200).send(png);
		} catch (err) {
			failWg(req, next, err, { notFound: isLinkNotFound });
		}
	});

router
	.route("/bandwidth")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.get(async (req, res, next) => {
		try {
			const range = typeof req.query.range === "string" ? req.query.range : "live";
			if (!["live", "24h", "30d", "12m"].includes(range))
				return next(new error.ValidationError("Invalid bandwidth range"));
			const data = await internalWireGuard.getBandwidth(range);
			res.status(200).send(data);
		} catch (err) {
			failWg(req, next, err);
		}
	});

// ── Peer / interface handlers (mounted on the RPC routes and the REST aliases) ──

const createPeerHandler = async (req, res, next) => {
	try {
		const { name, type, dns, fullTunnel, platform, importedNetworks, ifaceName } = req.body || {};
		if (typeof name !== "string" || !name.trim()) {
			next(new error.ValidationError("Name is required"));
			return;
		}
		const result = await internalWireGuard.createPeer({
			name: name.trim(),
			type: type || "client",
			dns: dns || [],
			fullTunnel: Boolean(fullTunnel),
			platform: platform || undefined,
			importedNetworks: importedNetworks || [],
			ifaceName: ifaceName || "wg0",
		});
		res.status(201).send(result);
	} catch (err) {
		failWg(req, next, err);
	}
};

const createInterfaceHandler = async (req, res, next) => {
	try {
		const { name, address, listenPort, role } = req.body || {};
		if (typeof address !== "string" || !address.trim()) {
			next(new error.ValidationError("address is required (e.g. 10.20.0.1/24)"));
			return;
		}
		const result = await internalWireGuard.createInterface({
			name: typeof name === "string" && name.trim() ? name.trim() : undefined,
			address: address.trim(),
			// Empty → auto-assign; anything else (incl. NaN) goes to createInterface, which
			// rejects non-integers instead of silently auto-assigning.
			listenPort:
				listenPort === undefined || listenPort === null || listenPort === "" ? undefined : Number(listenPort),
			role: role || undefined,
		});
		res.status(201).send(result);
	} catch (err) {
		failWg(req, next, err, { invalid: isIfaceExists });
	}
};

const updatePeerHandler = (getId) => async (req, res, next) => {
	try {
		const { linkId: _lid1, link_id: _lid2, ...changes } = req.body || {};
		const linkId = trimmedId(getId(req));
		if (!linkId) return next(new error.ValidationError("linkId is required"));
		res.status(200).send(await internalWireGuard.updatePeer(linkId, changes));
	} catch (err) {
		failWg(req, next, err, { notFound: isPeerNotFound });
	}
};

// The REST DELETE aliases never dry-run (dryRun is an RPC-only body flag).
const deletePeerHandler =
	(getId, { allowDryRun }) =>
	async (req, res, next) => {
		try {
			const linkId = trimmedId(getId(req));
			if (!linkId) return next(new error.ValidationError("linkId is required"));
			const opts = allowDryRun ? deleteOptions(req) : { ...deleteOptions(req), dryRun: false };
			res.status(200).send(await internalWireGuard.deletePeer(linkId, opts));
		} catch (err) {
			failWg(req, next, err, { notFound: isPeerNotFound });
		}
	};

const deleteInterfaceHandler =
	(getName, { allowDryRun }) =>
	async (req, res, next) => {
		try {
			const name = trimmedId(getName(req));
			if (!name) return next(new error.ValidationError("name is required"));
			const opts = allowDryRun ? deleteOptions(req) : { ...deleteOptions(req), dryRun: false };
			res.status(200).send(await internalWireGuard.deleteInterface(name, opts));
		} catch (err) {
			failWg(req, next, err, { notFound: isIfaceNotFound });
		}
	};

router
	.route("/create-peer")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(createPeerHandler);

router
	.route("/create-interface")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(createInterfaceHandler);

router
	.route("/delete-interface")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(deleteInterfaceHandler((req) => req.body?.name, { allowDryRun: true }));

router
	.route("/delete-peer")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(deletePeerHandler(bodyLinkId, { allowDryRun: true }));

router
	.route("/update-peer")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(updatePeerHandler(bodyLinkId));

router
	.route("/restore-metadata")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(async (req, res, next) => {
		try {
			const result = await internalWireGuardPlan.restoreMetadataBackup(req.body?.backupPath);
			res.status(200).send(result);
		} catch (err) {
			failWg(req, next, err, {
				invalid: (e) => e?.code === "restore-invalid-backup" || e?.code === "restore-unavailable",
			});
		}
	});

// ── RESTful aliases ──────────────────────────────────────────────────────────
// Proper REST endpoints alongside the legacy RPC-style routes above; they share
// the handlers, only the id source differs.

router
	.route("/peers")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(createPeerHandler);

router
	.route("/peers/:linkId")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.put(updatePeerHandler((req) => req.params.linkId))
	.delete(deletePeerHandler((req) => req.params.linkId, { allowDryRun: false }));

router
	.route("/interfaces")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.post(createInterfaceHandler);

router
	.route("/interfaces/:name")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.all(requireAdmin())
	.delete(deleteInterfaceHandler((req) => req.params.name, { allowDryRun: false }));

export default router;
