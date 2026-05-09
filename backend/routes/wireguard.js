import express from "express";
import internalWireGuard from "../internal/wireguard.js";
import internalWireGuardPlan from "../internal/wireguard-plan.js";
import error from "../lib/error.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

router
	.route("/status")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const status = await internalWireGuard.getStatus();
			res.status(200).send(status);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/metadata")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const status = await internalWireGuard.getStatus();
			res.status(200).send({ mode: status.mode, metadata: status.metadata || { interfaces: {}, links: {} } });
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	})
	.put(async (req, res, next) => {
		try {
			const { interfaces = {}, links = {} } = req.body || {};
			for (const [name, patch] of Object.entries(interfaces)) {
				await internalWireGuard.updateInterfaceMetadata(name, patch);
			}
			for (const [id, patch] of Object.entries(links)) {
				await internalWireGuard.updateLinkMetadata(id, patch);
			}
			const status = await internalWireGuard.getStatus();
			res.status(200).send({ saved: true, metadata: status.metadata || { interfaces: {}, links: {} } });
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/plan-preview")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const preview = await internalWireGuardPlan.previewPlan(req.body || {});
			res.status(200).send(preview);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/apply-metadata")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const result = await internalWireGuardPlan.applyMetadata(req.body || {});
			res.status(200).send(result);
		} catch (err) {
			if (err?.code === "preview-invalid" || err?.code === "apply-blocked") {
				next(new error.ValidationError(err.message));
				return;
			}
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/apply-state")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const state = await internalWireGuardPlan.getApplyState();
			res.status(200).send(state);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/link-config")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const { filename, content } = await internalWireGuard.generatePeerConfig(req.query.link_id);
			res.setHeader("Content-Type", "text/plain; charset=utf-8");
			res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
			res.status(200).send(content);
		} catch (err) {
			if (err?.message?.startsWith("Link not found")) {
				next(new error.ItemNotFoundError(err.message));
				return;
			}
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/link-config-qr")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const png = await internalWireGuard.generatePeerConfigQr(req.query.link_id);
			res.setHeader("Content-Type", "image/png");
			res.status(200).send(png);
		} catch (err) {
			if (err?.message?.startsWith("Link not found")) {
				next(new error.ItemNotFoundError(err.message));
				return;
			}
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/bandwidth")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.get(async (req, res, next) => {
		try {
			const data = await internalWireGuard.getBandwidth();
			res.status(200).send(data);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/create-peer")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const { name, type, dns, fullTunnel, platform, importedNetworks, ifaceName } = req.body || {};
			if (!name?.trim()) {
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
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/create-interface")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const { name, address, listenPort, role } = req.body || {};
			if (!address?.trim()) {
				next(new error.ValidationError("address is required (e.g. 10.20.0.1/24)"));
				return;
			}
			const result = await internalWireGuard.createInterface({
				name: name?.trim() || undefined,
				address: address.trim(),
				listenPort: listenPort ? Number(listenPort) : undefined,
				role: role || undefined,
			});
			res.status(201).send(result);
		} catch (err) {
			if (err?.message?.includes("already exists")) {
				next(new error.ValidationError(err.message));
				return;
			}
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/delete-interface")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const { name } = req.body || {};
			if (!name?.trim()) {
				next(new error.ValidationError("name is required"));
				return;
			}
			const result = await internalWireGuard.deleteInterface(name.trim());
			res.status(200).send(result);
		} catch (err) {
			if (err?.message?.includes("not found") || err?.message?.includes("Cannot delete")) {
				next(new error.ValidationError(err.message));
				return;
			}
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/delete-peer")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const { linkId } = req.body || {};
			if (!linkId?.trim()) {
				next(new error.ValidationError("linkId is required"));
				return;
			}
			const result = await internalWireGuard.deletePeer(linkId.trim());
			res.status(200).send(result);
		} catch (err) {
			if (err?.message?.startsWith("Link not found") || err?.message?.startsWith("Interface")) {
				next(new error.ItemNotFoundError(err.message));
				return;
			}
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/update-peer")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const { linkId, ...changes } = req.body || {};
			if (!linkId?.trim()) {
				next(new error.ValidationError("linkId is required"));
				return;
			}
			const result = await internalWireGuard.updatePeer(linkId.trim(), changes);
			res.status(200).send(result);
		} catch (err) {
			if (err?.message?.startsWith("Link not found") || err?.message?.startsWith("Interface")) {
				next(new error.ItemNotFoundError(err.message));
				return;
			}
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/restore-metadata")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())
	.post(async (req, res, next) => {
		try {
			const result = await internalWireGuardPlan.restoreMetadataBackup(req.body?.backupPath);
			res.status(200).send(result);
		} catch (err) {
			if (err?.code === "restore-invalid-backup") {
				next(new error.ValidationError(err.message));
				return;
			}
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
