import express from "express";
import internalWireGuard from "../internal/wireguard.js";
import internalWireGuardPlan from "../internal/wireguard-plan.js";
import error from "../lib/error.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });

router.route("/status")
	.options((_, res) => { res.sendStatus(204); })
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

router.route("/metadata")
	.options((_, res) => { res.sendStatus(204); })
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

router.route("/plan-preview")
	.options((_, res) => { res.sendStatus(204); })
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

router.route("/apply-metadata")
	.options((_, res) => { res.sendStatus(204); })
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

router.route("/apply-state")
	.options((_, res) => { res.sendStatus(204); })
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

router.route("/restore-metadata")
	.options((_, res) => { res.sendStatus(204); })
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
