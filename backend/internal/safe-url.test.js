import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { SAFE_HTTP_URL_PATTERN, SAFE_HTTP_URL_REGEX, URL_SAFE_CHARS_REGEX } from "../lib/safe-url.js";
import settingModel from "../models/setting.js";
import internalSetting from "./setting.js";

const here = path.dirname(fileURLToPath(import.meta.url));

test("settings PUT schema meta.redirect pattern equals SAFE_HTTP_URL_PATTERN", () => {
	const schema = JSON.parse(fs.readFileSync(path.join(here, "../schema/paths/settings/settingID/put.json"), "utf8"));
	const redirect = schema.requestBody.content["application/json"].schema.properties.meta.properties.redirect;
	assert.equal(redirect.pattern, SAFE_HTTP_URL_PATTERN);
});

test("safe URL regexes reject shell/nginx metacharacters", () => {
	for (const bad of [
		"http://h/$(id)",
		"http://h;reboot",
		"http://h|cat",
		'http://h"x',
		"http://h x",
		"http://h\nreturn 200;",
		"http://h#x",
		"http://h`id`",
		"http://h\\x",
	]) {
		assert.equal(SAFE_HTTP_URL_REGEX.test(bad), false, bad);
		assert.equal(URL_SAFE_CHARS_REGEX.test(bad), false, bad);
	}
	assert.equal(SAFE_HTTP_URL_REGEX.test("https://proxy.example.com:81/path?x=1"), true);
	assert.equal(SAFE_HTTP_URL_REGEX.test("ftp://h"), false);
});

// default-site guards must judge the state AFTER the patch (meta replaces the stored JSON wholesale)
const withStoredRow = async (row, fn) => {
	const original = settingModel.query;
	const patched = [];
	settingModel.query = () => ({
		where: () => ({
			first: async () => ({ ...row }),
			patch: async (data) => {
				patched.push(data);
				return 1;
			},
		}),
	});
	try {
		await fn(patched);
	} finally {
		settingModel.query = original;
	}
};
const allowAll = { can: async () => true };

test("default-site: meta-only PUT on an 'html' row without meta.html is rejected before patching", async () => {
	await withStoredRow({ id: "default-site", value: "html", meta: { html: "<p>x</p>" } }, async (patched) => {
		await assert.rejects(
			internalSetting.update(allowAll, { id: "default-site", meta: { redirect: "https://x" } }),
			(err) => err.status === 400 && /meta\.html/.test(err.message),
		);
		assert.equal(patched.length, 0);
	});
});

test("default-site: meta-only PUT on a 'redirect' row without a safe redirect is rejected before patching", async () => {
	await withStoredRow(
		{ id: "default-site", value: "redirect", meta: { redirect: "https://ok" } },
		async (patched) => {
			await assert.rejects(
				internalSetting.update(allowAll, { id: "default-site", meta: { html: "x" } }),
				(err) => err.status === 400 && /meta\.redirect/.test(err.message),
			);
			assert.equal(patched.length, 0);
		},
	);
});

test("default-site: switching to 'redirect' still validates the stored redirect", async () => {
	await withStoredRow(
		{ id: "default-site", value: "404", meta: { redirect: "https://h;reboot" } },
		async (patched) => {
			await assert.rejects(
				internalSetting.update(allowAll, { id: "default-site", value: "redirect" }),
				(err) => err.status === 400,
			);
			assert.equal(patched.length, 0);
		},
	);
});
