// Custom certificate upload: CN parsing and the missing-key guard.
import assert from "node:assert/strict";
import { afterEach, describe, it } from "node:test";

const { default: utils } = await import("../lib/utils.js");
const { default: errs } = await import("../lib/error.js");
const { default: internalCertificate } = await import("./certificate.js");

const DATES = "notBefore=Jul 14 04:04:29 2026 GMT\nnotAfter=Oct 12 04:04:29 2099 GMT\n";

describe("getCertificateInfoFromFile", () => {
	const origExec = utils.execFile;
	afterEach(() => {
		utils.execFile = origExec;
	});
	const parse = async (output) => {
		utils.execFile = async () => output;
		return internalCertificate.getCertificateInfoFromFile("/nonexistent.pem");
	};

	it("takes the CN attribute, not the first RDN of the subject", async () => {
		for (const subject of [
			"subject=C=DE, O=Example GmbH, CN=www.example.de",
			"subject=C = DE, O = Example GmbH, CN = www.example.de",
			"subject=CN = www.example.de",
		]) {
			const info = await parse(`${subject}\nissuer=C = US, O = Let's Encrypt, CN = E5\n${DATES}`);
			assert.equal(info.cn, "www.example.de", subject);
		}
	});

	// OpenSSL 1.1 prints "CN = x", OpenSSL 3.x (3.5 on the hub) "CN=x"; the old
	// /[^=]+=\s+(\S+)/ needed whitespace after "=" and stored domain_names [null].
	it("parses the CN of OpenSSL 1.0, 1.1 and 3.x subject lines", async () => {
		for (const subject of [
			"subject=CN=proxy.comnic.de", // OpenSSL 3.x
			"subject=CN = proxy.comnic.de", // OpenSSL 1.1
			"subject= /CN=proxy.comnic.de", // OpenSSL 1.0
			"subject=C=DE, ST=Berlin, O=comnic, CN=proxy.comnic.de", // 3.x, several RDNs
			"subject=C = DE, ST = Berlin, O = comnic, CN = proxy.comnic.de", // 1.1, several RDNs
			"subject= /C=DE/O=comnic/CN=proxy.comnic.de", // 1.0, several RDNs
		]) {
			const info = await parse(`${subject}\nissuer=CN=R11\n${DATES}`);
			assert.equal(info.cn, "proxy.comnic.de", subject);
		}
	});

	it("never yields an empty or null CN", async () => {
		for (const subject of ["subject=CN=", "subject=CN = ", "subject=O=Example"]) {
			const info = await parse(`${subject}\nissuer=CN=R11\n${DATES}`);
			assert.equal(info.cn, undefined, subject);
		}
	});

	it("falls back to the first DNS SAN when the subject has no CN", async () => {
		const info = await parse(
			`subject=O = Example GmbH\nissuer=CN = Some CA\n${DATES}X509v3 Subject Alternative Name: \n    DNS:a.example.de, DNS:b.example.de, IP Address:10.0.0.1\n`,
		);
		assert.equal(info.cn, "a.example.de");
		assert.ok(info.dates.to > info.dates.from);
	});
});

describe("upload", () => {
	const orig = {
		get: internalCertificate.get,
		validate: internalCertificate.validate,
		update: internalCertificate.update,
		writeCustomCert: internalCertificate.writeCustomCert,
	};
	afterEach(() => Object.assign(internalCertificate, orig));

	it("rejects a certificate without a key before touching the DB or disk", async () => {
		const calls = [];
		internalCertificate.get = async () => ({ id: 3, provider: "other", meta: {} });
		internalCertificate.validate = async () => ({ certificate: { cn: "x.example", dates: { from: 1, to: 2 } } });
		internalCertificate.update = async () => calls.push("update");
		internalCertificate.writeCustomCert = async () => calls.push("write");
		await assert.rejects(
			() => internalCertificate.upload({}, { id: 3, files: { certificate: { data: Buffer.from("CERT") } } }),
			(err) => err instanceof errs.ValidationError && /key file was not provided/.test(err.message),
		);
		assert.deepEqual(calls, []);
	});

	it("allows a certificate-only re-upload when a key is already stored", async () => {
		const calls = [];
		internalCertificate.get = async () => ({ id: 3, provider: "other", meta: { certificate_key: "KEY" } });
		internalCertificate.validate = async () => ({ certificate: { cn: "x.example", dates: { from: 1, to: 2 } } });
		internalCertificate.update = async (_a, data) => {
			calls.push("update");
			return { ...data };
		};
		internalCertificate.writeCustomCert = async () => calls.push("write");
		await internalCertificate.upload({}, { id: 3, files: { certificate: { data: Buffer.from("CERT") } } });
		assert.deepEqual(calls, ["update", "write"]);
	});
});

describe("certificate model domain_names", () => {
	it("drops null/empty names when reading and writing", async () => {
		const { default: certificateModel, cleanDomainNames } = await import("../models/certificate.js");
		assert.deepEqual(cleanDomainNames([null, "", " ", "b.example", "a.example"]), ["b.example", "a.example"]);
		const row = certificateModel.fromDatabaseJson({ id: 1, domain_names: "[null]", meta: "{}", is_deleted: 0 });
		assert.deepEqual(row.domain_names, []);
		const row2 = certificateModel.fromDatabaseJson({
			id: 2,
			domain_names: '["x.example",null]',
			meta: "{}",
			is_deleted: 0,
		});
		assert.deepEqual(row2.domain_names, ["x.example"]);
		const names = [null, "b.example", "a.example"];
		const fresh = certificateModel.fromJson({ provider: "other", domain_names: names }, { skipValidation: true });
		fresh.$beforeInsert();
		assert.deepEqual(fresh.domain_names, ["a.example", "b.example"]);
	});
});

describe("upload with an unparseable subject", () => {
	const orig = {
		get: internalCertificate.get,
		validate: internalCertificate.validate,
		update: internalCertificate.update,
		writeCustomCert: internalCertificate.writeCustomCert,
	};
	afterEach(() => Object.assign(internalCertificate, orig));

	it("keeps the stored domain_names instead of storing [null]", async () => {
		let updated = null;
		internalCertificate.get = async () => ({ id: 3, provider: "other", domain_names: ["keep.example"], meta: {} });
		internalCertificate.validate = async () => ({
			certificate: { dates: { from: 1, to: 2 } },
			certificate_key: true,
		});
		internalCertificate.update = async (_a, data) => {
			updated = data;
			return { ...data };
		};
		internalCertificate.writeCustomCert = async () => true;
		await internalCertificate.upload(
			{},
			{ id: 3, files: { certificate: { data: Buffer.from("C") }, certificate_key: { data: Buffer.from("K") } } },
		);
		assert.deepEqual(updated.domain_names, ["keep.example"]);
	});
});
