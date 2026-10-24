// Upstream #5421: access-list clients/items must be inserted one after another,
// in the order given. nginx evaluates allow/deny top-down; with Promise.all the
// rows got ids in completion order and the rules could render reordered.
import assert from "node:assert/strict";
import test from "node:test";

const { default: internalAccessList } = await import("./access-list.js");
const { default: accessListModel } = await import("../models/access_list.js");
const { default: accessListAuthModel } = await import("../models/access_list_auth.js");
const { default: accessListClientModel } = await import("../models/access_list_client.js");
const { default: internalAuditLog } = await import("./audit-log.js");

const clients = [
	{ directive: "allow", address: "10.0.0.5" },
	{ directive: "deny", address: "10.0.0.0/24" },
	{ directive: "allow", address: "192.168.0.0/16" },
];
// fresh objects per call: maskItems() blanks the passwords in place
const items = () => [
	{ username: "alice", password: "pw-a" },
	{ username: "bob", password: "pw-b" },
];

// Earlier inserts are slower: concurrent inserts would finish in reverse order.
const mockInserts = (t, done) => {
	let pending = 0;
	const slowInsert = (kind) => async (row) => {
		pending++;
		assert.equal(pending, 1, "inserts must not run concurrently");
		await new Promise((resolve) => setTimeout(resolve, 20 - done.length * 5));
		done.push(kind === "client" ? row.address : row.username);
		pending--;
		return row;
	};
	t.mock.method(accessListClientModel, "query", () => ({
		insert: slowInsert("client"),
		delete: () => ({ where: async () => 0 }),
	}));
	t.mock.method(accessListAuthModel, "query", () => ({
		insert: slowInsert("item"),
		delete: () => ({
			where: () => {
				const q = Promise.resolve(0);
				q.andWhere = () => q;
				return q;
			},
		}),
	}));
	t.mock.method(internalAccessList, "get", async () => ({ id: 9, items: [], clients: [], proxy_host_count: 0 }));
	t.mock.method(internalAccessList, "build", async () => true);
	t.mock.method(internalAuditLog, "add", async () => true);
};

const access = { can: async () => ({ permission_visibility: "all" }), token: { getUserId: () => 1 } };

test("access-list create inserts items and clients sequentially in order", async (t) => {
	const done = [];
	mockInserts(t, done);
	t.mock.method(accessListModel, "query", () => ({ insertAndFetch: async (row) => ({ id: 9, ...row }) }));
	await internalAccessList.create(access, { name: "x", satisfy_any: 0, pass_auth: 0, items: items(), clients });
	assert.deepEqual(done, ["alice", "bob", "10.0.0.5", "10.0.0.0/24", "192.168.0.0/16"]);
});

test("access-list update re-inserts items and clients sequentially in order", async (t) => {
	const done = [];
	mockInserts(t, done);
	await internalAccessList.update(access, { id: 9, items: items(), clients });
	assert.deepEqual(done, ["alice", "bob", "10.0.0.5", "10.0.0.0/24", "192.168.0.0/16"]);
});
