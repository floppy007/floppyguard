// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";
import now from "./now_helper.js";

Model.knex(db());

class UserPermission extends Model {
	$beforeInsert() {
		this.created_on = now();
		this.modified_on = now();
	}

	$beforeUpdate() {
		this.modified_on = now();
	}

	static get name() {
		return "UserPermission";
	}

	static get tableName() {
		return "user_permission";
	}

	/**
	 * Inserts the default permission row for a freshly created account:
	 * every object type "manage", visibility "all" for admins, "user" otherwise.
	 */
	static insertDefaults(userId, isAdmin) {
		return UserPermission.query().insert({
			user_id: userId,
			visibility: isAdmin ? "all" : "user",
			proxy_hosts: "manage",
			redirection_hosts: "manage",
			dead_hosts: "manage",
			streams: "manage",
			access_lists: "manage",
			certificates: "manage",
		});
	}
}

export default UserPermission;
