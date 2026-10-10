// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";

Model.knex(db());

// One row = two site links ("wg0:<pubkey>", link_a < link_b) that must not reach
// each other through the hub. See internal/site-isolation.js.
class SiteIsolation extends Model {
	$beforeInsert() {
		this.created_on = Math.floor(Date.now() / 1000);
		this.modified_on = Math.floor(Date.now() / 1000);
	}

	$beforeUpdate() {
		this.modified_on = Math.floor(Date.now() / 1000);
	}

	static get name() {
		return "SiteIsolation";
	}

	static get tableName() {
		return "site_isolation";
	}

	static get jsonAttributes() {
		return [];
	}
}

export default SiteIsolation;
