// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";
import { convertBoolFieldsToInt, convertIntFieldsToBool } from "../lib/helpers.js";

Model.knex(db());

const boolFields = ["enabled", "nat_a", "nat_b"];

class AgentDirectLink extends Model {
	$beforeInsert() {
		this.created_on = Math.floor(Date.now() / 1000);
		this.modified_on = Math.floor(Date.now() / 1000);
	}

	$beforeUpdate() {
		this.modified_on = Math.floor(Date.now() / 1000);
	}

	$parseDatabaseJson(json) {
		const thisJson = super.$parseDatabaseJson(json);
		return convertIntFieldsToBool(thisJson, boolFields);
	}

	$formatDatabaseJson(json) {
		const thisJson = convertBoolFieldsToInt(json, boolFields);
		return super.$formatDatabaseJson(thisJson);
	}

	static get name() {
		return "AgentDirectLink";
	}

	static get tableName() {
		return "agent_direct_link";
	}

	static get jsonAttributes() {
		return [];
	}
}

export default AgentDirectLink;
