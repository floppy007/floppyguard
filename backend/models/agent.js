// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";
import { convertBoolFieldsToInt, convertIntFieldsToBool } from "../lib/helpers.js";
import now from "./now_helper.js";

Model.knex(db());

const boolFields = ["is_deleted"];

class Agent extends Model {
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
		return "Agent";
	}

	static get tableName() {
		return "agent";
	}

	static get jsonAttributes() {
		return [];
	}
}

export default Agent;
