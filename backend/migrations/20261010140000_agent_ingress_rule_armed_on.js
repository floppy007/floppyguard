import { migrate as logger } from "../logger.js";

const migrateName = "agent_ingress_rule_armed_on";

// Reference point for the "no new connection for 30 days" hint on a Freigabe:
// set when the rule is created, switched on, or its targets (sources /
// destinations / ports) change — NOT on a rename or note edit, which used to
// bump modified_on and hide a truly unused rule for another 30 days.
// Existing rows start from their modified_on (the reference used until now).
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (!(await knex.schema.hasColumn("agent_ingress_rule", "armed_on"))) {
		await knex.schema.table("agent_ingress_rule", (table) => {
			table.integer("armed_on").unsigned().nullable();
		});
		await knex("agent_ingress_rule").whereNull("armed_on").update({ armed_on: knex.ref("modified_on") });
	}
	logger.info(`[${migrateName}] agent_ingress_rule.armed_on ensured`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	if (await knex.schema.hasColumn("agent_ingress_rule", "armed_on")) {
		await knex.schema.table("agent_ingress_rule", (table) => {
			table.dropColumn("armed_on");
		});
	}
	logger.info(`[${migrateName}] dropped`);
};

export { down, up };
