import { migrate as logger } from "../logger.js";

const migrateName = "agent_ingress_applied";

// Freigaben feedback: the agent reports in its heartbeat which ingress ruleset
// it actually runs (hash of FG_IN, or NONE) and the last apply error. The hub
// compares that with the ruleset it wants, so a filter the agent rejected no
// longer shows as active. Both columns nullable = "not reported" (older agent).
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (!(await knex.schema.hasColumn("agent", "ingress_applied_hash"))) {
		await knex.schema.table("agent", (table) => {
			table.string("ingress_applied_hash", 64).nullable();
		});
	}
	if (!(await knex.schema.hasColumn("agent", "ingress_error"))) {
		await knex.schema.table("agent", (table) => {
			table.string("ingress_error", 255).nullable();
		});
	}
	logger.info(`[${migrateName}] agent.ingress_applied_hash + agent.ingress_error ensured`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	for (const col of ["ingress_applied_hash", "ingress_error"]) {
		if (await knex.schema.hasColumn("agent", col)) {
			await knex.schema.table("agent", (table) => {
				table.dropColumn(col);
			});
		}
	}
	logger.info(`[${migrateName}] dropped`);
};

export { down, up };
