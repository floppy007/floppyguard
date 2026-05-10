import { migrate as logger } from "../logger.js";

const migrateName = "agent_allowed_sites";

const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	const cols = await knex.raw("SHOW COLUMNS FROM agent");
	const existing = new Set(cols[0].map((c) => c.Field));
	await knex.schema.table("agent", (table) => {
		if (!existing.has("allowed_sites")) table.text("allowed_sites").nullable();
		if (!existing.has("allowed_networks")) table.text("allowed_networks").nullable();
	});
	logger.info(`[${migrateName}] agent.allowed_sites + allowed_networks columns ensured`);
};

const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	return knex.schema
		.table("agent", (table) => {
			table.dropColumn("allowed_sites");
			table.dropColumn("allowed_networks");
		})
		.then(() => {
			logger.info(`[${migrateName}] agent.allowed_sites + allowed_networks columns dropped`);
		});
};

export { down, up };
