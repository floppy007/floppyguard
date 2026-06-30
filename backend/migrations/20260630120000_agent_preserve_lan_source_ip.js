import { migrate as logger } from "../logger.js";

const migrateName = "agent_preserve_lan_source_ip";

const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	const hasCol = await knex.schema.hasColumn("agent", "preserve_lan_source_ip");
	if (!hasCol) {
		await knex.schema.table("agent", (table) => {
			// Default OFF (opt-in): keep the current MASQUERADE behaviour for every
			// existing agent so the rollout changes no LAN behaviour anywhere. Enable
			// per-agent only at sites WITH a return route to the tunnel subnet, where
			// exempting the local LAN from NAT lets hosts (e.g. AD) see the real client IP.
			table.boolean("preserve_lan_source_ip").notNullable().defaultTo(0);
		});
	}
	logger.info(`[${migrateName}] agent.preserve_lan_source_ip column ensured`);
};

const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	return knex.schema
		.table("agent", (table) => {
			table.dropColumn("preserve_lan_source_ip");
		})
		.then(() => {
			logger.info(`[${migrateName}] agent.preserve_lan_source_ip column dropped`);
		});
};

export { down, up };
