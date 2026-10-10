import { migrate as logger } from "../logger.js";

const migrateName = "agent_ingress";

// Per-agent ingress filtering ("Freigaben"): replaces the UniFi-Manager VPN_MGR
// chain on gateway agents. Default ingress_mode "open" + no rules = the agent
// gets no filter at all, so this migration changes nothing on existing agents.
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (!(await knex.schema.hasColumn("agent", "ingress_mode"))) {
		await knex.schema.table("agent", (table) => {
			table.string("ingress_mode", 16).notNullable().defaultTo("open");
		});
	}
	if (!(await knex.schema.hasTable("agent_ingress_rule"))) {
		await knex.schema.createTable("agent_ingress_rule", (table) => {
			table.increments().primary();
			table.integer("agent_id").unsigned().notNullable().index();
			table.string("name", 100).notNullable();
			table.text("sources").notNullable(); // JSON array of CIDRs
			table.text("destinations").notNullable(); // JSON array of CIDRs, [] = any
			table.text("ports").notNullable(); // JSON array of {proto, port}, [] = all
			table.boolean("enabled").notNullable().defaultTo(1);
			table.string("note", 255).nullable();
			table.bigInteger("hit_packets").notNullable().defaultTo(0);
			table.integer("last_hit_at").unsigned().nullable();
			table.integer("created_on").unsigned().notNullable();
			table.integer("modified_on").unsigned().notNullable();
		});
	}
	logger.info(`[${migrateName}] agent.ingress_mode + agent_ingress_rule ensured`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	await knex.schema.dropTableIfExists("agent_ingress_rule");
	if (await knex.schema.hasColumn("agent", "ingress_mode")) {
		await knex.schema.table("agent", (table) => {
			table.dropColumn("ingress_mode");
		});
	}
	logger.info(`[${migrateName}] dropped`);
};

export { down, up };
