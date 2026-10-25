import { migrate as logger } from "../logger.js";

const migrateName = "agent_direct_link";

// Direct links ("Direktverbindungen"): a WireGuard tunnel between two site
// agents, the hub stays the fallback. Side A listens (fixed IP / port forward),
// side B dials endpoint_host:listen_port. Public keys are reported by the agents
// (private keys never leave them); a_status/b_status hold the last reported
// health (JSON). No rows = nothing changes on any agent.
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	if (!(await knex.schema.hasTable("agent_direct_link"))) {
		await knex.schema.createTable("agent_direct_link", (table) => {
			table.increments().primary();
			table.string("name", 64).notNullable();
			table.integer("agent_a_id").unsigned().notNullable().index();
			table.integer("agent_b_id").unsigned().notNullable().index();
			table.integer("listen_port").unsigned().notNullable();
			table.string("endpoint_host", 255).notNullable();
			table.string("tunnel_subnet", 32).notNullable();
			table.integer("mtu").unsigned().nullable();
			table.boolean("enabled").notNullable().defaultTo(0);
			table.boolean("nat_a").notNullable().defaultTo(0);
			table.boolean("nat_b").notNullable().defaultTo(0);
			table.string("a_public_key", 64).nullable();
			table.string("b_public_key", 64).nullable();
			table.text("a_status").nullable();
			table.text("b_status").nullable();
			table.integer("a_seen").unsigned().nullable();
			table.integer("b_seen").unsigned().nullable();
			table.integer("created_on").unsigned().notNullable();
			table.integer("modified_on").unsigned().notNullable();
		});
	}
	logger.info(`[${migrateName}] agent_direct_link ensured`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	await knex.schema.dropTableIfExists("agent_direct_link");
	logger.info(`[${migrateName}] dropped`);
};

export { down, up };
