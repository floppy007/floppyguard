import { migrate as logger } from "../logger.js";

const migrateName = "agent_hub_url_setting";

// Seeds the `agent-hub-url` setting that getConfig() advertises to agents so a
// hub domain change propagates to every agent. Seeded empty — sanitizeHubUrl
// turns empty into null, so getConfig omits the URLs and agents keep whatever
// they have baked in until an admin sets real values in the UI.
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);
	const existing = await knex("setting").where("id", "agent-hub-url").first();
	if (existing) {
		logger.info(`[${migrateName}] agent-hub-url setting already present, skipping`);
		return;
	}
	await knex("setting").insert({
		id: "agent-hub-url",
		name: "Agent Hub URL",
		description:
			"Hub URLs propagated to agents — value = public/fallback URL, meta.primary = internal primary URL",
		value: "",
		meta: JSON.stringify({ primary: "" }),
	});
	logger.info(`[${migrateName}] agent-hub-url setting seeded`);
};

const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	await knex("setting").where("id", "agent-hub-url").del();
	logger.info(`[${migrateName}] agent-hub-url setting removed`);
};

export { down, up };
