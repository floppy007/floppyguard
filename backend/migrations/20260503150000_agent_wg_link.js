export async function up(knex) {
	await knex.schema.table("agent", (table) => {
		table.string("wg_link_name", 255).nullable().defaultTo(null);
	});
}

export async function down(knex) {
	await knex.schema.table("agent", (table) => {
		table.dropColumn("wg_link_name");
	});
}
