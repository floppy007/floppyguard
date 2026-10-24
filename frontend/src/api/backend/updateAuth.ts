import * as api from "./base";
import type { User } from "./models";

export async function updateAuth(userId: number | "me", newPassword: string, current?: string): Promise<User> {
	const data = {
		type: "password",
		current,
		secret: newPassword,
	};
	return await api.put({
		url: `/users/${userId}/auth`,
		data,
	});
}
