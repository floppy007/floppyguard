import * as api from "./base";
import type { ApplicationUpdateStatus } from "./responseTypes";

export async function getApplicationUpdate(): Promise<ApplicationUpdateStatus> {
	return await api.get({ url: "/version/update" });
}
