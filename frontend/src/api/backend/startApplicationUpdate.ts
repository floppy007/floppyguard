import * as api from "./base";
import type { ApplicationUpdateStatus } from "./responseTypes";

export async function startApplicationUpdate(): Promise<ApplicationUpdateStatus> {
	return await api.post({ url: "/version/update" });
}
