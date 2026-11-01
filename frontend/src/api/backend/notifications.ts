import * as api from "./base";

export type SmtpSecurity = "ssl" | "starttls" | "none";

export interface NotificationSettings {
	enabled: boolean;
	appUrl: string;
	smtp: {
		host: string;
		port: number;
		security: SmtpSecurity;
		user: string;
		fromName: string;
		fromAddress: string;
		hasPassword: boolean;
	};
	recipients: string[];
	events: { certFailed: boolean; certExpiring: boolean };
	expiringDays: number;
}

export interface NotificationSettingsInput extends Omit<NotificationSettings, "smtp"> {
	smtp: Omit<NotificationSettings["smtp"], "hasPassword"> & { password?: string };
	clearPassword?: boolean;
}

export interface CertProblem {
	id: number;
	name: string;
	provider: string;
	expiresOn: string | null;
	daysLeft: number | null;
	kind: "expired" | "failed" | "expiring";
	error: string | null;
	failures: number;
	since: number | null;
	nextAttempt: number | null;
}

export async function getNotifications(): Promise<NotificationSettings> {
	return await api.get({ url: "/notifications" });
}

export async function updateNotifications(data: NotificationSettingsInput): Promise<NotificationSettings> {
	return await api.put({ url: "/notifications", data });
}

export async function testNotifications(to?: string): Promise<{ ok: boolean; message: string }> {
	return await api.post({ url: "/notifications/test", data: { to } });
}

export async function getCertProblems(): Promise<{ certificates: CertProblem[] }> {
	return await api.get({ url: "/notifications/problems" });
}
