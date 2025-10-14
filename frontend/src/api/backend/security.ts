import { del, get } from "./base";

export interface Fail2BanJail {
	name: string;
	currentlyFailed: number;
	totalFailed: number;
	currentlyBanned: number;
	totalBanned: number;
	bannedIps: string[];
}

export interface Fail2BanStatus {
	available: boolean;
	jails: Fail2BanJail[];
}

export function getFail2BanStatus(): Promise<Fail2BanStatus> {
	return get({ url: "security/fail2ban" }) as Promise<Fail2BanStatus>;
}

export function unbanIp(jail: string, ip: string): Promise<{ unbanned: boolean; jail: string; ip: string }> {
	return del({ url: `security/fail2ban/${encodeURIComponent(jail)}/${encodeURIComponent(ip)}` }) as Promise<{ unbanned: boolean; jail: string; ip: string }>;
}
