import type { AppVersion, User } from "./models";

export interface HealthResponse {
	status: string;
	version: AppVersion;
	setup: boolean;
}

export interface TokenResponse {
	expires: number;
	token: string;
}

export interface ValidatedCertificateResponse {
	certificate: Record<string, any>;
	certificateKey: boolean;
}

export interface LoginAsTokenResponse extends TokenResponse {
	user: User;
}

export interface VersionCheckResponse {
	current: string | null;
	latest: string | null;
	updateAvailable: boolean;
}

export interface ApplicationUpdateStatus {
	state: "idle" | "queued" | "running" | "restarting" | "completed" | "failed";
	step: string;
	message: string;
	startedAt?: string;
	updatedAt?: string;
	finishedAt?: string;
	current?: string;
	target?: string;
	alreadyRunning?: boolean;
}

export interface TwoFactorChallengeResponse {
	requires2fa: boolean;
	challengeToken: string;
}

export interface TwoFactorStatusResponse {
	enabled: boolean;
	backupCodesRemaining: number;
}

export interface TwoFactorSetupResponse {
	secret: string;
	otpauthUrl: string;
}

export interface TwoFactorEnableResponse {
	backupCodes: string[];
}
