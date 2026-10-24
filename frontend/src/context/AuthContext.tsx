import { useQueryClient } from "@tanstack/react-query";
import { createContext, type ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { getToken, isTwoFactorChallenge, loginAsUser, refreshToken, type TokenResponse } from "src/api/backend";
import AuthStore from "src/modules/AuthStore";

// Context
export interface AuthContextType {
	authenticated: boolean;
	login: (username: string, password: string) => Promise<void>;
	loginAs: (id: number) => Promise<void>;
	logout: () => void;
	token?: string;
}

const initalValue = null;
const AuthContext = createContext<AuthContextType | null>(initalValue);

// Provider
interface Props {
	children?: ReactNode;
	tokenRefreshInterval?: number;
}
function AuthProvider({ children, tokenRefreshInterval = 5 * 60 * 1000 }: Props) {
	const queryClient = useQueryClient();
	const [authenticated, setAuthenticated] = useState(AuthStore.hasActiveToken());

	const handleTokenUpdate = useCallback((response: TokenResponse) => {
		AuthStore.set(response);
		setAuthenticated(true);
	}, []);

	const login = async (identity: string, secret: string) => {
		const response = await getToken(identity, secret);
		if (isTwoFactorChallenge(response)) {
			// Only used by Setup for a freshly created admin; 2FA cannot be enabled yet.
			// The interactive login/2FA flow lives in pages/Login.
			throw new Error("Two-factor authentication is handled on the login page");
		}
		handleTokenUpdate(response);
		window.location.assign("/");
	};

	const loginAs = async (id: number) => {
		const response = await loginAsUser(id);
		AuthStore.add(response);
		queryClient.clear();
		window.location.reload();
	};

	const logout = () => {
		if (AuthStore.count() >= 2) {
			AuthStore.drop();
			queryClient.clear();
			window.location.reload();
			return;
		}
		AuthStore.clear();
		setAuthenticated(false);
		queryClient.clear();
	};

	const refresh = useCallback(async () => {
		const response = await refreshToken();
		// Replace only the top of the stack so a "login as" session
		// doesn't wipe out the admin's original token underneath it.
		AuthStore.replaceTop(response);
	}, []);

	useEffect(() => {
		if (!authenticated) {
			return;
		}

		const intervalId = window.setInterval(() => {
			refresh().catch(() => {
				// A real 401 is handled in processResponse (clear + reload). Anything
				// else here is transient (network, 502 during a restart): keep the
				// still-valid token and retry on the next tick.
				if (!AuthStore.isTopTokenExpired()) return;
				AuthStore.clear();
				setAuthenticated(false);
				queryClient.clear();
			});
		}, tokenRefreshInterval);

		return () => {
			window.clearInterval(intervalId);
		};
	}, [authenticated, queryClient, tokenRefreshInterval, refresh]);

	const value = {
		authenticated,
		login,
		loginAs,
		logout,
	};

	return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

function useAuthState() {
	const context = useContext(AuthContext);
	if (!context) {
		throw new Error("useAuthState must be used within a AuthProvider");
	}
	return context;
}

export { AuthProvider, useAuthState };
export default AuthContext;
