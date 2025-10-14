import { lazy, Suspense, useEffect } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import {
	ErrorNotFound,
	LoadingPage,
	Page,
	SiteContainer,
	SiteFooter,
	SiteHeader,
	Unhealthy,
} from "src/components";
import { useAuthState } from "src/context";
import { useHealth } from "src/hooks";
import type { HealthResponse } from "src/api/backend";

const Setup = lazy(() => import("src/pages/Setup"));
const Login = lazy(() => import("src/pages/Login"));
const Dashboard = lazy(() => import("src/pages/Dashboard"));
const Gateway = lazy(() => import("src/pages/Gateway"));
const Settings = lazy(() => import("src/pages/Settings"));
const Certificates = lazy(() => import("src/pages/Certificates"));
const Access = lazy(() => import("src/pages/Access"));
const AuditLog = lazy(() => import("src/pages/AuditLog"));
const Users = lazy(() => import("src/pages/Users"));
const WireGuard = lazy(() => import("src/pages/WireGuard"));
const ProxyHosts = lazy(() => import("src/pages/Nginx/ProxyHosts"));
const RedirectionHosts = lazy(() => import("src/pages/Nginx/RedirectionHosts"));
const DeadHosts = lazy(() => import("src/pages/Nginx/DeadHosts"));
const Streams = lazy(() => import("src/pages/Nginx/Streams"));

const hideBootSplash = () => {
	const fn = (window as typeof window & { __hideBootSplash?: () => void }).__hideBootSplash;
	if (typeof fn === "function") {
		fn();
	}
};

function Router() {
	const health = useHealth();
	const { authenticated } = useAuthState();
	const appReady = !health.isLoading && !health.isFetching;

	useEffect(() => {
		if (appReady) {
			window.setTimeout(hideBootSplash, 120);
		}
	}, [appReady]);

	if (health.isLoading) {
		return null;
	}

	if (health.isError || (health.data as unknown as HealthResponse | undefined)?.status !== "OK") {
		hideBootSplash();
		return <Unhealthy />;
	}

	if (!(health.data as unknown as HealthResponse | undefined)?.setup) {
		hideBootSplash();
		return <Setup />;
	}

	if (!authenticated) {
		return (
			<Suspense fallback={null}>
				<Login />
			</Suspense>
		);
	}

	return (
		<BrowserRouter>
			<Page>
				<SiteHeader />
				<SiteContainer>
					<Suspense fallback={<LoadingPage noLogo />}>
						<Routes>
							<Route path="*" element={<ErrorNotFound />} />
							<Route path="/platform" element={<Dashboard />} />
							<Route path="/gateway" element={<Gateway />} />
							<Route path="/certificates" element={<Certificates />} />
							<Route path="/access" element={<Access />} />
							<Route path="/audit-log" element={<AuditLog />} />
							<Route path="/settings" element={<Settings />} />
							<Route path="/users" element={<Users />} />
							<Route path="/wireguard" element={<WireGuard />} />
							<Route path="/nginx/proxy" element={<ProxyHosts />} />
							<Route path="/nginx/redirection" element={<RedirectionHosts />} />
							<Route path="/nginx/404" element={<DeadHosts />} />
							<Route path="/nginx/stream" element={<Streams />} />
							<Route path="/" element={<Dashboard />} />
						</Routes>
					</Suspense>
				</SiteContainer>
				<SiteFooter />
			</Page>
		</BrowserRouter>
	);
}

export default Router;
