import { lazy, type ReactNode, Suspense, useEffect, useRef } from "react";
import { BrowserRouter, Route, Routes, useLocation } from "react-router-dom";
import type { HealthResponse } from "src/api/backend";
import {
	ChunkErrorBoundary,
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
import { intl } from "src/locale/IntlProvider";

const Setup = lazy(() => import("src/pages/Setup"));
const Login = lazy(() => import("src/pages/Login"));
const Dashboard = lazy(() => import("src/pages/Dashboard"));
const Gateway = lazy(() => import("src/pages/Gateway"));
const Traffic = lazy(() => import("src/pages/Traffic"));
const Settings = lazy(() => import("src/pages/Settings"));
const Certificates = lazy(() => import("src/pages/Certificates"));
const Access = lazy(() => import("src/pages/Access"));
const AuditLog = lazy(() => import("src/pages/AuditLog"));
const Users = lazy(() => import("src/pages/Users"));
const WireGuard = lazy(() => import("src/pages/WireGuard"));
const Ingress = lazy(() => import("src/pages/Ingress"));
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

/** Error boundary for the routed pages; navigating elsewhere clears a shown error. */
function PageBoundary({ children }: { children: ReactNode }) {
	const { pathname } = useLocation();
	return <ChunkErrorBoundary resetKey={pathname}>{children}</ChunkErrorBoundary>;
}

function Router() {
	const health = useHealth();
	const { authenticated } = useAuthState();
	const appReady = !health.isLoading && !health.isFetching;
	const healthData = health.data as unknown as HealthResponse | undefined;
	// Set once a real (not cached) health check succeeded in this tab. After that a
	// failed background refetch (backend restart, network blip) only shows a
	// banner — replacing the tree with <Unhealthy/> would drop open forms/modals.
	const healthyOnce = useRef(false);
	if (health.isSuccess && health.isFetchedAfterMount && healthData?.status === "OK") {
		healthyOnce.current = true;
	}

	useEffect(() => {
		if (appReady) {
			window.setTimeout(hideBootSplash, 120);
		}
	}, [appReady]);

	if (health.isLoading) {
		return null;
	}

	if ((health.isError && !healthyOnce.current) || healthData?.status !== "OK") {
		hideBootSplash();
		return <Unhealthy />;
	}

	if (!healthData?.setup) {
		hideBootSplash();
		return (
			<ChunkErrorBoundary>
				<Suspense fallback={null}>
					<Setup />
				</Suspense>
			</ChunkErrorBoundary>
		);
	}

	if (!authenticated) {
		return (
			<ChunkErrorBoundary>
				<Suspense fallback={null}>
					<Login />
				</Suspense>
			</ChunkErrorBoundary>
		);
	}

	return (
		<BrowserRouter>
			<Page>
				<SiteHeader />
				{health.isError && (
					<div className="alert alert-warning rounded-0 mb-0 py-2 text-center small" role="status">
						{intl.formatMessage({ id: "health.refetch-error" })}
					</div>
				)}
				<SiteContainer>
					<PageBoundary>
						<Suspense fallback={<LoadingPage noLogo />}>
							<Routes>
								<Route path="*" element={<ErrorNotFound />} />
								<Route path="/platform" element={<Dashboard />} />
								<Route path="/gateway" element={<Gateway />} />
								<Route path="/traffic" element={<Traffic />} />
								<Route path="/certificates" element={<Certificates />} />
								<Route path="/access" element={<Access />} />
								<Route path="/audit-log" element={<AuditLog />} />
								<Route path="/settings" element={<Settings />} />
								<Route path="/users" element={<Users />} />
								<Route path="/wireguard" element={<WireGuard />} />
								<Route path="/ingress" element={<Ingress />} />
								<Route path="/nginx/proxy" element={<ProxyHosts />} />
								<Route path="/nginx/redirection" element={<RedirectionHosts />} />
								<Route path="/nginx/404" element={<DeadHosts />} />
								<Route path="/nginx/stream" element={<Streams />} />
								<Route path="/" element={<Dashboard />} />
							</Routes>
						</Suspense>
					</PageBoundary>
				</SiteContainer>
				<SiteFooter />
			</Page>
		</BrowserRouter>
	);
}

export default Router;
