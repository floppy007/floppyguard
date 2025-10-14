import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";
import checker from "vite-plugin-checker";
import tsconfigPaths from "vite-tsconfig-paths";
import "vitest/config";
import { execFile } from "node:child_process";

const runLocaleScripts = () => {
	execFile("yarn", ["locale-compile"], (error, stdout, _stderr) => {
		if (error) {
			throw error;
		}
		console.log(stdout);
		execFile("yarn", ["locale-sort"], (error, stdout, _stderr) => {
			if (error) {
				throw error;
			}
			console.log(stdout);
		});
	});
};

const enableLocaleWatcher = process.env.ENABLE_LOCALE_WATCH === "true";
const enableTypeChecker = process.env.ENABLE_TS_CHECKER === "true";

export default defineConfig({
	plugins: [
		...(enableLocaleWatcher ? [
			{
				name: "run-on-start",
				configureServer(_server) {
					runLocaleScripts();
				},
			},
			{
				name: "trigger-on-reload",
				configureServer(server) {
					server.watcher.on("change", (file) => {
						if (file.includes("locale/src")) {
							console.log(`File changed: ${file}, running locale scripts...`);
							runLocaleScripts();
						}
					});
				},
			},
		] : []),
		react(),
		...(enableTypeChecker ? [checker({ typescript: true })] : []),
		tsconfigPaths(),
	],
	server: {
		host: true,
		port: 5173,
		strictPort: true,
		allowedHosts: true,
		proxy: {
			"/api": {
				target: "http://127.0.0.1:3300",
				changeOrigin: true,
				rewrite: (path) => path.replace(/^\/api/, "") || "/",
			},
		},
	},
	build: {
		sourcemap: false,
		minify: "esbuild",
		cssCodeSplit: false,
		reportCompressedSize: false,
		chunkSizeWarningLimit: 1500,
		rollupOptions: {
			output: {
				manualChunks: {
					vendor: ["react", "react-dom", "react-router-dom"],
					tabler_icons: ["@tabler/icons-react"],
					tabler_core: ["@tabler/core"],
					bootstrap: ["react-bootstrap"],
					query: ["@tanstack/react-query"],
					forms: ["formik", "react-select"],
					intl: ["react-intl"],
				},
			},
		},
	},
	optimizeDeps: {
		noDiscovery: true,
		include: ["classnames", "cookie", "extend", "hoist-non-react-statics", "invariant", "prop-types", "react-dom/client", "react-fast-compare", "set-cookie-parser", "warning"],
	},
	test: {
		environment: "happy-dom",
		setupFiles: ["./vitest-setup.js"],
	},
	assetsInclude: ["**/*.md", "**/*.png", "**/*.svg"],
});
