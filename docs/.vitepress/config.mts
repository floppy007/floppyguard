import { defineConfig } from 'vitepress';

// https://vitepress.dev/reference/site-config
export default defineConfig({
	title: "FloppyGuard",
	description: "WireGuard VPN management and reverse proxy platform",
	head: [
		["link", { rel: "icon", type: "image/svg+xml", href: "/favicon.svg" }],
		["meta", { name: "description", content: "FloppyGuard — host-based reverse proxy and WireGuard VPN management platform, forked from nginx-proxy-manager" }],
		["meta", { property: "og:title", content: "FloppyGuard" }],
		["meta", { property: "og:description", content: "Host-based reverse proxy and WireGuard VPN management platform" }],
		["meta", { property: "og:type", content: "website" }],
	],
	metaChunk: true,
	srcDir: './src',
	outDir: './dist',
	themeConfig: {
		logo: { src: '/logo.svg', width: 24, height: 24 },
		nav: [
			{ text: 'Screenshots', link: '/screenshots/' },
		],
		sidebar: [
			{
				items: [
					{ text: 'Home', link: '/' },
					{ text: 'Screenshots', link: '/screenshots/' },
				]
			}
		],
		socialLinks: [
			{ icon: 'github', link: 'https://github.com/floppy007/floppyguard' }
		],
		search: {
			provider: 'local'
		},
		footer: {
			message: 'Released under the MIT License.',
			copyright: 'Copyright © 2026 Florian Hesse | Comnic-IT'
		}
	}
});
