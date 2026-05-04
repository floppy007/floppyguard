---
# https://vitepress.dev/reference/default-theme-home-page
layout: home

hero:
  name: "FloppyGuard"
  tagline: Reverse proxy and WireGuard VPN management — host-based, no Docker required
  image:
    src: /logo.svg
    alt: FloppyGuard Logo
  actions:
    - theme: brand
      text: Screenshots
      link: /screenshots/
    - theme: alt
      text: GitHub
      link: https://github.com/floppy007/floppyguard

features:
  - title: Reverse Proxy
    details: Proxy hosts, redirections, streams and dead hosts — with Let's Encrypt SSL (HTTP and DNS challenge) and access lists.
  - title: WireGuard Management
    details: Visual topology map, link planner, metadata editor. Hub-and-spoke routing automation — hub config and remote agent configs wired up in one apply.
  - title: Remote Agent System
    details: One-liner install on any Linux host. Agents self-register, poll for config every 30s, and self-update automatically when a new script version is available.
  - title: Host-Based Runtime
    details: Runs directly on the host via systemd. No Docker container for the app — nginx, certbot and WireGuard are managed as native system services.
  - title: Security Hardened
    details: nftables firewall with strict INPUT policy. fail2ban jails for API brute-force, admin bot scans and SSH.
  - title: Fork of nginx-proxy-manager
    details: Based on nginx-proxy-manager v2.14.0 by Jamie Curnow. Extended with WireGuard management starting at FloppyGuard v1.2.1.
---
