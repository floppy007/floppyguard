#!/usr/bin/env bash
# FloppyGuard installer
# Usage: curl -fsSL https://raw.githubusercontent.com/floppy007/floppyguard/develop/scripts/install.sh | bash

set -euo pipefail

REPO="https://github.com/floppy007/floppyguard.git"
BRANCH="develop"
INSTALL_DIR="/opt/floppyguard"
DATA_DIR="/data"
LE_DIR="/opt/npm/letsencrypt"
SERVICE_NAME="floppyguard-backend"
NGINX_SITE="floppyguard"
BACKEND_PORT=3300
ADMIN_PORT=81
DOMAIN="${FG_DOMAIN:-}"
SSL="${FG_SSL:-false}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
die()     { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "This script must be run as root (sudo)."
}

check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|raspbian) ok "Detected: $PRETTY_NAME" ;;
            *) warn "Untested OS: $PRETTY_NAME — proceeding anyway" ;;
        esac
    fi
}

ask_domain() {
    # Skip prompt if already set via env vars (FG_DOMAIN / FG_SSL)
    if [ -n "${DOMAIN}" ]; then
        ok "Domain: ${DOMAIN} (from FG_DOMAIN)"
        if [ "${SSL}" = "true" ]; then
            ok "SSL: Let's Encrypt enabled (from FG_SSL)"
        fi
        return
    fi

    echo ""
    echo -e "${CYAN}Domain configuration${NC}"
    echo -e "Enter the domain for the admin UI (e.g. floppyguard.example.com)"
    echo -e "Leave empty to use IP:${ADMIN_PORT} only."
    echo -n "> "

    if [ -t 0 ] || tty -s 2>/dev/null; then
        read -r DOMAIN
    else
        read -r DOMAIN </dev/tty 2>/dev/null || DOMAIN=""
    fi
    DOMAIN="${DOMAIN// /}"

    if [ -n "${DOMAIN}" ]; then
        ok "Domain: ${DOMAIN}"
        echo -e "Set up SSL via Let's Encrypt? [y/N] "
        echo -n "> "
        local ssl_answer=""
        if [ -t 0 ] || tty -s 2>/dev/null; then
            read -r ssl_answer
        else
            read -r ssl_answer </dev/tty 2>/dev/null || ssl_answer="n"
        fi
        if [[ "${ssl_answer,,}" == "y" ]]; then
            SSL=true
            ok "SSL: Let's Encrypt enabled"
        fi
    else
        warn "No domain — admin UI will be available on port ${ADMIN_PORT} only"
    fi
    echo ""
}

install_prereqs() {
    info "Checking prerequisites..."
    local pkgs=()

    command -v nginx   >/dev/null 2>&1 || pkgs+=(nginx)
    command -v nft     >/dev/null 2>&1 || pkgs+=(nftables)
    command -v wg      >/dev/null 2>&1 || pkgs+=(wireguard-tools)
    command -v git     >/dev/null 2>&1 || pkgs+=(git)
    command -v certbot >/dev/null 2>&1 || pkgs+=(certbot)

    if [ ${#pkgs[@]} -gt 0 ]; then
        info "Installing: ${pkgs[*]}"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || {
            warn "apt-get update had errors — removing broken mirror files and retrying..."
            # Remove vendor-specific mirror overrides (Hetzner, etc.) that may be
            # out of sync; the base debian.sources / sources.list already covers
            # the same suites so removing extras is safe.
            find /etc/apt/sources.list.d/ -name "*hetzner*" -o -name "*mirror*" \
                2>/dev/null | xargs rm -f 2>/dev/null || true
            # Also patch any remaining mirror refs in legacy sources.list
            sed -i 's|http://mirror\.[^ ]*|http://deb.debian.org/debian|g' \
                /etc/apt/sources.list 2>/dev/null || true
            DEBIAN_FRONTEND=noninteractive apt-get update -qq
        }
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${pkgs[@]}"
    fi

    # Node.js 20+
    if ! command -v node >/dev/null 2>&1 || \
       [ "$(node -e 'process.stdout.write(process.version.slice(1).split(".")[0])')" -lt 20 ]; then
        info "Installing Node.js 20 LTS..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs
    fi
    ok "Node $(node --version)"

    # Yarn
    if ! command -v yarn >/dev/null 2>&1; then
        info "Installing Yarn..."
        npm install -g yarn --silent
    fi
    ok "Yarn $(yarn --version)"
}

clone_or_update() {
    if [ -d "${INSTALL_DIR}/.git" ]; then
        info "Updating existing installation at ${INSTALL_DIR}..."
        git -C "${INSTALL_DIR}" fetch origin "${BRANCH}" -q
        git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}" -q
    else
        info "Cloning FloppyGuard to ${INSTALL_DIR}..."
        git clone --branch "${BRANCH}" --depth 1 "${REPO}" "${INSTALL_DIR}" -q
    fi
    ok "Source at ${INSTALL_DIR}"
}

build() {
    info "Installing backend dependencies..."
    (cd "${INSTALL_DIR}/backend" && yarn install --frozen-lockfile --silent 2>/dev/null)

    info "Installing frontend dependencies..."
    (cd "${INSTALL_DIR}/frontend" && yarn install --frozen-lockfile --silent 2>/dev/null)

    info "Building frontend..."
    (cd "${INSTALL_DIR}/frontend" && yarn build)
    ok "Frontend built to ${INSTALL_DIR}/frontend/dist"
}

setup_data_dirs() {
    info "Creating data directories..."
    mkdir -p "${DATA_DIR}/nginx/proxy_host" "${DATA_DIR}/nginx/redirection_host" \
             "${DATA_DIR}/nginx/stream" "${DATA_DIR}/nginx/dead_host" \
             "${DATA_DIR}/nginx/access" "${DATA_DIR}/nginx/temp" \
             "${DATA_DIR}/logs" "${LE_DIR}"
    ok "Data dirs at ${DATA_DIR}"
}

write_env() {
    local env_file="${INSTALL_DIR}/backend/.env"
    if [ -f "${env_file}" ]; then
        warn ".env already exists — skipping"
        return
    fi

    info "Writing default .env (SQLite)..."
    cat > "${env_file}" <<EOF
# FloppyGuard backend configuration

# --- SQLite (default) ---
DB_SQLITE_FILE=/data/database.sqlite

# --- MySQL ---
# DB_MYSQL_HOST=127.0.0.1
# DB_MYSQL_PORT=3306
# DB_MYSQL_USER=floppyguard
# DB_MYSQL_PASSWORD=changeme
# DB_MYSQL_NAME=floppyguard

# --- PostgreSQL ---
# DB_POSTGRES_HOST=127.0.0.1
# DB_POSTGRES_PORT=5432
# DB_POSTGRES_USER=floppyguard
# DB_POSTGRES_PASSWORD=changeme
# DB_POSTGRES_NAME=floppyguard

PORT=${BACKEND_PORT}
WG_CONF_DIR=/etc/wireguard

# --- WireGuard peer config defaults ---
# WG_HUB_HOST=your-server-ip-or-hostname
# WG_DNS=10.10.0.1,1.1.1.1
EOF
    ok ".env written"
}

install_systemd() {
    local unit_file="/etc/systemd/system/${SERVICE_NAME}.service"
    if [ ! -f "${unit_file}" ]; then
        info "Installing systemd unit..."
        cat > "${unit_file}" <<EOF
[Unit]
Description=FloppyGuard Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/backend
EnvironmentFile=${INSTALL_DIR}/backend/.env
ExecStart=/usr/bin/node index.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=floppyguard-backend

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" -q
    systemctl restart "${SERVICE_NAME}"
    ok "Backend started (systemd: ${SERVICE_NAME})"
}

install_nginx() {
    local site_file="/etc/nginx/sites-available/${NGINX_SITE}"

    # Remove default nginx site if present
    rm -f /etc/nginx/sites-enabled/default

    info "Writing nginx config..."
    cat > "${site_file}" <<EOF
server {
    listen ${ADMIN_PORT};
    listen [::]:${ADMIN_PORT};
    ${DOMAIN:+server_name ${DOMAIN};}

    root ${INSTALL_DIR}/frontend/dist;
    index index.html;

    location = /index.html {
        add_header Cache-Control "no-store, no-cache, must-revalidate";
        expires 0;
    }

    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Connection "";
    }
}
EOF

    # Domain: add HTTP→HTTPS redirect + port-80 block
    if [ -n "${DOMAIN}" ]; then
        cat >> "${site_file}" <<EOF

server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}
EOF
        ok "Domain ${DOMAIN} configured (HTTP → HTTPS redirect)"
    fi

    ln -sf "${site_file}" "/etc/nginx/sites-enabled/${NGINX_SITE}"
    nginx -t && nginx -s reload
    ok "nginx configured"

    # SSL via Let's Encrypt
    if [ "${SSL}" = true ] && [ -n "${DOMAIN}" ]; then
        info "Requesting Let's Encrypt certificate for ${DOMAIN}..."
        certbot --nginx -d "${DOMAIN}" --non-interactive --agree-tos \
            --register-unsafely-without-email --redirect 2>&1 | tail -5 || \
            warn "certbot failed — run manually: certbot --nginx -d ${DOMAIN}"
        ok "SSL certificate installed"
    fi
}

print_summary() {
    local url
    if [ -n "${DOMAIN}" ] && [ "${SSL}" = true ]; then
        url="https://${DOMAIN}"
    elif [ -n "${DOMAIN}" ]; then
        url="http://${DOMAIN}:${ADMIN_PORT}"
    else
        url="http://$(hostname -I | awk '{print $1}'):${ADMIN_PORT}"
    fi

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     FloppyGuard installed successfully   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Admin UI:  ${CYAN}${url}${NC}"
    echo -e "  Config:    ${INSTALL_DIR}/backend/.env"
    echo -e "  Logs:      journalctl -u ${SERVICE_NAME} -f"
    echo ""
    echo -e "  Default login:  ${YELLOW}admin@example.com${NC} / ${YELLOW}changeme${NC}"
    echo -e "  ${RED}Change the password immediately after first login!${NC}"
    echo ""
}

require_root
check_os
ask_domain
install_prereqs
clone_or_update
build
setup_data_dirs
write_env
install_systemd
install_nginx
print_summary
