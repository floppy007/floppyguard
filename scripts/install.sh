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
        # shellcheck source=/dev/null
        . /etc/os-release
        case "$ID" in
            debian|ubuntu|raspbian) ok "Detected: $PRETTY_NAME" ;;
            *) warn "Untested OS: $PRETTY_NAME — proceeding anyway" ;;
        esac
    fi
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
        apt-get update -qq
        apt-get install -y -qq "${pkgs[@]}"
    fi

    # Node.js
    if ! command -v node >/dev/null 2>&1 || [ "$(node -e 'process.stdout.write(process.version.slice(1).split(".")[0])')" -lt 20 ]; then
        info "Installing Node.js 20 LTS..."
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y -qq nodejs
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
        git -C "${INSTALL_DIR}" fetch origin "${BRANCH}"
        git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}"
    else
        info "Cloning FloppyGuard to ${INSTALL_DIR}..."
        git clone --branch "${BRANCH}" --depth 1 "${REPO}" "${INSTALL_DIR}"
    fi
    ok "Source at ${INSTALL_DIR}"
}

build() {
    info "Installing backend dependencies..."
    (cd "${INSTALL_DIR}/backend" && yarn install --frozen-lockfile --silent)

    info "Installing frontend dependencies and building..."
    (cd "${INSTALL_DIR}/frontend" && yarn install --frozen-lockfile --silent)
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
        warn ".env already exists — skipping. Edit ${env_file} manually if needed."
        return
    fi

    info "Writing default .env (SQLite)..."
    cat > "${env_file}" <<EOF
# FloppyGuard backend configuration
# Choose ONE database backend:

# --- SQLite (default, no extra setup required) ---
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

# Backend listen port
PORT=${BACKEND_PORT}

# WireGuard config directory
WG_CONF_DIR=/etc/wireguard
EOF
    ok ".env written — edit ${env_file} to configure your database"
}

install_systemd() {
    local unit_file="/etc/systemd/system/${SERVICE_NAME}.service"
    if [ -f "${unit_file}" ]; then
        warn "Systemd unit already exists — reloading"
    else
        info "Installing systemd unit..."
        cat > "${unit_file}" <<EOF
[Unit]
Description=FloppyGuard Backend
After=network.target
Wants=network.target

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
    systemctl enable "${SERVICE_NAME}"
    systemctl restart "${SERVICE_NAME}"
    ok "systemd unit ${SERVICE_NAME} enabled and started"
}

install_nginx() {
    local site_file="/etc/nginx/sites-available/${NGINX_SITE}"
    if [ -f "${site_file}" ]; then
        warn "nginx site already exists — skipping"
        return
    fi

    info "Writing nginx site config (admin UI on port ${ADMIN_PORT})..."
    cat > "${site_file}" <<EOF
server {
    listen ${ADMIN_PORT};
    listen [::]:${ADMIN_PORT};

    root ${INSTALL_DIR}/frontend/dist;
    index index.html;

    # SPA fallback
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    # Proxy API to backend
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

    ln -sf "${site_file}" "/etc/nginx/sites-enabled/${NGINX_SITE}"
    nginx -t && nginx -s reload
    ok "nginx site enabled — admin UI available on http://localhost:${ADMIN_PORT}"
}

print_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║     FloppyGuard installed successfully   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "  Admin UI:   ${CYAN}http://$(hostname -I | awk '{print $1}'):${ADMIN_PORT}${NC}"
    echo -e "  Backend:    port ${BACKEND_PORT} (systemd: ${SERVICE_NAME})"
    echo -e "  Install:    ${INSTALL_DIR}"
    echo -e "  Config:     ${INSTALL_DIR}/backend/.env"
    echo ""
    echo -e "  Default login:  ${YELLOW}admin@example.com${NC} / ${YELLOW}changeme${NC}"
    echo -e "  ${RED}Change the password immediately after first login!${NC}"
    echo ""
    echo -e "  Logs:  journalctl -u ${SERVICE_NAME} -f"
    echo ""
}

require_root
check_os
install_prereqs
clone_or_update
build
setup_data_dirs
write_env
install_systemd
install_nginx
print_summary
