#!/bin/bash
# =============================================================================
# Nakul — Server Intelligence & Protection Platform
# Bootstrap Installer Script
# =============================================================================
#
# Usage:
#   curl -sL https://your-server/install.sh | bash
#   bash install.sh
#   bash install.sh --unattended
#
# This script:
#   1. Detects OS family (CentOS/AlmaLinux/CloudLinux/RHEL)
#   2. Installs Python 3.9+ and dependencies
#   3. Creates system user and directories
#   4. Deploys application files
#   5. Creates Python virtual environment
#   6. Generates configuration
#   7. Generates admin credentials
#   8. Installs systemd service
#   9. Starts the service
#   10. Prints dashboard URL and credentials
#
# Idempotent: safe to re-run for upgrades/repairs
# =============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Configuration
NAKUL_VERSION="1.0.0"
INSTALL_DIR="/opt/nakul"
CONFIG_DIR="/etc/nakul"
DATA_DIR="/var/lib/nakul"
LOG_DIR="/var/log/nakul"
NAKUL_USER="nakul"
NAKUL_GROUP="nakul"
NAKUL_PORT=8122
CONFIG_FILE="${CONFIG_DIR}/nakul.yaml"
SERVICE_FILE="/etc/systemd/system/nakul.service"
VENV_DIR="${INSTALL_DIR}/venv"

# Flags
UNATTENDED=false
UPGRADE=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --unattended|-u) UNATTENDED=true; shift ;;
    --upgrade) UPGRADE=true; shift ;;
    --port) NAKUL_PORT="$2"; shift 2 ;;
    --help|-h)
      echo "Nakul Installer v${NAKUL_VERSION}"
      echo ""
      echo "Usage: bash install.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --unattended, -u  Non-interactive installation"
      echo "  --upgrade         Upgrade existing installation"
      echo "  --port PORT       Set dashboard port (default: 8122)"
      echo "  --help, -h        Show this help"
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# =============================================================================
# Helper Functions
# =============================================================================

log_info() { echo -e "${CYAN}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
  if [[ $EUID -ne 0 ]]; then
    log_error "This installer must be run as root"
    exit 1
  fi
}

detect_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_FAMILY="${ID_LIKE:-$ID}"
    OS_ID="${ID}"
    OS_VERSION="${VERSION_ID}"
  elif [ -f /etc/redhat-release ]; then
    OS_FAMILY="rhel"
    OS_ID="centos"
    OS_VERSION=$(cat /etc/redhat-release | grep -oP '\d+' | head -1)
  else
    log_error "Unsupported operating system"
    exit 1
  fi

  # Check if cPanel is installed
  CPANEL_INSTALLED=false
  if [ -f /usr/local/cpanel/cpanel ]; then
    CPANEL_INSTALLED=true
  fi

  log_info "Detected OS: ${OS_ID} ${OS_VERSION} (family: ${OS_FAMILY})"
  log_info "cPanel installed: ${CPANEL_INSTALLED}"
}

# =============================================================================
# Installation Steps
# =============================================================================

install_system_deps() {
  log_info "Installing system dependencies..."

  if [[ "$OS_FAMILY" == *"rhel"* ]] || [[ "$OS_ID" == "centos" ]] || [[ "$OS_ID" == "almalinux" ]] || [[ "$OS_ID" == "cloudlinux" ]] || [[ "$OS_ID" == "rocky" ]]; then
    yum install -y python39 python39-pip python39-devel gcc 2>/dev/null || \
    dnf install -y python39 python39-pip python39-devel gcc 2>/dev/null || \
    {
      log_warn "python39 not in repos, trying python3..."
      yum install -y python3 python3-pip python3-devel gcc 2>/dev/null || \
      dnf install -y python3 python3-pip python3-devel gcc 2>/dev/null
    }
  elif [[ "$OS_FAMILY" == *"debian"* ]] || [[ "$OS_ID" == "ubuntu" ]]; then
    apt-get update -qq
    apt-get install -y python3 python3-pip python3-venv python3-dev gcc
  else
    log_warn "Unknown package manager — attempting python3"
    which python3 || { log_error "Python 3 not found"; exit 1; }
  fi

  # Find Python 3.9+
  PYTHON_BIN=""
  for py in python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v $py &>/dev/null; then
      PY_VERSION=$($py -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
      PY_MAJOR=$(echo $PY_VERSION | cut -d. -f1)
      PY_MINOR=$(echo $PY_VERSION | cut -d. -f2)
      if [[ $PY_MAJOR -ge 3 ]] && [[ $PY_MINOR -ge 9 ]]; then
        PYTHON_BIN=$(command -v $py)
        break
      fi
    fi
  done

  if [ -z "$PYTHON_BIN" ]; then
    log_error "Python 3.9+ is required but not found"
    exit 1
  fi

  log_success "Python: ${PYTHON_BIN} ($(${PYTHON_BIN} --version 2>&1))"
}

create_user() {
  log_info "Setting up system user..."

  if id "$NAKUL_USER" &>/dev/null; then
    log_info "User '${NAKUL_USER}' already exists"
  else
    useradd --system --no-create-home --shell /sbin/nologin "$NAKUL_USER" 2>/dev/null || \
    adduser --system --no-create-home --shell /usr/sbin/nologin "$NAKUL_USER" 2>/dev/null || true
    log_success "Created system user: ${NAKUL_USER}"
  fi
}

create_directories() {
  log_info "Creating directories..."

  mkdir -p "$INSTALL_DIR"
  mkdir -p "$CONFIG_DIR"
  mkdir -p "$DATA_DIR"
  mkdir -p "$LOG_DIR"

  # Set permissions — nakul user needs read access to log files
  chown -R "${NAKUL_USER}:${NAKUL_USER}" "$INSTALL_DIR"
  chown -R "${NAKUL_USER}:${NAKUL_USER}" "$DATA_DIR"
  chown -R "${NAKUL_USER}:${NAKUL_USER}" "$LOG_DIR"
  chown -R root:root "$CONFIG_DIR"
  chmod 750 "$CONFIG_DIR"

  log_success "Directories created"
}

deploy_application() {
  log_info "Deploying application files..."

  # Copy the entire nakul package
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  if [ -d "${SCRIPT_DIR}/nakul" ]; then
    cp -r "${SCRIPT_DIR}/nakul" "${INSTALL_DIR}/"
    cp "${SCRIPT_DIR}/requirements.txt" "${INSTALL_DIR}/"
    cp "${SCRIPT_DIR}/pyproject.toml" "${INSTALL_DIR}/"
    log_success "Application files deployed from source"
  else
    log_info "Local source not found. Downloading from GitHub..."
    TMP_DIR=$(mktemp -d)
    curl -sL https://github.com/thekugelblitz/Nakul/archive/refs/heads/main.tar.gz | tar -xz -C "$TMP_DIR"
    cp -r "$TMP_DIR"/Nakul-main/nakul "${INSTALL_DIR}/"
    cp "$TMP_DIR"/Nakul-main/requirements.txt "${INSTALL_DIR}/"
    cp "$TMP_DIR"/Nakul-main/pyproject.toml "${INSTALL_DIR}/"
    rm -rf "$TMP_DIR"
    log_success "Application files deployed from GitHub"
  fi

  chown -R "${NAKUL_USER}:${NAKUL_USER}" "${INSTALL_DIR}"
}

setup_venv() {
  log_info "Setting up Python virtual environment..."

  if [ -d "${VENV_DIR}" ] && [ "$UPGRADE" = true ]; then
    log_info "Upgrading existing virtual environment..."
  elif [ -d "${VENV_DIR}" ]; then
    log_info "Virtual environment already exists"
  else
    ${PYTHON_BIN} -m venv "${VENV_DIR}"
    log_success "Virtual environment created"
  fi

  # Install dependencies
  "${VENV_DIR}/bin/pip" install --quiet --upgrade pip
  "${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"

  chown -R "${NAKUL_USER}:${NAKUL_USER}" "${VENV_DIR}"
  log_success "Dependencies installed"
}

generate_config() {
  if [ -f "$CONFIG_FILE" ] && [ "$UPGRADE" != true ]; then
    log_info "Configuration file already exists at ${CONFIG_FILE}"
    return
  fi

  log_info "Generating configuration..."

  # Generate admin password
  ADMIN_PASSWORD=$(${VENV_DIR}/bin/python -c "import secrets; print(secrets.token_urlsafe(16))")
  ADMIN_HASH=$(${VENV_DIR}/bin/python -c "from passlib.context import CryptContext; print(CryptContext(schemes=['bcrypt']).hash('${ADMIN_PASSWORD}'))")

  # Generate secret key
  SECRET_KEY=$(${VENV_DIR}/bin/python -c "import secrets; print(secrets.token_hex(32))")

  cat > "$CONFIG_FILE" <<YAML
# Nakul Server Intelligence Platform — Configuration
# Generated on $(date -u +"%Y-%m-%dT%H:%M:%SZ")

server:
  host: "0.0.0.0"
  port: ${NAKUL_PORT}
  workers: 1
  debug: false
  log_level: "info"
  ip_allowlist: []

auth:
  secret_key: "${SECRET_KEY}"
  algorithm: "HS256"
  access_token_expire_minutes: 60
  admin_username: "admin"
  admin_password_hash: "${ADMIN_HASH}"

database:
  path: "${DATA_DIR}/nakul.db"
  wal_mode: true
  retention_days: 30

collector:
  scan_interval_seconds: 30
  log_batch_size: 1000
  system_metrics_interval_seconds: 15
  service_check_interval_seconds: 60

log_paths:
  apache_access: "/var/log/apache2/access_log"
  apache_error: "/var/log/apache2/error_log"
  litespeed_access: "/usr/local/lsws/logs/access.log"
  litespeed_error: "/usr/local/lsws/logs/error.log"
  cpanel_access: "/usr/local/cpanel/logs/access_log"
  cpanel_error: "/usr/local/cpanel/logs/error_log"
  mysql_error: "/var/log/mysql/error.log"
  mysql_slow: "/var/log/mysql/slow.log"
  imunify360: "/var/log/imunify360/console.log"
  csf_log: "/var/log/lfd.log"
  auth_log: "/var/log/secure"
  backuply: "/var/log/backuply.log"
  syslog: "/var/log/messages"

alerts:
  cpu_warning_percent: 80.0
  cpu_critical_percent: 95.0
  memory_warning_percent: 85.0
  memory_critical_percent: 95.0
  disk_warning_percent: 85.0
  disk_critical_percent: 95.0
  cooldown_seconds: 300

notifications:
  dashboard_enabled: true
  email_enabled: false
  webhook_enabled: false

plugins:
  auto_detect: true
  litespeed_enabled: true
  cloudlinux_enabled: true
  imunify360_enabled: true
  csf_enabled: true
  backuply_enabled: true
  softaculous_enabled: true
  wptoolkit_enabled: true
YAML

  chmod 640 "$CONFIG_FILE"
  chown root:"${NAKUL_USER}" "$CONFIG_FILE"
  log_success "Configuration generated"

  # Save credentials for display
  echo "$ADMIN_PASSWORD" > /tmp/nakul_admin_password
  chmod 600 /tmp/nakul_admin_password
}

install_systemd_service() {
  log_info "Installing systemd service..."

  cat > "$SERVICE_FILE" <<SERVICE
[Unit]
Description=Nakul Server Intelligence & Protection Platform
Documentation=https://github.com/nakul-project/nakul
After=network.target mysqld.service

[Service]
Type=exec
WorkingDirectory=${INSTALL_DIR}
Environment=NAKUL_CONFIG=${CONFIG_FILE}
ExecStart=${VENV_DIR}/bin/python -m nakul.main --config ${CONFIG_FILE}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
TimeoutStopSec=30

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} ${LOG_DIR}
ReadOnlyPaths=${INSTALL_DIR} ${CONFIG_DIR} /var/log /etc /usr/local/cpanel /var/cpanel
ProtectHome=yes
PrivateTmp=yes

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
SERVICE

  # Grant log read access to nakul user
  usermod -aG adm "${NAKUL_USER}" 2>/dev/null || true

  systemctl daemon-reload
  systemctl enable nakul.service
  log_success "Systemd service installed and enabled"
}

start_service() {
  log_info "Starting Nakul service..."

  systemctl restart nakul.service
  sleep 3

  if systemctl is-active --quiet nakul.service; then
    log_success "Nakul service is running"
  else
    log_error "Nakul service failed to start"
    journalctl -u nakul.service --no-pager -n 20
    exit 1
  fi
}

firewall_hint() {
  # CSF
  if [ -f /etc/csf/csf.conf ]; then
    if ! grep -q "TCP_IN.*${NAKUL_PORT}" /etc/csf/csf.conf 2>/dev/null; then
      log_warn "Add port ${NAKUL_PORT} to CSF TCP_IN in /etc/csf/csf.conf"
      log_warn "Then run: csf -r"
    fi
  fi

  # firewalld
  if command -v firewall-cmd &>/dev/null; then
    if firewall-cmd --state 2>/dev/null | grep -q "running"; then
      firewall-cmd --permanent --add-port=${NAKUL_PORT}/tcp 2>/dev/null && \
      firewall-cmd --reload 2>/dev/null && \
      log_success "Port ${NAKUL_PORT} opened in firewalld" || \
      log_warn "Could not open port ${NAKUL_PORT} in firewalld"
    fi
  fi
}

print_summary() {
  ADMIN_PASSWORD=""
  if [ -f /tmp/nakul_admin_password ]; then
    ADMIN_PASSWORD=$(cat /tmp/nakul_admin_password)
    rm -f /tmp/nakul_admin_password
  fi

  # Get server IP
  SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server-ip")

  echo ""
  echo -e "${BOLD}============================================================${NC}"
  echo -e "${BOLD}  ${GREEN}✅ Nakul v${NAKUL_VERSION} Installation Complete!${NC}"
  echo -e "${BOLD}============================================================${NC}"
  echo ""
  echo -e "  ${CYAN}Dashboard URL:${NC}  http://${SERVER_IP}:${NAKUL_PORT}"
  echo ""
  echo -e "  ${CYAN}Username:${NC}       admin"
  if [ -n "$ADMIN_PASSWORD" ]; then
    echo -e "  ${CYAN}Password:${NC}       ${YELLOW}${ADMIN_PASSWORD}${NC}"
  else
    echo -e "  ${CYAN}Password:${NC}       (set during initial install)"
  fi
  echo ""
  echo -e "  ${CYAN}Config:${NC}         ${CONFIG_FILE}"
  echo -e "  ${CYAN}Database:${NC}       ${DATA_DIR}/nakul.db"
  echo -e "  ${CYAN}Logs:${NC}           ${LOG_DIR}/"
  echo -e "  ${CYAN}Service:${NC}        systemctl status nakul"
  echo ""
  echo -e "${BOLD}============================================================${NC}"
  echo ""

  if [ -n "$ADMIN_PASSWORD" ]; then
    log_warn "Save the admin password above — it will not be shown again!"
  fi
}

# =============================================================================
# Main Execution
# =============================================================================

echo ""
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ${CYAN}Nakul — Server Intelligence & Protection Platform${NC}   ${BOLD}║${NC}"
echo -e "${BOLD}║  ${NC}Bootstrap Installer v${NAKUL_VERSION}                           ${BOLD}║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

check_root
detect_os
install_system_deps
create_user
create_directories
deploy_application
setup_venv
generate_config
install_systemd_service
firewall_hint
start_service
print_summary
