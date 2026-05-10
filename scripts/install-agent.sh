#!/usr/bin/env bash
#
# pmx-Cloud Agent Installer
#
# Bootstraps the pmx-cloud agent on a Proxmox/Debian-style host.
# This installer:
# - validates prerequisites
# - installs the agent binary from a local path or URL
# - writes /etc/pmx-cloud/agent.conf
# - renders and installs a systemd unit
# - enables and starts the service
#
# Example:
#   sudo bash install-agent.sh \
#     --token=pmx_xxx \
#     --server-url=wss://ws.pmxcloud.cloud/ws/agent \
#     --binary-url=https://github.com/PMX-Cloud/agents/releases/download/v0.1.0/pmx-cloud-agent-0.1.0-linux-amd64 \
#     --binary-sha256=<sha256-from-release>
#

set -euo pipefail

CONFIG_DIR="/etc/pmx-cloud"
CONFIG_PATH="${CONFIG_DIR}/agent.conf"
DATA_DIR="/var/lib/pmx-cloud"
INSTALL_PATH="/usr/local/bin/pmx-cloud-agent"
SERVICE_PATH="/etc/systemd/system/pmx-cloud-agent.service"
DEFAULT_SERVER_URL="wss://ws.pmxcloud.cloud/ws/agent"

TOKEN="${PMX_CLOUD_TOKEN:-}"
SERVER_URL="${PMX_CLOUD_SERVER_URL:-$DEFAULT_SERVER_URL}"
OVERRIDE_DATA_DIR="${PMX_CLOUD_DATA_DIR:-}"
BINARY_URL=""
BINARY_PATH=""
BINARY_SHA256="${PMX_CLOUD_BINARY_SHA256:-}"
DRY_RUN="false"
FORCE="false"
NO_START="false"
ALLOW_INSECURE_HTTP="false"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

die() {
  log_error "$1"
  exit 1
}

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --token=VALUE           pmx-cloud agent token (or set PMX_CLOUD_TOKEN)
  --server-url=VALUE      WebSocket server URL (default: ${DEFAULT_SERVER_URL})
  --data-dir=VALUE        Override data directory (default: /var/lib/pmx-cloud)
  --binary-url=VALUE      Download agent binary from URL
  --binary-path=VALUE     Install agent binary from local file path
  --binary-sha256=VALUE   Expected SHA-256 for --binary-url downloads
  --dry-run               Print planned actions without changing the system
  --force                 Overwrite existing config/service files if needed
  --no-start              Install files and enable service, but do not start it
  --allow-insecure-http   Allow http:// binary downloads for local testing only
  --help, -h              Show this help message

Notes:
  - Exactly one of --binary-url or --binary-path is required.
  - --binary-url requires --binary-sha256 or PMX_CLOUD_BINARY_SHA256.
  - --binary-url must use https:// unless --allow-insecure-http is set.
  - This installer currently targets systemd-based Linux hosts.
EOF
}

run_cmd() {
  if [[ "$DRY_RUN" == "true" ]]; then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

require_root() {
  [[ "$DRY_RUN" == "true" ]] && return
  [[ ${EUID} -eq 0 ]] || die "This installer must be run as root"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --token=*) TOKEN="${1#*=}" ;;
      --server-url=*) SERVER_URL="${1#*=}" ;;
      --data-dir=*) OVERRIDE_DATA_DIR="${1#*=}" ;;
      --binary-url=*) BINARY_URL="${1#*=}" ;;
      --binary-path=*) BINARY_PATH="${1#*=}" ;;
      --binary-sha256=*) BINARY_SHA256="${1#*=}" ;;
      --dry-run) DRY_RUN="true" ;;
      --force) FORCE="true" ;;
      --no-start) NO_START="true" ;;
      --allow-insecure-http) ALLOW_INSECURE_HTTP="true" ;;
      --help|-h)
        usage
        exit 0
        ;;
      *) die "Unknown option: $1" ;;
    esac
    shift
  done
}

validate_inputs() {
  [[ -n "$TOKEN" ]] || die "Missing required token. Use --token or PMX_CLOUD_TOKEN"

  if [[ -n "$OVERRIDE_DATA_DIR" ]]; then
    DATA_DIR="$OVERRIDE_DATA_DIR"
  fi

  if [[ -n "$BINARY_URL" && -n "$BINARY_PATH" ]]; then
    die "Use only one of --binary-url or --binary-path"
  fi

  if [[ -z "$BINARY_URL" && -z "$BINARY_PATH" ]]; then
    die "One of --binary-url or --binary-path is required"
  fi

  if [[ -n "$BINARY_URL" && -z "$BINARY_SHA256" ]]; then
    die "Missing binary checksum. Use --binary-sha256 or PMX_CLOUD_BINARY_SHA256"
  fi

  case "$SERVER_URL" in
    ws://*|wss://*) ;;
    *) die "server-url must use ws:// or wss://" ;;
  esac

  if [[ -n "$BINARY_URL" ]]; then
    case "$BINARY_URL" in
      https://*) ;;
      http://*)
        [[ "$ALLOW_INSECURE_HTTP" == "true" ]] || die "binary-url must use https:// (use --allow-insecure-http only for local testing)"
        ;;
      *) die "binary-url must use https:// or http://" ;;
    esac
  fi
}

check_prereqs() {
  command -v uname >/dev/null 2>&1 || die "uname is required"

  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64|aarch64|arm64) ;;
    *) die "Unsupported architecture: $arch" ;;
  esac

  if [[ "$DRY_RUN" == "true" ]]; then
    log_warn "Skipping live host prerequisite checks in dry-run mode"
    return
  fi

  command -v systemctl >/dev/null 2>&1 || die "systemctl is required"
  command -v install >/dev/null 2>&1 || die "install is required"

  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      debian|ubuntu|proxmox) ;;
      *)
        if [[ "${ID_LIKE:-}" != *debian* ]]; then
          die "Unsupported OS: ${PRETTY_NAME:-unknown}. Expected Proxmox, Debian, or Ubuntu."
        fi
        ;;
    esac
  else
    log_warn "Could not read /etc/os-release; continuing because systemd is available"
  fi

  if [[ -n "$BINARY_URL" ]]; then
    command -v curl >/dev/null 2>&1 || die "curl is required when using --binary-url"
    if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
      die "sha256sum or shasum is required when using --binary-url"
    fi
  fi
}

prepare_dirs() {
  run_cmd mkdir -p "$CONFIG_DIR" "$DATA_DIR"
  run_cmd chmod 755 "$CONFIG_DIR" "$DATA_DIR"
}

install_binary() {
  if [[ -n "$BINARY_PATH" ]]; then
    [[ -f "$BINARY_PATH" ]] || die "Binary path does not exist: $BINARY_PATH"
    log_info "Installing agent binary from local path"
    run_cmd install -m 0755 "$BINARY_PATH" "$INSTALL_PATH"
    return
  fi

  log_info "Downloading agent binary"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] curl -fsSL '$BINARY_URL' -o '<temp-file>'"
    echo "[dry-run] verify SHA-256 '$BINARY_SHA256'"
    echo "[dry-run] install -m 0755 '<temp-file>' '$INSTALL_PATH'"
  else
    local temp_binary
    temp_binary="$(mktemp)"
    curl -fsSL "$BINARY_URL" -o "$temp_binary"
    verify_sha256 "$temp_binary" "$BINARY_SHA256"
    install -m 0755 "$temp_binary" "$INSTALL_PATH"
    rm -f "$temp_binary"
  fi
}

verify_sha256() {
  local path="$1"
  local expected="$2"
  local actual

  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$path" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$path" | awk '{print $1}')"
  fi

  if [[ "${actual,,}" != "${expected,,}" ]]; then
    rm -f "$path"
    die "Binary SHA-256 mismatch"
  fi
}

write_config() {
  if [[ -f "$CONFIG_PATH" && "$FORCE" != "true" ]]; then
    die "Config already exists at $CONFIG_PATH (use --force to overwrite)"
  fi

  log_info "Writing agent config"
  if [[ "$DRY_RUN" == "true" ]]; then
    cat <<EOF
[dry-run] write $CONFIG_PATH
# pmx-Cloud Agent Configuration

token = ${TOKEN}
server_url = ${SERVER_URL}
data_dir = ${DATA_DIR}
EOF
  else
    cat > "$CONFIG_PATH" <<EOF
# pmx-Cloud Agent Configuration
# This file is managed by install-agent.sh

token = ${TOKEN}
server_url = ${SERVER_URL}
data_dir = ${DATA_DIR}
EOF
    chmod 600 "$CONFIG_PATH"
  fi
}

install_service() {
  if [[ -f "$SERVICE_PATH" && "$FORCE" != "true" ]]; then
    die "Service file already exists at $SERVICE_PATH (use --force to overwrite)"
  fi

  log_info "Installing systemd service"
  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] write $SERVICE_PATH"
    echo "[dry-run] substitute INSTALL_PATH=$INSTALL_PATH CONFIG_PATH=$CONFIG_PATH DATA_DIR=$DATA_DIR"
  else
    cat > "$SERVICE_PATH" <<EOF
[Unit]
Description=pmx-Cloud Agent
Documentation=https://github.com/PMX-Cloud/agents
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
ExecStartPre=${INSTALL_PATH} --preflight --config ${CONFIG_PATH}
ExecStart=${INSTALL_PATH} --config ${CONFIG_PATH}
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=10
NoNewPrivileges=true
PrivateTmp=true
WorkingDirectory=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF
    chmod 644 "$SERVICE_PATH"
    systemctl daemon-reload
  fi
}

enable_service() {
  log_info "Enabling pmx-cloud-agent"
  run_cmd systemctl enable pmx-cloud-agent
  if [[ "$NO_START" == "true" ]]; then
    log_warn "Skipping service start because --no-start was set"
    return
  fi
  log_info "Starting pmx-cloud-agent"
  run_cmd systemctl restart pmx-cloud-agent
}

run_post_install_checks() {
  log_info "Running post-install checks"
  run_cmd "$INSTALL_PATH" --version
  run_cmd "$INSTALL_PATH" --preflight --config "$CONFIG_PATH"

  if [[ "$NO_START" == "true" ]]; then
    return
  fi

  if [[ "$DRY_RUN" == "true" ]]; then
    echo "[dry-run] systemctl is-active --quiet pmx-cloud-agent"
    return
  fi

  for _ in 1 2 3 4 5; do
    if systemctl is-active --quiet pmx-cloud-agent; then
      log_info "pmx-cloud-agent service is active"
      return
    fi
    sleep 1
  done

  systemctl status pmx-cloud-agent --no-pager || true
  die "pmx-cloud-agent service did not become active"
}

post_install_summary() {
  cat <<EOF

Installation complete.

Paths:
- Binary: ${INSTALL_PATH}
- Config: ${CONFIG_PATH}
- Data dir: ${DATA_DIR}
- Service: ${SERVICE_PATH}

Recommended verification:
- systemctl status pmx-cloud-agent
- journalctl -u pmx-cloud-agent -n 50 --no-pager
- ${INSTALL_PATH} --version
EOF
}

main() {
  parse_args "$@"
  require_root
  validate_inputs
  check_prereqs
  prepare_dirs
  install_binary
  write_config
  install_service
  enable_service
  run_post_install_checks
  post_install_summary
}

main "$@"
