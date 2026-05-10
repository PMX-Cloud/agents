#!/usr/bin/env bash
#
# Read-only smoke checks for a pmx-cloud-agent installed on a real Proxmox host.

set -euo pipefail

CONFIG_PATH="/etc/pmx-cloud/agent.conf"
AGENT_BIN="${PMX_CLOUD_AGENT_BIN:-pmx-cloud-agent}"
JOURNAL_LINES="80"
SKIP_SYSTEMD="false"

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --config=PATH         Agent config path (default: ${CONFIG_PATH})
  --agent-bin=PATH      Agent binary or command name (default: ${AGENT_BIN})
  --journal-lines=N     Lines to print from pmx-cloud-agent journal (default: ${JOURNAL_LINES})
  --skip-systemd        Skip systemd service checks
  --help, -h            Show this help message

Environment:
  PMX_CLOUD_AGENT_BIN   Agent binary override
EOF
}

log_section() {
  printf '\n== %s ==\n' "$1"
}

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config=*) CONFIG_PATH="${1#*=}" ;;
      --agent-bin=*) AGENT_BIN="${1#*=}" ;;
      --journal-lines=*) JOURNAL_LINES="${1#*=}" ;;
      --skip-systemd) SKIP_SYSTEMD="true" ;;
      --help|-h)
        usage
        exit 0
        ;;
      *) die "Unknown option: $1" ;;
    esac
    shift
  done
}

resolve_agent_bin() {
  if [[ "$AGENT_BIN" == */* ]]; then
    [[ -x "$AGENT_BIN" ]] || die "Agent binary is not executable: $AGENT_BIN"
    return
  fi

  if ! command -v "$AGENT_BIN" >/dev/null 2>&1; then
    die "Agent binary not found in PATH: $AGENT_BIN"
  fi
}

check_systemd_service() {
  [[ "$SKIP_SYSTEMD" == "true" ]] && return

  log_section "systemd service"
  if ! command -v systemctl >/dev/null 2>&1; then
    die "systemctl is required unless --skip-systemd is set"
  fi

  systemctl status pmx-cloud-agent --no-pager || true
  systemctl is-enabled pmx-cloud-agent
  systemctl is-active pmx-cloud-agent

  log_section "recent service logs"
  journalctl -u pmx-cloud-agent -n "$JOURNAL_LINES" --no-pager || true
}

main() {
  parse_args "$@"
  resolve_agent_bin

  log_section "agent version"
  "$AGENT_BIN" --version

  log_section "agent preflight"
  "$AGENT_BIN" --preflight --config "$CONFIG_PATH"

  log_section "read-only host diagnostics"
  "$AGENT_BIN" --diagnostics

  check_systemd_service

  log_section "smoke result"
  printf 'pmx-cloud-agent real-cluster smoke checks completed\n'
}

main "$@"
