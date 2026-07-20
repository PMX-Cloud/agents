#!/bin/sh
set -eu

RULES="/etc/audit/rules.d/pmx-cloud.rules"

if [ "${1:-}" = "--check" ]; then
  systemctl is-enabled auditd.service >/dev/null 2>&1 || exit 1
  [ -f "$RULES" ] || exit 1
  exit 0
fi

mkdir -p /etc/audit/rules.d
cat > "$RULES" <<'RULEEOF'
-w /etc/ssh/sshd_config -p wa -k pmx-ssh
-w /etc/ssh/sshd_config.d -p wa -k pmx-ssh
-w /etc/passwd -p wa -k pmx-identity
-w /etc/group -p wa -k pmx-identity
RULEEOF

augenrules --load
systemctl enable --now auditd.service
