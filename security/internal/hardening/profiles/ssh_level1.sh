#!/bin/sh
set -eu

DROPIN="/etc/ssh/sshd_config.d/99-pmx-cloud.conf"
TMPFILE="${DROPIN}.tmp"

CONTENT='PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
'

if [ "${1:-}" = "--check" ]; then
  if [ -f "$DROPIN" ] \
    && grep -q "^PasswordAuthentication no$" "$DROPIN" \
    && grep -q "^PermitRootLogin no$" "$DROPIN" \
    && grep -q "^PubkeyAuthentication yes$" "$DROPIN" \
    && grep -q "^KbdInteractiveAuthentication no$" "$DROPIN" \
    && grep -q "^ChallengeResponseAuthentication no$" "$DROPIN"; then
    exit 0
  fi
  exit 1
fi

mkdir -p /etc/ssh/sshd_config.d
printf "%s" "$CONTENT" > "$TMPFILE"
chmod 0644 "$TMPFILE"
mv "$TMPFILE" "$DROPIN"

if /usr/sbin/sshd -t; then
  systemctl reload ssh
  exit 0
fi

rm -f "$DROPIN"
systemctl reload ssh || true
exit 1
