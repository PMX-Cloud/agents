#!/bin/sh
set -eu

if [ "${1:-}" = "--check" ]; then
  systemctl is-enabled rpcbind.service >/dev/null 2>&1 && exit 1
  systemctl is-enabled rpcbind.socket >/dev/null 2>&1 && exit 1
  systemctl is-active rpcbind.service >/dev/null 2>&1 && exit 1
  systemctl is-active rpcbind.socket >/dev/null 2>&1 && exit 1
  exit 0
fi

systemctl disable --now rpcbind.socket rpcbind.service
