#!/bin/bash
set -eo pipefail
if [[ "$WORKDIR" != "/home/$USERNAME" && "$WORKDIR" != "/home/$USERNAME/"* ]]; then
  echo "error - must be run from within /home/$USERNAME, got: $WORKDIR" >&2
  exit 1
fi

socat TCP-LISTEN:8090,fork,reuseaddr UNIX-CONNECT:/mnt/socket/uplink.sock >/dev/null 2>&1 &
cd "$WORKDIR"
exec claude -d --dangerously-skip-permissions
