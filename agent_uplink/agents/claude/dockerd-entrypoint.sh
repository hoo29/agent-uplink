#!/bin/bash
set -eou pipefail

dockerd \
  --host=unix:///var/run/docker.sock \
  --data-root=/var/lib/docker \
  > /tmp/dockerd.log 2>&1 &

for _ in $(seq 1 30); do
  if [ -S /var/run/docker.sock ]; then
    chgrp docker /var/run/docker.sock
    chmod 0660 /var/run/docker.sock
    break
  fi
  sleep 1
done

if [ ! -S /var/run/docker.sock ]; then
  echo "dockerd did not create /var/run/docker.sock within 30s; see /tmp/dockerd.log" >&2
fi

exec runuser -u "${USERNAME}" -- sleep infinity
