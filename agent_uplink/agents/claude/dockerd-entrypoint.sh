#!/bin/bash
# PID 1 for the agent pod when --docker is set. Starts dockerd as root, makes
# the socket group-accessible for the agent user, then drops PID 1 to that
# user (host UID match → hostPath writes land as the host user, not root).
# The agent itself is launched later by `kubectl exec` (which also drops privs
# via runuser, since kubectl exec uses the pod's image USER = root here).
#
# RoFS is preserved: dockerd's writable paths (/var/lib/docker, /run, /tmp)
# are emptyDir mounts supplied by the pod spec.

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
