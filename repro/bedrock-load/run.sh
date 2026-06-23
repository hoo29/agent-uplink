#!/usr/bin/env bash
# Offline repro of the bearer-token Bedrock path under concurrent large-body load.
# Runs the REAL mitm_addon/filter.py inside real mitmdump with the production
# proxy args, routes the matched flow to a local TLS sink, and fires N concurrent
# large streaming requests. Nothing reaches AWS; nothing is billed.
#
# Usage: run.sh [concurrency] [rounds]
#   REQ_MB, SINK_RESP_MB, SINK_CHUNK_DELAY_S tunable via env.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PY="${PY:-$HOME/.venv/bin/python}"
MITM="${MITM:-$HOME/.venv/bin/mitmdump}"
FILTER="$REPO/agent_uplink/mitm_addon/filter.py"
CONC="${1:-8}"
ROUNDS="${2:-1}"

export SINK_PORT="${SINK_PORT:-8443}"
PROXY_PORT="${PROXY_PORT:-8080}"

WORK="$(mktemp -d /tmp/bedrock-load.XXXXXX)"
CONFDIR="$WORK/confdir"
mkdir -p "$CONFDIR"
echo "workdir: $WORK"

cleanup() {
  [[ -n "${SINK_PID:-}" ]] && kill "$SINK_PID" 2>/dev/null || true
  [[ -n "${MITM_PID:-}" ]] && kill "$MITM_PID" 2>/dev/null || true
}
trap cleanup EXIT

# 1. Sink TLS cert (self-signed; mitm runs --ssl-insecure on the upstream leg,
#    same allowance the integration harness uses for the echo upstream).
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/sink.key" \
  -out "$WORK/sink.crt" -days 1 -subj "/CN=bedrock-runtime.us-east-1.amazonaws.com" \
  >/dev/null 2>&1

# 2. mitm generates its own CA into CONFDIR on first start; start it, wait for CA.
"$MITM" \
  --listen-host=127.0.0.1 --listen-port="$PROXY_PORT" \
  --set confdir="$CONFDIR" \
  --set stream_large_bodies=1m \
  --set connection_strategy=lazy \
  --ssl-insecure \
  -s "$FILTER" \
  -s "$HERE/redirect.py" \
  --set rules_file="$HERE/rules.json" \
  >"$WORK/mitm.log" 2>&1 &
MITM_PID=$!
echo "mitm pid=$MITM_PID log=$WORK/mitm.log"

for _ in $(seq 1 50); do
  [[ -f "$CONFDIR/mitmproxy-ca-cert.pem" ]] && break
  sleep 0.2
done
CA="$CONFDIR/mitmproxy-ca-cert.pem"
[[ -f "$CA" ]] || { echo "mitm CA never appeared"; cat "$WORK/mitm.log"; exit 1; }

# 3. Sink up.
SINK_RESP_MB="${SINK_RESP_MB:-8}" SINK_CHUNK_DELAY_S="${SINK_CHUNK_DELAY_S:-0.001}" \
  "$PY" "$HERE/sink.py" "$WORK/sink.crt" "$WORK/sink.key" &
SINK_PID=$!
sleep 1

echo "--- mitm RSS before load ---"
ps -o rss= -p "$MITM_PID" | awk '{printf "  %.1f MB\n", $1/1024}'

# 4. Fire load.
PROXY="http://127.0.0.1:$PROXY_PORT" CA="$CA" REQ_MB="${REQ_MB:-4}" \
  "$PY" "$HERE/driver.py" "$CONC" "$ROUNDS" || true

echo "--- mitm RSS after load ---"
ps -o rss= -p "$MITM_PID" | awk '{printf "  %.1f MB\n", $1/1024}'

echo "--- mitm log tail ---"
tail -n 20 "$WORK/mitm.log"
