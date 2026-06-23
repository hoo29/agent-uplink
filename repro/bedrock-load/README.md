# Bedrock load repro — mitm event-loop CPU starvation

Offline reproduction of agent-uplink hangs under **large requests + many subagents** on the
**bearer-token Bedrock** auth path. Runs the real `agent_uplink/mitm_addon/filter.py` inside a real
`mitmdump`, routes the matched flow to a local TLS sink, and drives concurrent large streaming
requests. Nothing reaches AWS; nothing is billed.

## Finding

The failure is **CPU / event-loop starvation of the single mitm process**, not memory.

mitmproxy is one asyncio event loop in one process. Every byte of every streamed body is pumped
through that loop. When many subagents stream large contexts concurrently, the loop saturates and
new/small requests sit in a head-of-line queue — accepted by the kernel but not yet serviced, so
**nothing is logged** and the agent **hangs**. No OOM, no pod restart.

Measured here (2 unthrottled cores, no cgroup cap):

| Condition | Canary latency (tiny request through same proxy) |
|---|---|
| No load (baseline) | p50 ~62ms, max ~87ms |
| During 40× 40MB concurrent streams | p50 ~927ms, max ~1693ms |

A trivial request slows ~15× while heavy streams are in flight, with zero error lines in the mitm
log — matching the production signature: **hangs + clean logs + no restart**.

Two things make production worse than these numbers:

1. **mitm CPU limit `500m`** (`agent_uplink/cli.py`, `_mitm_manifests` Resources) — half a core. The
   repro ran on 2 unthrottled cores and still showed a 15× blowup; under a 500m cgroup cap the loop
   is *throttled* (not killed — consistent with no restart), pushing latencies toward timeouts.
2. **One mitm pod per session** serves all subagents — no horizontal relief.

Ruled out by "no restart": memory exhaustion / OOM, and the SigV4 body-buffering path
(`stream=False` in `filter.py._begin_sigv4`) — that path is not used for bearer-token auth, where
bodies stream.

## Files

| File | Role |
|---|---|
| `run.sh` | Orchestrator: cert, real mitmdump (prod args), sink, driver. `run.sh [conc] [rounds]`. |
| `sink.py` | Fake `bedrock-runtime` TLS upstream; streams `SINK_RESP_MB`, tiny `/ping` for the canary. |
| `redirect.py` | Test-only mitm addon, loaded **after** `filter.py`; rewrites the allowed upstream to the local sink in `requestheaders`. |
| `rules.json` | Bearer-path rule: matches the Bedrock host, injects an `Authorization` header (same shape `agents/claude/agent.py` produces). |
| `driver.py` | Concurrent large-POST load generator through the proxy. |
| `canary.py` | Head-of-line probe: tiny request every 0.5s, reports latency spread. |

## Fidelity / caveats

- Real `filter.py` + real `mitmdump` (12.x) + production proxy args (`stream_large_bodies=1m`).
- `--ssl-insecure` on the upstream leg (self-signed sink cert) — same allowance the integration
  harness uses; the agent→mitm leg still validates mitm's real CA.
- `connection_strategy=lazy` is set **only in this repro** so the redirect addon can change the
  upstream after `filter.py` runs. Production resolves the real host via DNS and does not need it.
- **CPU not capped here**: the sandbox has no user systemd bus, so the prod `500m` cgroup limit
  could not be applied. The mechanism is proven; absolute latencies are optimistic — production
  under 500m will be worse.

## Re-run

```bash
# default: 8 concurrent, 1 round
bash run.sh

# heavier: 40 concurrent, 40MB request bodies, 20MB streamed responses
SINK_RESP_MB=20 REQ_MB=40 SINK_CHUNK_DELAY_S=0.002 bash run.sh 40 1
```

Tunables (env): `REQ_MB` request body size, `SINK_RESP_MB` response size, `SINK_CHUNK_DELAY_S`
inter-chunk delay (mimics token streaming), `PROXY_PORT`, `SINK_PORT`.

### Confirm magnitude outside the sandbox

To measure the real prod throttle, during a multi-subagent run against a live session:

```bash
kubectl top pod -n <session-ns> --containers   # watch the mitm container pin at ~500m
```

Or point `canary.py`/`driver.py` at a real session's mitm Service (set `PROXY` to it, `CA` to that
session's mitm CA) and compare canary latency idle vs. under subagent load.
