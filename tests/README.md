# Tests

Two layers:

| Layer | Path | Needs a cluster? | What it covers |
|---|---|---|---|
| **unit** | `tests/unit/` | no | rule layering + validation + placeholder resolution, AWS dummy-cred derivation, the mitm addon's match/reroute logic, NetworkPolicy/env assembly, SSH-CIDR + cwd validation, the Claude fake-credential strip |
| **integration** | `tests/integration/` | yes (live k3s) | the security properties end-to-end against real pods, NetworkPolicies and a real mitmproxy running the real addon |

The integration suite is built around three security questions:

1. **Credentials never enter the agent pod** (`test_credentials.py`) — a sentinel
   secret that mitm injects on the wire, and a stand-in real OAuth token handed
   to the production fake-creds builder, are both proven absent from the agent
   pod's env and filesystem; the pod only holds dummy AWS creds and a fake
   `.credentials.json`, and the resolved-rules Secret is mounted only into mitm.
2. **Agent egress is restricted as designed** (`test_network_policy.py`,
   `test_ssh_egress.py`) — from inside the agent pod: mitm + kube-dns reachable,
   the public internet and other in-cluster pods unreachable (so mitm can't be
   bypassed), and `--ssh-cidr` opens exactly TCP 22 to exactly that CIDR.
3. **The injector / allow-list works** (`test_injector.py`, `test_sigv4.py`) —
   allowed requests reach the upstream with the injected header (over HTTP and
   intercepted HTTPS), denied requests get 403, path rules are honoured, and AWS
   SigV4 requests are rerouted to the sidecar with their signature stripped and
   Host preserved — only *after* the allow-list authorises the host.

Plus `test_dockerd.py`: a privileged pod on the default runtime runs its own dockerd,
which is what lets the whole suite run without kata installed.

## Running

Prerequisites (the same `kubectl` + `docker` + local-registry setup agent-uplink
itself needs — see the top-level CLAUDE.md):

- a reachable k3s (or compatible) cluster with its NetworkPolicy controller
  enforcing (k3s ships one);
- `/etc/rancher/k3s/registries.yaml` configured for the insecure `localhost:5000`
  registry;
- `docker` on PATH (to build + push the test image).

**No real credentials are required** — every secret in the suite is a dummy or a
sentinel.

```bash
pip install -e ".[tests]"

pytest tests/unit                 # fast, no cluster
pytest tests/integration          # live cluster
pytest tests                      # everything
pytest -m "not dockerd" tests     # skip the in-pod dockerd smoke test
```

If no cluster is reachable, the integration suite skips itself (the `cluster`
fixture), so `pytest` stays green on a bare checkout. The mitm CA and the local
registry are created on demand (reusing the product's own bootstrap), so a fresh
runner needs only the cluster + `registries.yaml`.

CI: `.github/workflows/integration-tests.yml` stands up a single-node k3s on a
GitHub runner and runs the whole suite there.

## How it works

The harness (`tests/integration/harness.py`) assembles each namespace out of the
**real** production builders — `cli._network_policies`, `cli._mitm_manifests`,
`cli._agent_env`, `rules.resolve`, `aws.*` — so the tests exercise shipping code,
not a parallel reimplementation. Only two things are swapped for testability:

- **the agent image** → a small probe image (`tests/integration/testimage/`,
  built `FROM docker:dind`) instead of the full Claude image, and **privileged +
  the default runtime** instead of `runtimeClassName: kata-*`, so the suite runs
  on any k3s without kata;
- **the upstreams** → an in-cluster `echo` server that reflects the request it
  received, so a test can read back exactly what mitm forwarded, injected or
  stripped. For SigV4 the same echo stands in for the `aws-sigv4-proxy` sidecar.

A `warmup` poll gates each test on the full agent→mitm→upstream path being live,
because `kubectl wait Ready` returns before Service endpoints and NetworkPolicy
rules are programmed.

### Note: mitmproxy version

The mitm pod and the addon target mitmproxy 12.x (the image is pinned to
`mitmproxy/mitmproxy:12`). `tests/unit/test_mitm_addon.py` imports the addon
under whatever mitmproxy is installed in your venv, so keep that on 12.x too
(`pip install -e ".[tests]" mitmproxy`).
