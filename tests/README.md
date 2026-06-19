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
   intercepted HTTPS), denied requests get 403, path rules are honoured, and a
   signed AWS request to an unlisted host is denied (a signature is not a
   backdoor around the allow-list). The real AWS credentials live in the mitm
   pod that re-signs and never reach the agent pod. The re-sign + forward crypto
   itself (canonical request, signature, body hashing, session tokens) is
   validated end-to-end against real AWS by the live test below.

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
  stripped.

A `warmup` poll gates each test on the full agent→mitm→upstream path being live,
because `kubectl wait Ready` returns before Service endpoints and NetworkPolicy
rules are programmed.

### Note: mitmproxy version

The mitm pod and the addon target mitmproxy 12.x (the image is pinned to
`mitmproxy/mitmproxy:12`). `tests/unit/test_mitm_addon.py` imports the addon
under whatever mitmproxy is installed in your venv, so keep that on 12.x too
(`pip install -e ".[tests]" mitmproxy`).

## Live SigV4 signing check (real AWS)

The unit and integration suites pin the addon's host parsing, signature shape
and the security gates, but they never reach real AWS, so they can't prove the
re-signed request is cryptographically valid. That is checked manually, against
real AWS, by running the production addon under a local `mitmdump`:

1. Build the real-credentials map for a profile's dummy AKIA and a dummy
   `~/.aws/credentials` the "agent" side signs with (see `agent_uplink.aws`:
   `dummy_akia`, `dummy_aws_credentials_ini`, `real_aws_credentials`,
   `sigv4_credentials_json`), plus a `rules.json` allowing the AWS hosts to test.
2. Run `mitmdump` with the shipping addon and those files:

   ```bash
   mitmdump --listen-host 127.0.0.1 --listen-port 18080 \
     --set confdir=~/.agent_uplink/mitm --set stream_large_bodies=1m \
     -s agent_uplink/mitm_addon/filter.py \
     --set rules_file=rules.json --set aws_creds_file=creds.json
   ```

3. Point the AWS CLI at it with the dummy credentials and the mitm CA, then make
   real calls — STS, SSM, S3 (regional, global, virtual-hosted):

   ```bash
   HTTPS_PROXY=http://127.0.0.1:18080 \
   AWS_CA_BUNDLE=~/.agent_uplink/mitm/mitmproxy-ca-cert.pem \
   AWS_SHARED_CREDENTIALS_FILE=dummy-credentials AWS_PROFILE=<profile> \
   aws sts get-caller-identity
   ```

A `200` (the real identity / real data) confirms AWS accepted the re-signed
request; the addon log shows the detected `service/region` per request.
