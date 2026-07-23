# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Detailed docs

This file is a lean index. Read the relevant `docs/` file on demand when a task touches that area — they are not loaded
automatically:

| Doc | Read it when working on |
|---|---|
| `docs/architecture.md` | Generic-vs-agent split, per-session topology, startup sequence, key constraints (security posture, rebuild triggers), extra mounts, **module layout table**, adding a new agent |
| `docs/config-file.md` | `.agent-uplink.yaml` resolution, precedence, additive/inline rules (`agent_uplink/config.py`) |
| `docs/rules.md` | Allow-list rules, credential injection, rule schema, keyring, placeholders (`agent_uplink/rules.py`, `mitm_addon/`) |
| `docs/aws-resigning.md` | AWS SigV4 re-signing in mitm (`agent_uplink/aws.py`, `mitm_addon/filter.py`) |
| `docs/network-and-egress.md` | NetworkPolicy perimeter, SSH egress, git over HTTPS, kube cluster access (`kube.py`, `git.py`, `sshagent.py`) |
| `docs/claude-agent.md` | Claude auth modes (`--anthropic`/`--bedrock`), Maven, Ansible, private docker registry auth (`agents/claude/`) |

## What this project is

agent-uplink runs a coding agent in a Kata-containers microVM on a local k3s cluster with all outbound traffic intercepted by
mitmproxy. The agent pod has its egress restricted by a `NetworkPolicy` to the mitmproxy service only; the microVM boundary
(`runtimeClassName: kata-clh`) gives defence in depth on top of the cluster network. The mitm support pod runs with the
cluster's default runtime under a hardened security context.

The microVM also exists to make running a Docker daemon inside the pod viable: the agent container runs its own `dockerd` so the
agent can spin up testcontainers and other Docker workloads while debugging tests. (This is not Docker-in-Docker — the outer pod
runtime is k3s's containerd plus the kata microVM, not a second Docker. There is exactly one `dockerd` in the stack, inside the
agent container.) The cost is that the agent container itself runs `privileged`, root, `seccompProfile=Unconfined` inside the
kata guest — the kata guest kernel is the trust boundary, not the in-container hardening that the support pods retain.

It is agent-agnostic by design — agent-specific bits (image, auth, config files, default rules) live behind an `Agent` interface
in `agent_uplink/agents/`. Currently only `claude` is implemented; new agents are added by dropping a directory in
`agent_uplink/agents/<name>/` and registering it in `agent_uplink/agents/__init__.py`.

AWS requests are re-signed in the mitm pod regardless of agent: the agent pod's `~/.aws/credentials` holds only dummy AWS
credentials (a deterministic dummy AKIA per `--aws-profiles` profile). mitmproxy detects the SigV4 `Authorization` header, maps
the dummy AKIA to the profile's real credentials (mounted into the mitm pod as a K8s Secret), derives the service and region from
the host, strips the bogus signature and re-signs the request before forwarding it straight to AWS. Real AWS keys never enter the
agent pod. (Details: `docs/aws-resigning.md`.)

## Commands

```bash
# Install (editable)
pip install -e .
pip install -e ".[tests]"   # includes pytest
pip install -e ".[lint]"    # includes pyright

# Run — pick an agent subcommand. For claude, one of --anthropic / --bedrock is required.
agent-uplink claude --anthropic
agent-uplink claude --bedrock --aws-profiles profile1 profile2
agent-uplink claude --anthropic --force-rebuild
agent-uplink claude --anthropic --image my-image
agent-uplink claude --anthropic --mitmproxy-image mitmproxy/mitmproxy:12
agent-uplink claude --anthropic --mitm-insecure                                                   # accept any upstream cert (no TLS verify)
agent-uplink claude --anthropic --mitm-ca-cert ~/certs/corp-root.pem                              # trust extra PEM CA(s) upstream
agent-uplink claude --anthropic --rules examples/rules/atlassian.yaml
agent-uplink claude --anthropic --rules my.yaml --no-default-rules
agent-uplink claude --anthropic --agent-runtime-class kata-qemu  # override default kata-clh
agent-uplink claude --anthropic --mitm-runtime-class kata-clh    # microVM mitm too (slower)
agent-uplink claude --anthropic --ssh-cidr 10.0.0.0/24 203.0.113.7 --ssh-key-dir ~/keys/agent  # SSH egress
agent-uplink claude --anthropic --rules examples/rules/git.yaml                                   # git over HTTPS
agent-uplink claude --anthropic --git-https-rewrite git.example.com --no-git-identity             # extra host, no identity
agent-uplink claude --anthropic --kube-context dev-cluster                                        # k8s cluster access
agent-uplink claude --anthropic --kube-context ctx-a ctx-b --kubeconfig ~/.kube/extra.yaml        # multiple contexts
agent-uplink claude --anthropic --deploy-context my-cluster                                       # cluster to deploy into
agent-uplink claude --anthropic --mount-rw ~/code/repo-b ~/code/repo-c                            # mount extra repos (read-write)
agent-uplink claude --anthropic --mount-ro ~/.ansible.cfg                                         # mount a host file read-only
agent-uplink claude --anthropic --maven                                                           # opt-in: mount ~/.m2 + Maven proxy env
agent-uplink claude --anthropic -- --resume <id>                                                 # forward args to `claude`
agent-uplink claude --anthropic -- -p "prompt"                                                   # non-interactive print mode
agent-uplink claude --anthropic --debug

# Session management (orphan reaper — namespaces left by killed/crashed runs)
agent-uplink list                          # list session namespaces (status + age)
agent-uplink clean <id> [<id> ...]         # delete specific sessions (id or namespace)
agent-uplink clean --older-than 2h         # delete sessions older than a duration
agent-uplink clean --all --yes             # delete all (skip confirmation)

# Tests
pytest

# Lint / type-check (CLI equivalent of the editor's Pylance checks; run by CI)
pyright
```

**Runtime requirements** (must be on PATH): `kubectl`, `docker` (for build + push). `aws` CLI is needed only when
`--aws-profiles` is used or when an agent's own config resolves an additional AWS profile (e.g. `claude --bedrock` reads
`env.AWS_PROFILE` from `settings.json`). `ssh-keygen` (OpenSSH client) is needed only when `--ssh-key-dir` is used (to derive
public keys host-side).

**Cluster requirements**:

- A reachable k3s (or compatible) cluster with a kata RuntimeClass installed (default is `kata-clh`; `kata-qemu` and `kata-fc`
  work too — `kubectl get runtimeclass`).
- agent-uplink deploys into the kubeconfig context named by `--deploy-context` (default `local-k8s-admin`;
  pass `''` for the current-context). Distinct from `--kube-context`, which exposes clusters *to* the agent.
- A local registry pod (auto-deployed on first run to namespace `agent-uplink-system`) reachable from both the host and the
  cluster nodes at `localhost:5000`.
- A one-time `/etc/rancher/k3s/registries.yaml` config that tells containerd `localhost:5000` is insecure. `agent-uplink` will
  print the exact `sudo` commands if missing.
