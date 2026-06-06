# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**agent-uplink** runs a coding agent in a Kata-containers microVM on a local k3s cluster with all outbound traffic intercepted by mitmproxy. The agent pod has its egress restricted by a `NetworkPolicy` to the mitmproxy service only; the microVM boundary (`runtimeClassName: kata-clh`) gives defence in depth on top of the cluster network. Support pods (mitm, aws-sigv4-proxy) run with the cluster's default runtime under hardened security contexts.

The microVM also exists to make running a Docker daemon inside the pod viable: the agent container runs its own `dockerd` so the agent can spin up testcontainers and other Docker workloads while debugging tests. (This is *not* Docker-in-Docker — the outer pod runtime is k3s's containerd plus the kata microVM, not a second Docker. There is exactly one `dockerd` in the stack, inside the agent container.) The earlier "Claude in a plain Docker container" design couldn't host that. The cost is that the agent container itself runs `privileged`, root, `seccompProfile=Unconfined` *inside* the kata guest — the kata guest kernel is the trust boundary, not the in-container hardening that the support pods retain.

It is **agent-agnostic by design** — agent-specific bits (image, auth, config files, default rules) live behind an `Agent` interface in `agent_uplink/agents/`. Currently only `claude` is implemented; new agents are added by dropping a directory in `agent_uplink/agents/<name>/` and registering it in `agent_uplink/agents/__init__.py`.

AWS requests get an extra hop regardless of agent: the agent pod's `~/.aws/credentials` holds only dummy AWS credentials, mitmproxy detects the SigV4 `Authorization` header, strips it, and reroutes the request to an `aws-sigv4-proxy` pod (one per `--aws-profiles` profile) that re-signs with the real credentials kept in a K8s Secret. Real AWS keys never enter the agent pod.

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
agent-uplink claude --anthropic --rules examples/rules/atlassian.yaml
agent-uplink claude --anthropic --rules my.yaml --no-default-rules
agent-uplink claude --anthropic --agent-runtime-class kata-qemu  # override default kata-clh
agent-uplink claude --anthropic --mitm-runtime-class kata-clh    # microVM mitm too (slower)
agent-uplink claude --anthropic --ssh-cidr 10.0.0.0/24 203.0.113.7 --ssh-key-dir ~/keys/agent  # SSH egress
agent-uplink claude --anthropic --kube-context dev-cluster                                        # k8s cluster access
agent-uplink claude --anthropic --kube-context ctx-a ctx-b --kubeconfig ~/.kube/extra.yaml        # multiple contexts
agent-uplink claude --anthropic --deploy-context my-cluster                                       # cluster to deploy into
agent-uplink claude --anthropic --add-dir ~/code/repo-b ~/code/repo-c                            # mount extra repos
agent-uplink claude --anthropic --debug

# Tests
pytest

# Lint / type-check (CLI equivalent of the editor's Pylance checks; run by CI)
pyright
```

**Runtime requirements** (must be on PATH): `kubectl`, `docker` (for build + push). `aws` CLI is needed only when `--aws-profiles` is used or when an agent's own config resolves an additional AWS profile (e.g. `claude --bedrock` reads `env.AWS_PROFILE` from `settings.json`).

**Cluster requirements**:

- A reachable k3s (or compatible) cluster with a kata RuntimeClass installed (default is `kata-clh`; `kata-qemu` and `kata-fc` work too — `kubectl get runtimeclass`).
- agent-uplink deploys into the kubeconfig context named by `--deploy-context` (default `local-k8s-admin`;
  pass `''` for the current-context). Distinct from `--kube-context`, which exposes clusters *to* the agent.
- A local registry pod (auto-deployed on first run to namespace `agent-uplink-system`) reachable from both the host and the cluster nodes at `localhost:5000`.
- A one-time `/etc/rancher/k3s/registries.yaml` config that tells containerd `localhost:5000` is insecure. `agent-uplink` will print the exact `sudo` commands if missing.

## Architecture

### Generic vs agent-specific

The runtime splits cleanly into two halves:

| Layer | Files | Responsibility |
|---|---|---|
| **Generic** | `cli.py`, `k8s.py`, `bootstrap.py`, `rules.py`, `aws.py`, `session.py`, `process.py`, `mitm_addon/`, `default_rules.yaml` | mitm lifecycle, AWS SigV4 sidecars, K8s manifest assembly, registry + cert bootstrap, session cleanup, rule resolution. Knows nothing about specific agents. |
| **Agent** | `agents/base.py` (interface), `agents/<name>/...` (impl) | Image to build, auth flow, fake-creds production, K8s volumes/mounts, agent-specific default rules, per-mode auth-rule injection. |

`cli.py` is the orchestrator. It parses args, picks an `Agent` subclass from the registry, and calls its lifecycle hooks at the right points around the generic plumbing.

### Per-session topology

Every run creates a namespace `agent-uplink-<id>` containing:

```
              ┌───────────── agent-uplink-<id> ─────────────┐
              │                                             │
              │  Pod: agent (kata-clh, privileged, dockerd) │
              │    PID 1: dockerd-entrypoint.sh             │
              │    HTTPS_PROXY=http://mitm:8080             │
              │    NetworkPolicy: egress → mitm + kube-dns  │
              │                       │                     │
              │                       ▼                     │
              │  Pod: mitm  ──► Service mitm:8080           │
              │    addon: ConfigMap (filter.py)             │
              │    rules: Secret  ─► sigv4-<profile>:8080
              │    CA cert+key: Secret                      │
              │                       │                     │
              │                       ▼                     │
              │  Pod(s): sigv4-<profile>                    │
              │    creds: Secret /aws/credentials           │
              │    NetworkPolicy: ingress from mitm only    │
              │                                             │
              └─────────────────────────────────────────────┘
                                      │ egress (mitm + sigv4 only)
                                      ▼
                              real AWS / Anthropic / etc
```

Namespace cleanup (`kubectl delete ns`) is the entire teardown path.

### Startup sequence

1. Parse args, instantiate the chosen agent (e.g. `ClaudeAgent(args)`).
2. Validate cwd is under `/home/<USER>/`.
3. `bootstrap.check_registries_yaml()` — verify k3s is configured to pull from `localhost:5000`; if not, print instructions and exit.
4. `bootstrap.ensure_registry()` — apply registry Deployment/Service in `agent-uplink-system` (idempotent), wait for ready.
5. `bootstrap.ensure_mitm_certs()` — generate mitmproxy CA into `~/.agent_uplink/mitm/` via a one-shot pod with hostPath if missing.
6. `agent.discover_aws_profiles()` — agent may add to the AWS profile list (e.g. Claude bedrock mode picks up `env.AWS_PROFILE`). Combined with `--aws-profiles`, deduped.
7. `agent.prepare(session, aws_profile_names)` — host-side OAuth refresh, keyring reads, fake-creds + settings.json bytes (all in memory; no disk writes). Returns a `PreparedAgent` (the agent's auth rules + K8s Secret payloads) rather than stashing them on the instance.
8. `bootstrap.build_and_push_agent_image(...)` — assemble a temp build context (agent dir + the **public** mitm CA cert only; the CA private key never enters the context or any image layer), `docker build`, `docker push localhost:5000/<repo>:latest`. Rebuilds also fire if certs were just regenerated, `--force-rebuild`, or the image is older than `AGENT_IMAGE_MAX_AGE_SECONDS` (24 h).
9. For each AWS profile: export real AWS env vars on the host, build a per-profile shared-credentials INI as bytes, wrap in a K8s Secret (`aws-creds-<safe-profile>`).
10. Build the dummy `~/.aws/credentials` INI (deterministic AKIA per profile) as bytes, wrap in a K8s Secret (`agent-aws-creds`).
11. Resolve rules: layer in precedence order user `--rules` YAML → agent auth rules (from `prepare()`) → agent default rules → generic defaults (first match wins, generic catch-all last); expand `{{keyring:...}}` (and `{{exec:...}}` only when `--allow-exec`) placeholders; embed the `aws_sigv4_routes` map; wrap as Secret (`rules-json`).
12. `prepared.secret_payloads` — any agent-specific Secrets (`claude-settings`, `claude-fake-creds` in anthropic mode).
13. Assemble the full manifest set: namespace, ConfigMap (mitm-addon), Secrets, NetworkPolicies (default-deny + agent-egress + mitm-policy + sigv4-policy), mitm Pod + Service, one sigv4 Pod + Service per profile, agent Pod.
14. `kubectl apply -f -` for everything in one call.
15. Wait for support pods Ready, then agent pod Ready (Kata cold start + nested `dockerd` warmup is the long pole).
16. `kubectl exec -it agent -- <PodContribution.command>` — for Claude: `runuser -u <username> -- bash -lc 'cd "$WORKDIR" && exec claude --dangerously-skip-permissions'` (with `--debug`, `-d` is prepended to the `claude` flags). PID 1 (`dockerd-entrypoint.sh`) is root so it can start the nested `dockerd` and chgrp the socket; `runuser` drops the interactive session to the host UID so hostPath writes land as the host user.
17. On exit / SIGINT / SIGTERM: `kubectl delete ns <id> --wait=false` and `rmtree(session_dir)`. The cluster finishes the cascade in the background.

### Key constraints

- **Working directory**: `agent-uplink` must be run from within `/home/<USER>/` (validated in Python). `--add-dir`
  folders follow the same constraint and must not overlap (be nested within, contain, or equal) the working
  directory or each other; startup is refused otherwise. All are mounted read-write at their identical host paths.
- **Image rebuild triggers**: rebuild + push whenever mitm certs are newly generated, `--force-rebuild` is passed, the image doesn't exist locally, or it's older than `AGENT_IMAGE_MAX_AGE_SECONDS` (24 h).
- **Security posture (agent pod)**: `runtimeClassName: kata-clh` (microVM isolation; `kata-qemu` / `kata-fc` selectable via `--agent-runtime-class`). Container runs `privileged=true`, `allowPrivilegeEscalation=true`, `seccompProfile=Unconfined`, PID 1 as root — required so the nested `dockerd` can manage cgroups/namespaces/mounts/iptables inside the guest. `readOnlyRootFilesystem` is deliberately **off** here. On a privileged, root, seccomp-unconfined container it is not a boundary — the agent holds `CAP_SYS_ADMIN` and can remount the rootfs read-write at will — so it would only add friction (an explicit writable mount per path the agent touches). The container rootfs is writable; the trust boundary is the kata guest kernel plus the NetworkPolicy egress lock. Two paths are still memory-backed tmpfs because they require it regardless: `/var/lib/docker` (2Gi — the nested `dockerd`'s overlayfs upperdir, which kata's virtio-fs rejects) and `/run` (64Mi — holds the `dockerd` unix socket, unreliable on virtio-fs). The interactive session drops to the host UID via `runuser` in `container_command`. NetworkPolicy egress restricted to `mitm:8080` + `kube-dns` (plus TCP 22 to `--ssh-cidr` ranges if set — see SSH egress). Memory limit 4Gi (sized for the 2Gi tmpfs `/var/lib/docker` plus headroom for image layers and the agent process), CPU limit 1; requests are lower (1Gi / 250m) so the pod schedules on small nodes but can burst to the limit. Trust boundary is the kata guest kernel.
- **Security posture (mitm / sigv4 pods)**: full hardened container security context (`drop=[ALL]`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation=false`, `runAsNonRoot=true`, `seccompProfile=RuntimeDefault`) under the cluster default runtime (faster cold start). Egress isolation enforced by NetworkPolicy. Memory limits 512Mi / 128Mi, CPU limits 500m / 100m (requests 96Mi·50m / 48Mi·25m).

### Module layout

| File | Responsibility |
|---|---|
| `agent_uplink/__main__.py` | Entry point shim — re-exports `cli.main` |
| `agent_uplink/cli.py` | Arg parsing, signal handler wiring, manifest assembly, orchestration |
| `agent_uplink/k8s.py` | Low-level `kubectl` wrappers + typed manifest builders (Pod/Secret/ConfigMap/Service/NetworkPolicy/Deployment) and reusable volume/securityContext fragments |
| `agent_uplink/bootstrap.py` | One-time setup: local registry, k3s `registries.yaml` check, mitm CA generation, docker build+push |
| `agent_uplink/aws.py` | AWS helpers: dummy AKIA, dummy + real shared-credentials INI as bytes, profile env export, k8s-safe name sanitiser |
| `agent_uplink/kube.py` | Kubernetes context resolution: reads host kubeconfig via `kubectl config view`, validates auth method, produces sanitized pod kubeconfig + mitm wiring (allow rules, client certs, upstream CA bundle) |
| `agent_uplink/rules.py` | Rule resolution: layers user YAML + kube rules + agent auth rules + `agent.default_rules()` + generic defaults (in precedence order, generic last), resolves keyring/exec placeholders, returns JSON bytes |
| `agent_uplink/session.py` | `Session` dataclass: tracks namespace + session_dir; `cleanup()` is `kubectl delete ns --wait=false` + rmtree |
| `agent_uplink/process.py` | `run_command` (piped) + `run_interactive` (stdio-attached) |
| `agent_uplink/default_rules.yaml` | Generic baseline (allow `GET`/`OPTIONS`/`HEAD` everywhere) |
| `agent_uplink/mitm_addon/filter.py` | mitmproxy addon — enforces allow-list, injects pre-resolved headers, reroutes AWS SigV4 requests to sidecar services by dummy AKIA (stdlib only) |
| `agent_uplink/agents/__init__.py` | `AGENTS` registry keyed by agent name |
| `agent_uplink/agents/base.py` | `Agent` ABC — interface every agent implements |
| `agent_uplink/agents/claude/agent.py` | `ClaudeAgent`: per-mode auth, K8s volumes/mounts, privileged (in-pod `dockerd`) security context, container command |
| `agent_uplink/agents/claude/config.py` | Claude host-side helpers: OAuth refresh, fake-creds bytes, settings.json bytes |
| `agent_uplink/agents/claude/default_rules.yaml` | Claude-specific allow rules (Datadog log POSTs; GET-only hosts are covered by the generic rule) |
| `agent_uplink/agents/claude/Dockerfile` | Claude container image (Ubuntu 24.04, Claude CLI, AWS CLI v2, Docker engine for the in-pod `dockerd`, dev tools, baked mitm CA) |
| `agent_uplink/agents/claude/dockerd-entrypoint.sh` | Agent pod PID 1: starts nested `dockerd`, chgrp's the socket, then drops to `sleep infinity` as the agent user |
| `agent_uplink/agents/claude/certs/` | Legacy path (gitignored, not packaged). Certs live in `~/.agent_uplink/mitm/`; the image build context is assembled in a tempdir with only the public cert, so this dir is no longer written to |

## Adding a new agent

1. Create `agent_uplink/agents/<name>/` with:
   - `__init__.py` re-exporting your `Agent` subclass
   - `agent.py` subclassing `agent_uplink.agents.base.Agent`
   - `Dockerfile` for the container image
   - `default_rules.yaml` for agent-specific allow rules (optional)
   - any agent-specific config helpers
2. Register the class in `agent_uplink/agents/__init__.py`'s `AGENTS` dict.
3. Add the package to `[tool.setuptools]` in `pyproject.toml`.

The CLI picks up the new agent as a subcommand automatically. All generic infra (mitm, sigv4 sidecars, K8s Secrets, NetworkPolicy, namespace lifecycle, registry, certs) works without modification.

## Rules and credential injection

`agent-uplink` enforces an allow-list policy on every request leaving the agent pod. Credentials it injects come from one of two places: the host's OS keyring (for user-supplied rules and any agent auth rule referencing `{{keyring:...}}`) or files the agent reads directly on the host (e.g. Claude's `~/.claude/.credentials.json`). Either way, the real secret stays on the host and is only added to requests inside the mitm pod.

### Default behaviour

With no `--rules` flag, three layers apply: the agent's per-mode auth rule, agent-specific defaults (e.g. Claude's Datadog logs), and the generic catch-all (`GET`/`OPTIONS`/`HEAD` anywhere). Everything else returns `403`.

When `--rules <file>` is supplied, the user's rules are added. **Match priority is by layer, not regex length** — first match wins in this order: user rules → agent auth rule → agent defaults → generic catch-all (evaluated last). So a user rule always beats a default, and the broad `GET` catch-all is always considered last. Pass `--no-default-rules`, or set `replace_defaults: true` at the top of the YAML, to use only the user's rules; the agent's auth rule is then *also* skipped — the user supplies any auth the chosen mode needs.

### Rule schema

```yaml
replace_defaults: false   # optional; CLI --no-default-rules takes precedence

rules:
  - name: my-rule         # human-readable label, shown in mitm logs
    host: '<regex>'       # required; matched against request host with re.fullmatch
    methods: [GET, POST]  # optional; default = allow any method
    paths: ['<regex>']    # optional; default = allow any path (any matches)
    inject:               # optional
      headers:
        Authorization: 'Bearer {{keyring:my-svc:my-user}}'
```

Rules are evaluated in layer order (user → agent auth → agent defaults → generic catch-all; see Default behaviour above), first match wins. An empty `paths: []` is rejected (omit `paths` to allow any path). Header values may contain any number of placeholders, resolved on the host before the mitm pod starts:

- `{{keyring:SERVICE:USERNAME}}` — static secret from the OS keyring (`keyring.get_password()`).
- `{{exec:COMMAND}}` — stdout (trailing newline stripped) of a host shell command, run at startup. For short-lived dynamic credentials keyring can't hold (e.g. an AWS CodeArtifact auth token). **Requires `--allow-exec`**; without it, a rules file containing an `{{exec:...}}` placeholder aborts startup (so a rules file alone can't run host commands).

Resolution is single-pass, so a resolved secret value is never re-scanned for placeholders. A failed lookup/command (or any validation error) aborts startup with no pods launched. Header injection **overwrites** any same-named header already on the request.

The resolved JSON is stored as a K8s `Secret` (`rules-json`) and mounted read-only into the mitm pod; the agent pod never sees it.

### Populating the keyring

```bash
keyring set my-svc my-user           # prompts for the secret
keyring get my-svc my-user           # verify
```

- macOS → Keychain. Works out of the box.
- Windows → Credential Locker. Works out of the box.
- Linux/WSL2 → Secret Service. Requires `gnome-keyring` (or KDE's `kwallet`) running. On WSL2 you may need `sudo apt install gnome-keyring` and to start it (`dbus-launch gnome-keyring-daemon --start`), or fall back to the encrypted file backend in `keyrings.alt`.

### Examples

`examples/rules/atlassian.yaml` and `examples/rules/gitlab.yaml` show worked configurations for Atlassian Cloud (Basic auth) and GitLab (PRIVATE-TOKEN), including the `keyring set ...` command for each. `examples/rules/codeartifact.yaml` shows `{{exec:...}}` generating a CodeArtifact auth token on the host and injecting it as Maven Basic auth.

## Claude agent: auth modes

`--anthropic` and `--bedrock` are mutually exclusive and one is required for `agent-uplink claude`.

- **`--anthropic`**: requires `~/.claude/.credentials.json` on the host (populated by `claude login`). The real OAuth `accessToken` is embedded directly into the mitm rules; the pod gets a *fake* `.credentials.json` (`sk-ant-oat01-agent-uplink-*` tokens, `expiresAt` pinned ~10 years out) so the Claude CLI takes the OAuth code path and shows the welcome banner. There are no fallback auth paths in this mode — if the credentials file is missing or unparseable, startup fails.
- **`--bedrock`**: injects `AWS_BEARER_TOKEN_BEDROCK=placeholder` into the pod's settings.json. mitm swaps it for the real bearer (from `keyring get bedrock key`) on `bedrock-runtime.<region>.amazonaws.com`. If `settings.json` sets `env.AWS_PROFILE`, that profile is added to the sigv4-proxy pod list automatically (in addition to anything from `--aws-profiles`) — note that wires the agent to that profile's full IAM scope via the SigV4 hop (above), gated on your rules.

**Known limitation — host settings.json is copied wholesale.** `claude_settings_bytes` currently copies the host `settings.json` into the pod *as-is*: it drops only the top-level `sandbox` key, replaces `permissions`, and merges the mode's injected placeholder into `env`. It does **not** implement an allow-list, so secret-bearing keys — `apiKeyHelper` and any secret `env` entries (e.g. API tokens) — in your host `settings.json` **do** reach the agent container's `~/.claude/settings.json`. Keep secrets out of your host `settings.json` for now.

### Claude agent: Java / Maven

The image bundles OpenJDK 21 + Maven. When `~/.m2` exists on the host, the agent pod gets (no flag needed):

- `~/.m2/settings.xml` mounted **read-only**, `~/.m2/repository` mounted **read-write** (the agent writes downloaded artifacts straight into the host's real local repo).
- `MAVEN_OPTS` set to point the Maven JVM at `mitm:8080` — the JVM does **not** read `HTTPS_PROXY` (dockerd does), and the pod can egress only to mitm.
- `CODEARTIFACT_AUTH_TOKEN=placeholder` so `${env.CODEARTIFACT_AUTH_TOKEN}` in `settings.xml` expands; the real CodeArtifact auth is injected by mitm (see `examples/rules/codeartifact.yaml`), never entering the pod.

The mitm CA is added to the JVM truststore at image build (the JDK pulls in `ca-certificates-java`, which `update-ca-certificates` feeds from the system store), so Maven trusts mitm's TLS interception of HTTPS dependency downloads.

### Claude agent: private docker registry auth

`~/.docker/config.json` is **not** mounted into the pod. Private registry pulls (ECR, etc.) are handled purely by mitm rules, the same mechanism as every other credential — there is no docker-specific code path. The in-pod `dockerd` makes anonymous registry requests; a rule matching the registry host injects the `Authorization` header (header injection adds it even when the request had none), so the registry accepts the pull. The credential is resolved on the host and never enters the pod.

ECR uses HTTP **Basic** auth (`AWS:<token>`, token from `aws ecr get-login-password`), so a single `{{exec:...}}` rule on the registry host suffices — see `examples/rules/ecr.yaml`. Blob downloads redirect to presigned S3 URLs on a different host (no `Authorization` header) and fall through to the default `GET` allow rule. (This is unrelated to the SigV4 routing below: ECR's Basic-auth `Authorization` header is not `AWS4-HMAC-SHA256`, so it is never picked up by the sigv4 reroute.)

## AWS SigV4 routing

When one or more `--aws-profiles` are supplied (directly or via an agent's `discover_aws_profiles()` hook), a Secret `agent-aws-creds` is created with **dummy** values: a deterministic dummy AKIA per profile (`AKIA` + first 16 hex chars of `sha256(profile)`) plus a fixed dummy secret. The container's AWS SDK signs requests with these fake creds; the resulting signature is bogus and never goes to AWS.

The allow-list is checked **first**, on the original AWS host — the SigV4 reroute no longer bypasses it. Only if a rule permits the request does the addon then reroute: for a `*.amazonaws.com` request whose `Authorization` header is `AWS4-HMAC-SHA256`, it extracts the AKIA from the `Credential=` field, looks it up in the `aws_sigv4_routes` map (embedded into the rules JSON), strips the `Authorization` / `X-Amz-Date` / `X-Amz-Security-Token` / `X-Amz-Content-Sha256` headers, and reroutes to the matching `sigv4-<safe-profile>` `Service` (port 8080). The original `Host` header is preserved so the sidecar can re-sign with the real credentials for the right service/region. (SigV4 rerouting and `inject.headers` are mutually exclusive on a rerouted AWS host — the sidecar re-signs, so injected headers would be discarded.)

So an AWS host is reachable **only if an allow rule matches it** (e.g. a rule with `host: 's3\.eu-west-2\.amazonaws\.com'`); the mere presence of an AWS signature grants nothing. A request to `*.amazonaws.com` that no rule allows returns `403`. A matched AWS host signed with an unknown AKIA is forwarded unrerouted (and fails at AWS with the dummy signature); a non-`AWS4-HMAC-SHA256` request to a matched host is handled normally (e.g. anonymous `GET`).

**Security note:** the sidecar re-signs with the real profile credentials and is not scoped to a single service, so any *allowed* AWS request runs with that profile's full IAM permissions. Scope both the profile you pass and the host rules you write — don't pass broad admin profiles.

Real AWS credentials are obtained on the host via `aws configure export-credentials` (with an `aws sso login` fallback), formatted as a single-profile shared-credentials-file INI blob, and wrapped in a K8s Secret (`aws-creds-<safe-profile>`) in the session namespace. The sidecar mounts that Secret read-only at `/aws/credentials` and reads it via `AWS_SHARED_CREDENTIALS_FILE`; `AWS_PROFILE` is the only AWS-related env var on the pod. The `sigv4-policy` NetworkPolicy ensures only the mitm pod can reach those services, so the agent pod can't bypass the SigV4 hop.

## NetworkPolicy perimeter

`k3s` ships a built-in NetworkPolicy controller (iptables-based) that enforces the policies against pods' host-side veth interfaces. Kata pods only egress through that veth, so the policies hold for the agent pod too. The per-session policies are:

| Policy | Selector | Effect |
|---|---|---|
| `default-deny` | all pods | Deny all ingress + egress unless another policy allows it |
| `agent-egress` | `app=agent` | Egress only to `app=mitm` on TCP 8080 + `kube-system/kube-dns` on UDP/TCP 53, plus TCP 22 to any `--ssh-cidr` ranges (see SSH egress) |
| `mitm-policy` | `app=mitm` | Ingress from `app=agent` on TCP 8080; egress unrestricted (out to internet + sigv4 services) |
| `sigv4-policy` | `tier=sigv4` | Ingress from `app=mitm` on TCP 8080; egress unrestricted (to AWS) |

### SSH egress

By default the agent pod can only reach `mitm` and `kube-dns`, so SSH is blocked. Two flags open a controlled SSH path that **bypasses mitm** (SSH is not HTTP — there is no allow-list, rule engine, or credential injection for it; it is a different, weaker trust model than the rest of agent-uplink):

- `--ssh-cidr <CIDR> [<CIDR> ...]` — adds an `agent-egress` rule allowing **TCP 22 only** to those `ipBlock` CIDRs (a bare IP becomes `/32`; CIDRs are normalised to their network address). Everything else stays denied, and those CIDRs are reachable on no other port. This `ipBlock` set is the **sole** control on SSH egress, so scope it tightly. NetworkPolicy matches resolved IPs, not DNS names — `kube-dns` still resolves the target, but the returned IP must fall inside an allowed CIDR (mind DNS/CDN churn for hosts like GitHub).
- `--ssh-key-dir <DIR>` — mounts a host directory of SSH private keys **read-only** at the agent user's `~/.ssh` (the directory need not be named `.ssh`). Read-only keeps the untrusted agent from tampering with the keys; the cost is that `known_hosts` can't be persisted (connections still succeed; pre-seed a `known_hosts` in the dir to avoid prompts). The container user shares the host UID (`USER_UID` build arg), so `0600` host-owned keys are readable.

The two flags are independent but want each other: keys without a CIDR can't reach anything on 22, and a CIDR without keys opens egress with nothing to authenticate with — each case logs a warning. Implementation: `--ssh-cidr` flows into `_network_policies` (`cli.py`) and `--ssh-key-dir` into `_agent_pod_manifest` (`cli.py`); both are orchestrator-level (universal) concerns, so no `Agent` subclass is involved.

### Kubernetes cluster access

`--kube-context <ctx> [<ctx> ...]` exposes one or more host kubeconfig contexts to the agent. Unlike SSH egress, k8s traffic flows through mitmproxy and is fully governed by the allow-list; no NetworkPolicy is modified.

**Auth methods supported in v1:**
- Static bearer token (`user.token` or `user.tokenFile`) — injected as an `Authorization: Bearer` header on the upstream leg.
- Client certificate (`user.client-certificate-data` + `user.client-key-data`) — presented by mitmproxy during upstream TLS.

`exec`/`auth-provider` contexts (EKS, GKE, AKS, OIDC) are rejected at startup with a clear error. `insecure-skip-tls-verify` is also refused; a cluster CA is required.

**What is produced per context:**
- A sanitized pod kubeconfig (real server URL, mitm CA for trust, real credential stripped — placeholder token for bearer, no cert/key fields for client cert).
- A synthetic allow rule for the API server host; bearer rules carry the `Authorization` injection, cert rules carry none.
- For client cert auth: a `<host>.pem` file (cert + key) mounted into mitm's `client_certs` directory.
- All cluster serving CAs are combined into an upstream trust bundle (`ssl_verify_upstream_trusted_ca`) so mitmproxy can verify the API server's certificate.

`--kubeconfig <path>` overrides the source file (default: `$KUBECONFIG` then `~/.kube/config`).

Implementation lives in `agent_uplink/kube.py` (`resolve()`) and is an orchestrator-level concern wired in `cli.py`; no `Agent` subclass is involved.

See `examples/kube/README.md` for worked examples.
