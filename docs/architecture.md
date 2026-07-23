# Architecture

## Generic vs agent-specific

The runtime splits into two halves:

| Layer | Files | Responsibility |
|---|---|---|
| Generic | `cli.py`, `k8s.py`, `bootstrap.py`, `rules.py`, `aws.py`, `kube.py`, `git.py`, `sshagent.py`, `session.py`, `process.py`, `mitm_addon/`, `default_rules.yaml` | mitm lifecycle, AWS SigV4 re-signing in mitm, K8s manifest assembly, registry + cert bootstrap, kube/git/ssh wiring, session cleanup, rule resolution. Knows nothing about specific agents. |
| Agent | `agents/base.py` (interface), `agents/<name>/...` (impl) | Image to build, auth flow, fake-creds production, K8s volumes/mounts, agent-specific default rules, per-mode auth-rule injection. |

`cli.py` is the orchestrator. It parses args, picks an `Agent` subclass from the registry, and calls its lifecycle hooks at the right points around the generic plumbing.

## Per-session topology

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
              │    rules: Secret                            │
              │    AWS creds: Secret (akia → real creds)    │
              │    CA cert+key: Secret                      │
              │                                             │
              └─────────────────────────────────────────────┘
                                      │ egress (mitm only)
                                      ▼
                              real AWS / Anthropic / etc
```

Namespace cleanup (`kubectl delete ns`) is the entire teardown path.

## Startup sequence

1. Parse args (`config.load_config()` folds `.agent-uplink.yaml` files into the subparser defaults first — see Configuration file), instantiate the chosen agent (e.g. `ClaudeAgent(args)`).
2. Validate cwd is under `/home/<USER>/`.
3. `bootstrap.check_registries_yaml()` — verify k3s is configured to pull from `localhost:5000`; if not, print instructions and exit.
4. `bootstrap.ensure_registry()` — apply registry Deployment/Service in `agent-uplink-system` (idempotent), wait for ready.
5. `bootstrap.ensure_mitm_certs()` — generate mitmproxy CA into `~/.agent_uplink/mitm/` via a one-shot pod with hostPath if missing.
6. `agent.discover_aws_profiles()` — agent may add to the AWS profile list (e.g. Claude bedrock mode picks up `env.AWS_PROFILE`). Combined with `--aws-profiles`, deduped.
7. `agent.prepare(session, aws_profile_names)` — host-side OAuth refresh, keyring reads, fake-creds + settings.json bytes (all in memory; no disk writes). Returns a `PreparedAgent` (the agent's auth rules + K8s Secret payloads).
8. `bootstrap.build_and_push_agent_image(...)` — assemble a temp build context (agent dir + the public mitm CA cert only; the CA private key never enters the context or any image layer), `docker build`, `docker push localhost:5000/<repo>:latest`. Rebuilds also fire if certs were just regenerated, `--force-rebuild`, or the image is older than `AGENT_IMAGE_MAX_AGE_SECONDS` (24 h).
9. Build the dummy `~/.aws/credentials` INI (deterministic AKIA per profile) as bytes, wrap in a K8s Secret (`agent-aws-creds`) for the agent pod. For each AWS profile, export real AWS env vars on the host and collect them into a single dummy-AKIA → real-credentials JSON map, wrapped in one K8s Secret (`aws-sigv4-creds`) mounted only into the mitm pod.
10. Resolve rules: layer in precedence order agent auth rules (from `prepare()`) → kube rules → user `--rules` YAML → agent default rules → generic defaults (first match wins, generic catch-all last); expand `{{keyring:...}}` (and `{{exec:...}}` only when `--allow-exec`) placeholders; wrap as Secret (`rules-json`).
11. `prepared.secret_payloads` — any agent-specific Secrets (`claude-settings`, `claude-fake-creds` in anthropic mode).
12. Assemble the full manifest set: namespace, ConfigMap (mitm-addon), Secrets, NetworkPolicies (default-deny + agent-egress + mitm-policy), mitm Pod + Service, agent Pod.
13. `kubectl apply -f -` for everything in one call.
14. Wait for the mitm pod Ready, then agent pod Ready (Kata cold start + nested `dockerd` warmup is the long pole).
15. `kubectl exec -it agent -- <PodContribution.command>` — for Claude: `runuser -u <username> -- bash -lc 'cd "$WORKDIR" && exec claude --allow-dangerously-skip-permissions'` (with `--debug`, `-d` is prepended to the `claude` flags; any args after a `--` separator on the agent-uplink command line are shell-quoted and appended, e.g. `-- --resume <id>` or `-- -p "prompt"`). The default permission mode is `auto`, set via `defaultMode` in the pod's `settings.json` (mounted at `~/.claude/settings.json`, the only scope from which Claude honours `defaultMode: auto`); `--allow-dangerously-skip-permissions` adds `bypassPermissions` to the `Shift+Tab` cycle without activating it, so a user can opt into bypass, and on models without `auto` support the mode falls back to `default` with bypass still reachable. On bedrock, `auto` additionally requires `CLAUDE_CODE_ENABLE_AUTO_MODE=1` (injected via settings env) and is supported only on Opus 4.7/4.8. PID 1 (`dockerd-entrypoint.sh`) is root so it can start the nested `dockerd` and chgrp the socket; `runuser` drops the interactive session to the host UID so hostPath writes land as the host user.
16. On exit / SIGINT / SIGTERM: `kubectl delete ns <id> --wait=false` and `rmtree(session_dir)`. The cluster finishes the cascade in the background.

## Key constraints

- **Working directory**: `agent-uplink` must be run from within `/home/<USER>/` (validated in Python). `--mount-rw`
  and `--mount-ro` paths follow the same constraint. Writable directories must not overlap (be nested within,
  contain, or equal) the working directory or each other; startup is refused otherwise. Each path is mounted at its
  identical host path (see Extra mounts).
- **Image rebuild triggers**: rebuild + push whenever mitm certs are newly generated, `--force-rebuild` is passed, the image doesn't exist locally, or it's older than `AGENT_IMAGE_MAX_AGE_SECONDS` (24 h).
- **Security posture (agent pod)**: `runtimeClassName: kata-clh` (microVM isolation; `kata-qemu` / `kata-fc` selectable via `--agent-runtime-class`). Container runs `privileged=true`, `allowPrivilegeEscalation=true`, `seccompProfile=Unconfined`, PID 1 as root — required so the nested `dockerd` can manage cgroups/namespaces/mounts/iptables inside the guest. `readOnlyRootFilesystem` is deliberately off here. On a privileged, root, seccomp-unconfined container it is not a boundary — the agent holds `CAP_SYS_ADMIN` and can remount the rootfs read-write at will — so it would only add friction (an explicit writable mount per path the agent touches). The container rootfs is writable; the trust boundary is the kata guest kernel plus the NetworkPolicy egress lock. Two paths are still memory-backed tmpfs because they require it regardless: `/var/lib/docker` (2Gi — the nested `dockerd`'s overlayfs upperdir, which kata's virtio-fs rejects) and `/run` (64Mi — holds the `dockerd` unix socket, unreliable on virtio-fs). The interactive session drops to the host UID via `runuser` in `container_command`. NetworkPolicy egress restricted to `mitm:8080` + `kube-dns` (plus TCP 22 to `--ssh-cidr` ranges if set — see SSH egress). Memory limit 4Gi (sized for the 2Gi tmpfs `/var/lib/docker` plus headroom for image layers and the agent process), CPU limit 1; requests are lower (1Gi / 250m) so the pod schedules on small nodes but can burst to the limit. Trust boundary is the kata guest kernel.
- **Security posture (mitm pod)**: full hardened container security context (`drop=[ALL]`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation=false`, `runAsNonRoot=true`, `seccompProfile=RuntimeDefault`) under the cluster default runtime (faster cold start). Holds the real AWS credentials (mounted Secret) and the resolved rules, so it is the most secret-bearing support pod — kept off any hostPath and locked down accordingly. Egress isolation enforced by NetworkPolicy. Memory limit 512Mi, CPU limit 500m (requests 96Mi·50m).

## Extra mounts

The working directory is always mounted read-write at its host path. Two orchestrator-level flags (wired in `cli.py`
via `validate_mounts` / `HostMount`; no `Agent` subclass involved) add more host paths, each mounted at its identical
host path:

- `--mount-rw <PATH> [<PATH> ...]` — host file(s)/dir(s) mounted read-write, e.g. extra repos for cross-repo work.
- `--mount-ro <PATH> [<PATH> ...]` — host file(s)/dir(s) mounted read-only, e.g. `~/.ansible.cfg` or a shared
  config dir.

Each path must exist and be under `/home/<user>/`. The same path can't be requested both read-write and read-only.
Writable directories must not overlap (be nested within, contain, or equal) the working directory or each other, so a
write can't land in two trees; read-only mounts and files may sit anywhere (e.g. a read-only file inside a read-write
dir). The hostPath type (`File`/`Directory`) is auto-detected. There is no auto-mounting by file existence — apart from
the agent's own config (Claude's `~/.claude/*`), every host integration is explicit via a flag.

## Module layout

| File | Responsibility |
|---|---|
| `agent_uplink/__main__.py` | Entry point shim — re-exports `cli.main` |
| `agent_uplink/cli.py` | Arg parsing, signal handler wiring, manifest assembly, orchestration, `list`/`clean` dispatch |
| `agent_uplink/config.py` | `.agent-uplink.yaml` resolution: discover files cwd→`~`, derive the schema from the chosen subparser's actions, fold into argparse defaults (scalars override, repeatable flags additive) |
| `agent_uplink/k8s.py` | Low-level `kubectl` wrappers + typed manifest builders (Pod/Secret/ConfigMap/Service/NetworkPolicy/Deployment) and reusable volume/securityContext fragments |
| `agent_uplink/bootstrap.py` | One-time setup: local registry, k3s `registries.yaml` check, mitm CA generation, docker build+push |
| `agent_uplink/aws.py` | AWS helpers: dummy AKIA, dummy `~/.aws/credentials` INI for the agent, real per-AKIA credentials JSON for the mitm pod, profile env export |
| `agent_uplink/kube.py` | Kubernetes context resolution: reads host kubeconfig via `kubectl config view`, validates auth method, produces sanitized pod kubeconfig + mitm wiring (allow rules, client certs, upstream CA bundle) |
| `agent_uplink/rules.py` | Rule resolution: layers agent auth rules + kube rules + user YAML + `agent.default_rules()` + generic defaults (in precedence order, generic last), resolves keyring/exec placeholders, returns JSON bytes |
| `agent_uplink/sshagent.py` | SSH agent-forwarding relay: splits `--ssh-key-dir` into private keys (holder pod's `ssh-agent`) and public keys + `config` (agent pod); derives missing `.pub` halves |
| `agent_uplink/session.py` | `Session` dataclass: tracks namespace + session_dir; `cleanup()` is `kubectl delete ns --wait=false` + rmtree |
| `agent_uplink/reaper.py` | `list` / `clean` subcommands: find session namespaces by `managed-by=agent-uplink`, filter by id/age/all, delete leftovers from killed runs |
| `agent_uplink/process.py` | `run_command` (piped) + `run_interactive` (stdio-attached) |
| `agent_uplink/default_rules.yaml` | Generic baseline (allow `GET`/`OPTIONS`/`HEAD` everywhere) |
| `agent_uplink/mitm_addon/filter.py` | mitmproxy addon — enforces allow-list, injects pre-resolved headers, re-signs AWS SigV4 requests in place with real per-AKIA credentials (stdlib SigV4 implementation; parses service/region from the host) |
| `agent_uplink/agents/__init__.py` | `AGENTS` registry keyed by agent name |
| `agent_uplink/agents/base.py` | `Agent` ABC — interface every agent implements |
| `agent_uplink/agents/claude/agent.py` | `ClaudeAgent`: per-mode auth, K8s volumes/mounts, privileged (in-pod `dockerd`) security context, container command |
| `agent_uplink/agents/claude/config.py` | Claude host-side helpers: OAuth refresh, fake-creds bytes, settings.json bytes |
| `agent_uplink/agents/claude/default_rules.yaml` | Claude-specific allow rules (Datadog log POSTs; GET-only hosts are covered by the generic rule) |
| `agent_uplink/agents/claude/Dockerfile` | Claude container image (Ubuntu 24.04, Claude CLI, AWS CLI v2, Docker engine for the in-pod `dockerd`, dev tools, baked mitm CA) |
| `agent_uplink/agents/claude/dockerd-entrypoint.sh` | Agent pod PID 1: starts nested `dockerd`, chgrp's the socket, then drops to `sleep infinity` as the agent user |
| `agent_uplink/agents/claude/certs/` | Unused path (gitignored, not packaged). Certs live in `~/.agent_uplink/mitm/`; the image build context is assembled in a tempdir with only the public cert, so this dir is not written to |

## Adding a new agent

1. Create `agent_uplink/agents/<name>/` with:
   - `__init__.py` re-exporting your `Agent` subclass
   - `agent.py` subclassing `agent_uplink.agents.base.Agent`
   - `Dockerfile` for the container image
   - `default_rules.yaml` for agent-specific allow rules (optional)
   - any agent-specific config helpers
2. Register the class in `agent_uplink/agents/__init__.py`'s `AGENTS` dict.
3. Add the package to `[tool.setuptools]` in `pyproject.toml`.

The CLI picks up the new agent as a subcommand automatically. All generic infra (mitm, AWS SigV4 re-signing, K8s Secrets, NetworkPolicy, namespace lifecycle, registry, certs) works without modification.
