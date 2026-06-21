# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**agent-uplink** runs a coding agent in a Kata-containers microVM on a local k3s cluster with all outbound traffic intercepted by mitmproxy. The agent pod has its egress restricted by a `NetworkPolicy` to the mitmproxy service only; the microVM boundary (`runtimeClassName: kata-clh`) gives defence in depth on top of the cluster network. The mitm support pod runs with the cluster's default runtime under a hardened security context.

The microVM also exists to make running a Docker daemon inside the pod viable: the agent container runs its own `dockerd` so the agent can spin up testcontainers and other Docker workloads while debugging tests. (This is *not* Docker-in-Docker — the outer pod runtime is k3s's containerd plus the kata microVM, not a second Docker. There is exactly one `dockerd` in the stack, inside the agent container.) The earlier "Claude in a plain Docker container" design couldn't host that. The cost is that the agent container itself runs `privileged`, root, `seccompProfile=Unconfined` *inside* the kata guest — the kata guest kernel is the trust boundary, not the in-container hardening that the support pods retain.

It is **agent-agnostic by design** — agent-specific bits (image, auth, config files, default rules) live behind an `Agent` interface in `agent_uplink/agents/`. Currently only `claude` is implemented; new agents are added by dropping a directory in `agent_uplink/agents/<name>/` and registering it in `agent_uplink/agents/__init__.py`.

AWS requests are re-signed in the mitm pod regardless of agent: the agent pod's `~/.aws/credentials` holds only dummy AWS credentials (a deterministic dummy AKIA per `--aws-profiles` profile). mitmproxy detects the SigV4 `Authorization` header, maps the dummy AKIA to the profile's real credentials (mounted into the mitm pod as a K8s Secret), derives the service and region from the host, strips the bogus signature and re-signs the request before forwarding it straight to AWS. Real AWS keys never enter the agent pod.

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

**Runtime requirements** (must be on PATH): `kubectl`, `docker` (for build + push). `aws` CLI is needed only when `--aws-profiles` is used or when an agent's own config resolves an additional AWS profile (e.g. `claude --bedrock` reads `env.AWS_PROFILE` from `settings.json`). `ssh-keygen` (OpenSSH client) is needed only when `--ssh-key-dir` is used (to derive public keys host-side).

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
| **Generic** | `cli.py`, `k8s.py`, `bootstrap.py`, `rules.py`, `aws.py`, `kube.py`, `git.py`, `sshagent.py`, `session.py`, `process.py`, `mitm_addon/`, `default_rules.yaml` | mitm lifecycle, AWS SigV4 re-signing in mitm, K8s manifest assembly, registry + cert bootstrap, kube/git/ssh wiring, session cleanup, rule resolution. Knows nothing about specific agents. |
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

### Startup sequence

1. Parse args (`config.load_config()` folds `.agent-uplink.yaml` files into the subparser defaults first — see Configuration file), instantiate the chosen agent (e.g. `ClaudeAgent(args)`).
2. Validate cwd is under `/home/<USER>/`.
3. `bootstrap.check_registries_yaml()` — verify k3s is configured to pull from `localhost:5000`; if not, print instructions and exit.
4. `bootstrap.ensure_registry()` — apply registry Deployment/Service in `agent-uplink-system` (idempotent), wait for ready.
5. `bootstrap.ensure_mitm_certs()` — generate mitmproxy CA into `~/.agent_uplink/mitm/` via a one-shot pod with hostPath if missing.
6. `agent.discover_aws_profiles()` — agent may add to the AWS profile list (e.g. Claude bedrock mode picks up `env.AWS_PROFILE`). Combined with `--aws-profiles`, deduped.
7. `agent.prepare(session, aws_profile_names)` — host-side OAuth refresh, keyring reads, fake-creds + settings.json bytes (all in memory; no disk writes). Returns a `PreparedAgent` (the agent's auth rules + K8s Secret payloads) rather than stashing them on the instance.
8. `bootstrap.build_and_push_agent_image(...)` — assemble a temp build context (agent dir + the **public** mitm CA cert only; the CA private key never enters the context or any image layer), `docker build`, `docker push localhost:5000/<repo>:latest`. Rebuilds also fire if certs were just regenerated, `--force-rebuild`, or the image is older than `AGENT_IMAGE_MAX_AGE_SECONDS` (24 h).
9. Build the dummy `~/.aws/credentials` INI (deterministic AKIA per profile) as bytes, wrap in a K8s Secret (`agent-aws-creds`) for the agent pod. For each AWS profile, export real AWS env vars on the host and collect them into a single dummy-AKIA → real-credentials JSON map, wrapped in one K8s Secret (`aws-sigv4-creds`) mounted only into the mitm pod.
10. Resolve rules: layer in precedence order agent auth rules (from `prepare()`) → kube rules → user `--rules` YAML → agent default rules → generic defaults (first match wins, generic catch-all last); expand `{{keyring:...}}` (and `{{exec:...}}` only when `--allow-exec`) placeholders; wrap as Secret (`rules-json`).
11. `prepared.secret_payloads` — any agent-specific Secrets (`claude-settings`, `claude-fake-creds` in anthropic mode).
12. Assemble the full manifest set: namespace, ConfigMap (mitm-addon), Secrets, NetworkPolicies (default-deny + agent-egress + mitm-policy), mitm Pod + Service, agent Pod.
13. `kubectl apply -f -` for everything in one call.
14. Wait for the mitm pod Ready, then agent pod Ready (Kata cold start + nested `dockerd` warmup is the long pole).
15. `kubectl exec -it agent -- <PodContribution.command>` — for Claude: `runuser -u <username> -- bash -lc 'cd "$WORKDIR" && exec claude --allow-dangerously-skip-permissions'` (with `--debug`, `-d` is prepended to the `claude` flags; any args after a `--` separator on the agent-uplink command line are shell-quoted and appended, e.g. `-- --resume <id>` or `-- -p "prompt"`). The default permission mode is `auto`, set via `defaultMode` in the pod's `settings.json` (mounted at `~/.claude/settings.json`, the only scope from which Claude honours `defaultMode: auto`); `--allow-dangerously-skip-permissions` adds `bypassPermissions` to the `Shift+Tab` cycle without activating it, so a user can opt into bypass, and on models without `auto` support the mode falls back to `default` with bypass still reachable. On bedrock, `auto` additionally requires `CLAUDE_CODE_ENABLE_AUTO_MODE=1` (injected via settings env) and is supported only on Opus 4.7/4.8. PID 1 (`dockerd-entrypoint.sh`) is root so it can start the nested `dockerd` and chgrp the socket; `runuser` drops the interactive session to the host UID so hostPath writes land as the host user.
16. On exit / SIGINT / SIGTERM: `kubectl delete ns <id> --wait=false` and `rmtree(session_dir)`. The cluster finishes the cascade in the background.

### Key constraints

- **Working directory**: `agent-uplink` must be run from within `/home/<USER>/` (validated in Python). `--mount-rw`
  and `--mount-ro` paths follow the same constraint. Writable directories must not overlap (be nested within,
  contain, or equal) the working directory or each other; startup is refused otherwise. Each path is mounted at its
  identical host path (see Extra mounts).
- **Image rebuild triggers**: rebuild + push whenever mitm certs are newly generated, `--force-rebuild` is passed, the image doesn't exist locally, or it's older than `AGENT_IMAGE_MAX_AGE_SECONDS` (24 h).
- **Security posture (agent pod)**: `runtimeClassName: kata-clh` (microVM isolation; `kata-qemu` / `kata-fc` selectable via `--agent-runtime-class`). Container runs `privileged=true`, `allowPrivilegeEscalation=true`, `seccompProfile=Unconfined`, PID 1 as root — required so the nested `dockerd` can manage cgroups/namespaces/mounts/iptables inside the guest. `readOnlyRootFilesystem` is deliberately **off** here. On a privileged, root, seccomp-unconfined container it is not a boundary — the agent holds `CAP_SYS_ADMIN` and can remount the rootfs read-write at will — so it would only add friction (an explicit writable mount per path the agent touches). The container rootfs is writable; the trust boundary is the kata guest kernel plus the NetworkPolicy egress lock. Two paths are still memory-backed tmpfs because they require it regardless: `/var/lib/docker` (2Gi — the nested `dockerd`'s overlayfs upperdir, which kata's virtio-fs rejects) and `/run` (64Mi — holds the `dockerd` unix socket, unreliable on virtio-fs). The interactive session drops to the host UID via `runuser` in `container_command`. NetworkPolicy egress restricted to `mitm:8080` + `kube-dns` (plus TCP 22 to `--ssh-cidr` ranges if set — see SSH egress). Memory limit 4Gi (sized for the 2Gi tmpfs `/var/lib/docker` plus headroom for image layers and the agent process), CPU limit 1; requests are lower (1Gi / 250m) so the pod schedules on small nodes but can burst to the limit. Trust boundary is the kata guest kernel.
- **Security posture (mitm pod)**: full hardened container security context (`drop=[ALL]`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation=false`, `runAsNonRoot=true`, `seccompProfile=RuntimeDefault`) under the cluster default runtime (faster cold start). Holds the real AWS credentials (mounted Secret) and the resolved rules, so it is the most secret-bearing support pod — kept off any hostPath and locked down accordingly. Egress isolation enforced by NetworkPolicy. Memory limit 512Mi, CPU limit 500m (requests 96Mi·50m).

### Extra mounts

The working directory is always mounted read-write at its host path. Two orchestrator-level flags (wired in `cli.py`
via `validate_mounts` / `HostMount`; no `Agent` subclass involved) add more host paths, each mounted at its identical
host path:

- `--mount-rw <PATH> [<PATH> ...]` — host file(s)/dir(s) mounted **read-write**, e.g. extra repos for cross-repo work.
- `--mount-ro <PATH> [<PATH> ...]` — host file(s)/dir(s) mounted **read-only**, e.g. `~/.ansible.cfg` or a shared
  config dir.

Each path must exist and be under `/home/<user>/`. The same path can't be requested both read-write and read-only.
Writable directories must not overlap (be nested within, contain, or equal) the working directory or each other, so a
write can't land in two trees; read-only mounts and files may sit anywhere (e.g. a read-only file inside a read-write
dir). The hostPath type (`File`/`Directory`) is auto-detected. There is no auto-mounting by file existence — apart from
the agent's own config (Claude's `~/.claude/*`), every host integration is explicit via a flag.

### Module layout

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
| `agent_uplink/agents/claude/certs/` | Legacy path (gitignored, not packaged). Certs live in `~/.agent_uplink/mitm/`; the image build context is assembled in a tempdir with only the public cert, so this dir is no longer written to |

## Configuration file

Any CLI flag can be set in a `.agent-uplink.yaml` file (`agent_uplink/config.py`). On an agent run, `parse_args()` peeks
the subcommand, then `config.load_config()` discovers every `.agent-uplink.yaml` from cwd up to and including
`~/.agent-uplink.yaml` and folds them into the chosen subparser's defaults via `set_defaults()` before the real parse.
The `list`/`clean` subcommands skip config.

Key points:

- **Schema is derived from the subparser's actions**, not hand-maintained — a new flag is configurable automatically. Keys
  are the flag's `dest` or its long option; dashes and underscores are interchangeable.
- **Precedence** (lowest to highest): `~/.agent-uplink.yaml` → … → project `./.agent-uplink.yaml` → CLI args. Scalars and
  booleans: closer file wins, CLI wins over all (`--no-debug` beats a config `debug: true`).
- **Repeatable flags are additive.** List-valued flags (`aws_profiles`, `ssh_cidr`, `mount_rw`, `mount_ro`,
  `git_https_rewrite`, `kube_context`, `rules`) accumulate across every config file *and* the CLI. This relies on argparse's
  `extend` action extending the `set_defaults` list default with the CLI values. The passthrough positional (`claude_args`,
  after `--`) is the exception: a CLI `-- …` replaces a config `claude_args:`.
- **Inline rules.** The `rules` list is special-cased (`config._STRUCTURED_LIST_DESTS`): a list item that is a mapping is
  treated as an inline rule (same schema as a rules-file entry) and passed through verbatim rather than coerced to a
  `Path`. File paths and inline rules can be mixed in one list; `rules.resolve()` concatenates all sources in order
  (earlier sources win first-match). So rules can be defined entirely inline in `.agent-uplink.yaml` with no separate file.
- **store_const flags** that share a dest (`--anthropic`/`--bedrock` → `auth_mode`) are settable by option name
  (`anthropic: true`) or dest (`auth_mode: anthropic`). Because config can supply the mode, the claude subparser's mode
  group is **not** argparse-`required`; `ClaudeAgent.__init__` enforces that one was supplied by either route.
- Values are coerced with each action's `type` (so a config `rules:` becomes a `Path`, `~` expanded). A malformed YAML,
  unknown key, or invalid value raises `config.ConfigError` and aborts startup before any pod is launched.

See `examples/agent-uplink.yaml` for a worked file.

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

## Rules and credential injection

`agent-uplink` enforces an allow-list policy on every request leaving the agent pod. Credentials it injects come from one of two places: the host's OS keyring (for user-supplied rules and any agent auth rule referencing `{{keyring:...}}`) or files the agent reads directly on the host (e.g. Claude's `~/.claude/.credentials.json`). Either way, the real secret stays on the host and is only added to requests inside the mitm pod.

### Default behaviour

With no `--rules` flag, three layers apply: the agent's per-mode auth rule, agent-specific defaults (e.g. Claude's Datadog logs), and the generic catch-all (`GET`/`OPTIONS`/`HEAD` anywhere). Everything else returns `403`.

When `--rules <file>` is supplied, the user's rules are added. `--rules` is repeatable (`--rules a.yaml b.yaml`) and the user layer can also be defined inline in `.agent-uplink.yaml` under the `rules:` key (file paths and inline rule mappings can be mixed). `rules.resolve()` takes a list of sources (each a `Path` to a YAML file or an inline rule `dict`) and concatenates them in order to form the single user layer — an earlier source wins first-match over a later one; a bare `Path`/`None` is still accepted as shorthand. **Match priority is by layer, not regex length** — first match wins in this order: agent auth rule → kube rules → user rules → agent defaults → generic catch-all (evaluated last). Auth and kube rules lead so a broad user allow rule on an overlapping host (e.g. `.*\.amazonaws\.com`) can't win first-match and strip an injected credential — a real failure mode for `--bedrock`, whose auth is a header inject on `bedrock-runtime.<region>.amazonaws.com`. The user's rules still beat the per-agent and generic defaults, and the broad `GET` catch-all is always considered last. Pass `--no-default-rules`, or set `replace_defaults: true` at the top of any rules file, to use only the user's rules; the agent's auth rule is then *also* skipped — the user supplies any auth the chosen mode needs.

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

Rules are evaluated in layer order (agent auth → kube → user → agent defaults → generic catch-all; see Default behaviour above), first match wins. An empty `paths: []` is rejected (omit `paths` to allow any path). Header values may contain any number of placeholders, resolved on the host before the mitm pod starts:

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
- **`--bedrock`**: injects `AWS_BEARER_TOKEN_BEDROCK=placeholder` into the pod's settings.json. mitm swaps it for the real bearer (from `keyring get bedrock key`) on `bedrock-runtime.<region>.amazonaws.com`. If `settings.json` sets `env.AWS_PROFILE`, that profile is added to the SigV4 re-signing credential map automatically (in addition to anything from `--aws-profiles`) — note that wires the agent to that profile's full IAM scope via the re-signing hop (above), gated on your rules.

**Known limitation — host settings.json is copied wholesale.** `claude_settings_bytes` currently copies the host `settings.json` into the pod *as-is*: it drops only the top-level `sandbox` key, replaces `permissions`, and merges the mode's injected placeholder into `env`. It does **not** implement an allow-list, so secret-bearing keys — `apiKeyHelper` and any secret `env` entries (e.g. API tokens) — in your host `settings.json` **do** reach the agent container's `~/.claude/settings.json`. Keep secrets out of your host `settings.json` for now.

### Claude agent: Java / Maven

The image bundles OpenJDK 21 + Maven. Maven support is **opt-in via `--maven`** (a claude-agent flag, since the JDK and
truststore bits are baked into the claude image). With `--maven` the agent pod gets:

- `~/.m2/settings.xml` mounted **read-only**, `~/.m2/repository` mounted **read-write** (the agent writes downloaded artifacts straight into the host's real local repo).
- `MAVEN_OPTS` set to point the Maven JVM at `mitm:8080` — the JVM does **not** read `HTTPS_PROXY` (dockerd does), and the pod can egress only to mitm.
- `CODEARTIFACT_AUTH_TOKEN=placeholder` so `${env.CODEARTIFACT_AUTH_TOKEN}` in `settings.xml` expands; the real CodeArtifact auth is injected by mitm (see `examples/rules/codeartifact.yaml`), never entering the pod.

`--maven` is a shortcut for `--mount-ro ~/.m2/settings.xml --mount-rw ~/.m2/repository` plus the Maven proxy env above;
the mount half can be reproduced with the generic flags, but the env half only comes with `--maven`.

The mitm CA is added to the JVM truststore at image build (the JDK pulls in `ca-certificates-java`, which `update-ca-certificates` feeds from the system store), so Maven trusts mitm's TLS interception of HTTPS dependency downloads.

### Claude agent: Ansible

The image bundles `ansible` (in a venv). It is **not** auto-configured. To share the host's defaults, mount the config
read-only with the generic flag: `--mount-ro ~/.ansible.cfg`. Unlike credentials, the file's contents enter the pod
verbatim — it bypasses mitm — so keep inline secrets (or `vault_password_file` references) out of it.

### Claude agent: private docker registry auth

`~/.docker/config.json` is **not** mounted into the pod. Private registry pulls (ECR, etc.) are handled purely by mitm rules, the same mechanism as every other credential — there is no docker-specific code path. The in-pod `dockerd` makes anonymous registry requests; a rule matching the registry host injects the `Authorization` header (header injection adds it even when the request had none), so the registry accepts the pull. The credential is resolved on the host and never enters the pod.

ECR uses HTTP **Basic** auth (`AWS:<token>`, token from `aws ecr get-login-password`), so a single `{{exec:...}}` rule on the registry host suffices — see `examples/rules/ecr.yaml`. Blob downloads redirect to presigned S3 URLs on a different host (no `Authorization` header) and fall through to the default `GET` allow rule. (This is unrelated to the SigV4 re-signing below: ECR's Basic-auth `Authorization` header is not `AWS4-HMAC-SHA256`, so it is never picked up by the re-signer.)

## AWS SigV4 re-signing

When one or more `--aws-profiles` are supplied (directly or via an agent's `discover_aws_profiles()` hook), a Secret `agent-aws-creds` is created with **dummy** values: a deterministic dummy AKIA per profile (`AKIA` + first 16 hex chars of `sha256(profile)`) plus a fixed dummy secret. The container's AWS SDK signs requests with these fake creds; the resulting signature is bogus and never goes to AWS.

The allow-list is checked **first**, on the original AWS host. Only if a rule permits the request does the addon re-sign it: for a `*.amazonaws.com` request whose `Authorization` header is `AWS4-HMAC-SHA256`, it extracts the AKIA from the `Credential=` field, looks it up in the real-credentials map (the `aws-sigv4-creds` Secret mounted into the mitm pod), derives the service and region from the host (a pattern parse — `service.region.amazonaws.com`, with global/region-less hosts signing as `us-east-1`; not a frozen endpoint table), strips the dummy `Authorization` / `X-Amz-Date` / `X-Amz-Security-Token` / `X-Amz-Content-Sha256` headers, and re-signs with the real credentials before forwarding straight to AWS. The original `Host` is preserved. (Re-signing and `inject.headers` are mutually exclusive on an AWS host — the re-signer overwrites `Authorization`, so injected headers would be discarded.)

S3 is signed with `x-amz-content-sha256: UNSIGNED-PAYLOAD` at headers time so large objects keep streaming; every other service buffers the body and signs the real SHA256 payload hash (AWS API bodies are small). The SigV4 implementation is stdlib-only (the addon ships as a ConfigMap into the stock mitmproxy image, so it can't use botocore).

So an AWS host is reachable **only if an allow rule matches it** (e.g. a rule with `host: 's3\.eu-west-2\.amazonaws\.com'`); the mere presence of an AWS signature grants nothing. A request to `*.amazonaws.com` that no rule allows returns `403`. A matched AWS host signed with an unknown AKIA is forwarded unchanged (and fails at AWS with the dummy signature); a non-`AWS4-HMAC-SHA256` request to a matched host is handled normally (e.g. anonymous `GET`).

**Security note:** re-signing uses the real profile credentials and is not scoped to a single service, so any *allowed* AWS request runs with that profile's full IAM permissions. Scope both the profile you pass and the host rules you write — don't pass broad admin profiles.

Real AWS credentials are obtained on the host via `aws configure export-credentials` (with an `aws sso login` fallback), collected into a single JSON map (dummy AKIA → `{access_key_id, secret_access_key, session_token?}`), and wrapped in one K8s Secret (`aws-sigv4-creds`) mounted read-only into the mitm pod only. The agent pod never sees it; `mitm-policy`'s unrestricted egress lets mitm reach the real AWS endpoints directly, and `agent-egress` confines the agent to mitm so it can't reach AWS itself.

## NetworkPolicy perimeter

`k3s` ships a built-in NetworkPolicy controller (iptables-based) that enforces the policies against pods' host-side veth interfaces. Kata pods only egress through that veth, so the policies hold for the agent pod too. The per-session policies are:

| Policy | Selector | Effect |
|---|---|---|
| `default-deny` | all pods | Deny all ingress + egress unless another policy allows it |
| `agent-egress` | `app=agent` | Egress only to `app=mitm` on TCP 8080 + `kube-system/kube-dns` on UDP/TCP 53, plus TCP 22 to any `--ssh-cidr` ranges and the `app=ssh-agent` holder on TCP 8765 when `--ssh-key-dir` is set (see SSH egress) |
| `mitm-policy` | `app=mitm` | Ingress from `app=agent` on TCP 8080; egress unrestricted (out to the internet, including the real AWS endpoints it re-signs for) |
| `ssh-agent-policy` | `app=ssh-agent` | Present only with `--ssh-key-dir`: ingress from `app=agent` on TCP 8765 (the signing bridge); no egress (the holder does pure crypto) |

### SSH egress

By default the agent pod can only reach `mitm` and `kube-dns`, so SSH is blocked. The SSH *transport* still **bypasses mitm** (SSH is not HTTP — there is no allow-list, rule engine, or per-request credential injection for it; reachability is the only control). Two flags open it:

- `--ssh-cidr <CIDR> [<CIDR> ...]` — adds an `agent-egress` rule allowing **TCP 22 only** to those `ipBlock` CIDRs (a bare IP becomes `/32`; CIDRs are normalised to their network address). Everything else stays denied, and those CIDRs are reachable on no other port. This `ipBlock` set is the **sole** control on SSH egress, so scope it tightly. NetworkPolicy matches resolved IPs, not DNS names — `kube-dns` still resolves the target, but the returned IP must fall inside an allowed CIDR (mind DNS/CDN churn for hosts like GitHub).
- `--ssh-key-dir <DIR>` — the private keys **never enter the agent pod**. They are loaded into an `ssh-agent` running in a dedicated **holder pod** (`app=ssh-agent`), and the agent reaches that agent over a `socat` TCP bridge, so it can request signatures but can never read the key bytes. This matters because the agent container is `privileged`/`CAP_SYS_ADMIN` inside the kata guest — a same-pod sidecar would not be a boundary against it, so the holder is a separate, hardened pod (non-root, read-only root, `drop=[ALL]`), modelled on mitm. Host→key mapping stays client-side: for each private key a `<name>.pub` is derived host-side via `ssh-keygen -y` (which also rejects passphrase-protected keys, since the holder's `ssh-add` runs non-interactively) and, with any `config`, dropped file-by-file into the agent's `~/.ssh` via per-file subPath mounts; the agent gets `SSH_AUTH_SOCK` pointing at the bridged socket. Per-file mounts (not a single read-only mount over `~/.ssh`, which the image pre-creates user-owned) keep the directory writable so ssh can create `known_hosts`, and `~/.ssh/config` is read by default with no Include. Pin a key to a host with `IdentityFile ~/.ssh/<name>.pub` + `IdentitiesOnly yes`; ssh loads the public half locally and the holder signs.

Topology: the holder runs `ssh-agent` + `socat TCP-LISTEN→UNIX` (port 8765); a `ssh-agent-relay` sidecar in the agent pod runs `socat UNIX-LISTEN→TCP` to present the socket locally. `agent-egress` adds a rule to the holder on 8765; `ssh-agent-policy` accepts that ingress and grants the holder no egress (it does pure crypto). The actual SSH connection still leaves the *agent* pod via the `--ssh-cidr` rule — only signing is delegated. What this buys: key **confidentiality** (no theft/reuse). What it does not buy: per-host authorization — anyone who can reach the agent socket can sign for any host the key works on, so the CIDR set remains the egress control (tighten further with OpenSSH 8.9+ destination-constrained keys if needed).

The two flags are independent but want each other: keys without a CIDR can't reach anything on 22, and a CIDR without keys opens egress with nothing to authenticate with — each case logs a warning. Implementation: `--ssh-cidr` flows into `_network_policies`, `--ssh-key-dir` is split by `agent_uplink/sshagent.py` into the holder + agent Secrets and wired in `cli.py` (`_ssh_agent_manifests`, the relay sidecar in `_agent_pod_manifest`); both are orchestrator-level (universal) concerns, so no `Agent` subclass is involved. The holder/sidecar reuse the agent image purely for its `ssh-agent`/`socat` binaries.

### Git over HTTPS

SSH egress (above) is for shelling into machines, not git: it bypasses mitm, so it has no allow-list or
credential injection. Git instead runs over **HTTPS**, through mitm, so the same rule engine governs it and
injects credentials host-side.

To avoid editing existing SSH remotes, the agent image bakes `/etc/gitconfig` with git `insteadOf` rules that
rewrite SSH URLs to their HTTPS form at operation time for **github.com, gitlab.com, bitbucket.org** (both
`git@host:owner/repo` and `ssh://git@host/owner/repo`). So `git clone git@github.com:owner/repo.git` transparently
becomes an HTTPS clone routed through mitm. Submodules with SSH URLs are rewritten the same way.

Two orchestrator-level flags layer a runtime overlay on top of the baked defaults (wired in `cli.py` via
`agent_uplink/git.py`; no `Agent` subclass involved):

- `--git-https-rewrite <HOST> [<HOST> ...]` — additional hosts (e.g. self-hosted GitLab) to rewrite SSH→HTTPS.
  Auth for them still needs a matching `--rules` entry.
- `--no-git-identity` — by default the host's `user.name`/`user.email` (read via `git config --global`) are
  surfaced so commits are attributed; this flag omits them.

The overlay is shipped as the `git-config` Secret and mounted read-only at `/etc/gitconfig.d/agent-uplink.inc`,
which the baked `/etc/gitconfig` pulls in via `include.path` (a missing file is silently ignored). It carries only
name/email + host rewrites — **no secrets** — so it is safe in the agent pod; the agent's `~/.gitconfig` is left
writable. `GIT_TERMINAL_PROMPT=0` is set so denied/unconfigured auth fails fast instead of hanging.

**Auth is opt-in.** The default allow-list only permits `GET`/`OPTIONS`/`HEAD`, but git transport POSTs to
`git-upload-pack` (fetch) and `git-receive-pack` (push). Pass `--rules examples/rules/git.yaml` to allow those
endpoints and inject HTTP Basic auth (keyring value = `base64("<user>:<token>")`; the token never enters the pod).
The rule injects auth on `info/refs` too, since a private repo's discovery `GET` returns `401` otherwise. Without
such a rule, even a public clone is denied at `git-upload-pack`.

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
