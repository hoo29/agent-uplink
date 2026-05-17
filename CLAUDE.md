# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**agent-uplink** runs a coding agent in a hardened Docker container with all outbound traffic intercepted by mitmproxy. The agent container has `--network none`; instead, `socat` inside the container bridges a Unix socket to a local TCP port (8090), which in turn is forwarded by `socat` on the host to the mitmproxy container. This gives full TLS inspection of the agent's traffic without direct network access.

It is **agent-agnostic by design** — agent-specific bits (image, auth, config files, default rules) live behind an `Agent` interface in `agent_uplink/agents/`. Currently only `claude` is implemented; new agents are added by dropping a directory in `agent_uplink/agents/<name>/` and registering it in `agent_uplink/agents/__init__.py`.

AWS requests get an extra hop regardless of agent: the container holds only dummy AWS credentials, mitmproxy detects the SigV4 `Authorization` header, strips it, and reroutes the request to an `aws-sigv4-proxy` sidecar (one per `--aws-profiles` profile) that re-signs with the real credentials kept on the host. Real AWS keys never enter the agent container.

## Commands

```bash
# Install (editable)
pip install -e .
pip install -e ".[tests]"   # includes pytest

# Run — pick an agent subcommand. For claude, one of --anthropic / --bedrock is required.
agent-uplink claude --anthropic
agent-uplink claude --bedrock --aws-profiles profile1 profile2   # bedrock + extra AWS creds
agent-uplink claude --anthropic --force-rebuild
agent-uplink claude --anthropic --image my-image
agent-uplink claude --anthropic --mitmproxy-image mitmproxy/mitmproxy:latest
agent-uplink claude --anthropic --rules examples/rules/atlassian.yaml   # extra allow rules + injected creds
agent-uplink claude --anthropic --rules my.yaml --no-default-rules      # disable defaults (you must supply auth for bedrock)
agent-uplink claude --anthropic --runtime runc                          # override gVisor default
agent-uplink claude --anthropic --debug                                  # mount claude debug logs to host

# Tests (no tests exist yet, but the runner is)
pytest
```

**Runtime requirements** (must be on PATH): `docker`, `socat`. `aws` CLI is needed only when `--aws-profiles` is used or when an agent's own config resolves an additional AWS profile (e.g. `claude --bedrock` reads `env.AWS_PROFILE` from `settings.json`).

## Architecture

### Generic vs agent-specific

The runtime splits cleanly into two halves:

| Layer | Files | Responsibility |
|---|---|---|
| **Generic** | `cli.py`, `docker_ops.py`, `rules.py`, `aws.py`, `session.py`, `secret.py`, `process.py`, `mitm_addon/`, `default_rules.yaml` | mitmproxy lifecycle, AWS SigV4 sidecars, locked secrets, docker network, session cleanup, rule resolution. Knows nothing about specific agents. |
| **Agent** | `agents/base.py` (interface), `agents/<name>/...` (impl) | Image to build, auth flow, fake-creds dance, mounts, agent-specific default rules, per-mode auth-rule injection. |

`cli.py` is the orchestrator. It parses args, picks an `Agent` subclass from the registry, and calls its lifecycle hooks at the right points around the generic plumbing.

### Startup sequence

1. Parse args, instantiate the chosen agent (e.g. `ClaudeAgent(args)`).
2. Validate cwd is under `/home/<USER>/`.
3. Generate mitmproxy TLS certs into `~/.agent_uplink/mitm/` (once, via a throwaway mitmproxy container).
4. `agent.resolve_auth(session)` — host-side credential work (e.g. Claude refreshes/reads `~/.claude/.credentials.json` and writes a fake one into the session dir, or reads the bedrock bearer from the keyring).
5. `agent.discover_aws_profiles()` — agent may add to the AWS profile list (e.g. Claude bedrock mode picks up `env.AWS_PROFILE`). Combined with `--aws-profiles`, deduped.
6. Build the agent image (`agent-uplink-<name>` by default) — certs are copied into the build context so the container trusts mitmproxy's CA. Rebuilds also fire if the existing image is older than 24 h (`AGENT_IMAGE_MAX_AGE_SECONDS`).
7. For each AWS profile: export the real AWS env vars on the host, write them as a shared-credentials-file INI blob into a per-profile `LockedSecret` (mlock'd `/dev/shm`, mode 0600) for bind-mounting into the sidecar; and write a dummy `~/.aws/credentials` file (mode 0600) with a deterministic dummy AKIA per profile for the agent container.
8. `agent.write_session_files(session, aws_profile_names)` — agent-specific config (e.g. Claude writes a filtered `settings.json` with `awsAuthRefresh`/`sandbox` stripped, `skipDangerousModePermissionPrompt: true`, and any auth env merged in).
9. `agent.build_mounts(...)` — assemble `-v` / `--tmpfs` flags for the agent container.
10. Resolve rules via `rules.resolve(...)`: layer `default_rules.yaml` (generic baseline) + `agent.default_rules()` (per-agent YAML) + `agent.auth_rules()` (per-mode header injection) + user's `--rules` YAML. Expand `{{keyring:...}}` placeholders, embed `aws_sigv4_routes`, store JSON in a `LockedSecret`.
11. If there are AWS profiles, create a per-session docker network `agent-uplink-net-<id>`.
12. Start mitmproxy container on a random host port (attached to the docker network if present) with the addon (`mitm_addon/filter.py`) and resolved rules mounted read-only; start host-side `socat` forwarding `~/.agent_uplink/<uuid>/sockets/uplink.sock` → `127.0.0.1:<port>`.
13. For each AWS profile, start an `aws-sigv4-proxy` sidecar on the docker network.
14. Start the agent container (interactive, `--network none`, default `--runtime=runsc`) with the mounts and env vars the agent supplied. The agent's `entrypoint.sh` does any container-side init (e.g. starting `socat` to bridge TCP 8090 → the Unix socket) and execs the agent CLI.
15. On SIGINT/SIGTERM: stop all containers (mitm + sidecars + agent, 3 s timeout), terminate background processes, scrub `LockedSecret`s, remove the docker network, delete the session directory.

### Key constraints

- **Working directory**: `agent-uplink` must be run from within `/home/<USER>/` (validated in both Python and `entrypoint.sh`).
- **Image rebuild triggers**: the agent image is (re)built whenever mitmproxy certs are newly generated, `--force-rebuild` is passed, the image doesn't exist, or it's older than `AGENT_IMAGE_MAX_AGE_SECONDS` (24 h). Certs are baked into the image, so if certs change the image must be rebuilt.
- **Security posture**: `--cap-drop=ALL`, `--read-only` root FS, `--pids-limit 300`, `--security-opt no-new-privileges`. Memory is 1 GiB for the agent container, 0.5 GiB for mitmproxy, 128 MiB for each sigv4-proxy sidecar; `--cpus 1` on all of them.

### Module layout

| File | Responsibility |
|---|---|
| `agent_uplink/__main__.py` | Entry point shim — re-exports `cli.main` so `python -m agent_uplink` works |
| `agent_uplink/cli.py` | Arg parsing (subcommand-per-agent), signal handler wiring, top-level orchestration |
| `agent_uplink/aws.py` | Generic AWS helpers: dummy AKIA, dummy + real shared-credentials INI, profile env export |
| `agent_uplink/docker_ops.py` | All `docker` invocations + `DOCKER_RUN_FLAGS` shared by all containers; per-session network + mitm + sigv4 sidecars + generic agent container start |
| `agent_uplink/process.py` | `run_command`, `run_command_background`, `get_free_port` |
| `agent_uplink/session.py` | `Session` dataclass: tracks containers/processes/secrets; idempotent `cleanup()` |
| `agent_uplink/secret.py` | `LockedSecret`: mlock'd `/dev/shm` file (mode 0600) used to ferry rules JSON and AWS creds into containers without env vars or on-disk persistence |
| `agent_uplink/rules.py` | Generic rule resolution; layers generic defaults + `agent.default_rules()` + `agent.auth_rules()` + user YAML, resolves keyring placeholders, stores JSON in a `LockedSecret` |
| `agent_uplink/default_rules.yaml` | Generic baseline (allow `GET`/`OPTIONS`/`HEAD` everywhere) |
| `agent_uplink/mitm_addon/filter.py` | mitmproxy addon — enforces allow-list, injects pre-resolved headers, and reroutes AWS SigV4 requests to sidecars by dummy AKIA (stdlib only; runs inside the mitmproxy container) |
| `agent_uplink/agents/__init__.py` | `AGENTS` registry keyed by agent name |
| `agent_uplink/agents/base.py` | `Agent` ABC — interface every agent implements |
| `agent_uplink/agents/claude/agent.py` | `ClaudeAgent`: per-mode auth (anthropic OAuth vs bedrock keyring), settings env injection, mount layout, auth rule |
| `agent_uplink/agents/claude/config.py` | Claude-specific host-side config: OAuth refresh, fake-creds generation, settings.json read/filter |
| `agent_uplink/agents/claude/default_rules.yaml` | Claude-specific allow rules (Datadog logs, changelog, downloads) |
| `agent_uplink/agents/claude/Dockerfile` | Claude container image (Ubuntu 24.04, Claude CLI, AWS CLI v2, dev tools) |
| `agent_uplink/agents/claude/entrypoint.sh` | Container init: validates `$WORKDIR`, starts socat proxy bridge, execs Claude |
| `agent_uplink/agents/claude/certs/` | Runtime-generated mitmproxy certs (gitignored, copied in at image build) |

## Adding a new agent

1. Create `agent_uplink/agents/<name>/` with:
   - `__init__.py` re-exporting your `Agent` subclass
   - `agent.py` subclassing `agent_uplink.agents.base.Agent`
   - `Dockerfile` and `entrypoint.sh` for the container
   - `default_rules.yaml` for agent-specific allow rules (optional)
   - any agent-specific config helpers
2. Register the class in `agent_uplink/agents/__init__.py`'s `AGENTS` dict.
3. Add the package to `[tool.setuptools]` in `pyproject.toml` so the wheel ships it.

The CLI will pick up the new agent as a subcommand automatically. All generic infra (mitm, sigv4 sidecars, locked secrets, session cleanup) works without modification.

## Rules and credential injection

`agent-uplink` enforces an allow-list policy on every request leaving the agent container. Credentials it injects come from one of two places: the host's OS keyring (for user-supplied rules and any agent auth rule referencing `{{keyring:...}}`) or files the agent reads directly on the host (e.g. Claude's `~/.claude/.credentials.json`). Either way, the real secret stays on the host and is only added to requests inside the mitmproxy container.

### Default behaviour

With no `--rules` flag, three layers are loaded in order: generic defaults (`GET`/`OPTIONS`/`HEAD` anywhere) → agent-specific defaults (e.g. Claude's Datadog logs/changelog/downloads) → the agent's per-mode auth rule. Everything else returns `403`.

When `--rules <file>` is supplied, the user's rules are **appended** to those layers. Pass `--no-default-rules`, or set `replace_defaults: true` at the top of the YAML, to use only the user's rules. Under `--no-default-rules`, the agent's auth rule is *also* skipped — the user is responsible for supplying any auth that the chosen mode needs.

### Rule schema

```yaml
replace_defaults: false   # optional; CLI --no-default-rules takes precedence

rules:
  - name: my-rule         # human-readable label, shown in mitmproxy logs
    host: '<regex>'       # required; matched against request host with re.fullmatch
    methods: [GET, POST]  # optional; default = allow any method
    paths: ['<regex>']    # optional; default = allow any path (any matches)
    inject:               # optional
      headers:
        Authorization: 'Bearer {{keyring:my-svc:my-user}}'
```

Rules iterate in order, sorted by host-regex length (longest first); first match wins. Header values may contain any number of `{{keyring:SERVICE:USERNAME}}` placeholders, which are resolved on the host via `keyring.get_password()` before the mitmproxy container starts. A failed lookup (or any validation error) aborts startup with no containers launched.

The resolved JSON is stored in a `LockedSecret` (mlock'd `/dev/shm` file, mode `0o600`) and bind-mounted read-only into the mitmproxy container; the agent container never sees it.

### Populating the keyring

```bash
keyring set my-svc my-user           # prompts for the secret
keyring get my-svc my-user           # verify
```

- macOS → Keychain. Works out of the box.
- Windows → Credential Locker. Works out of the box.
- Linux/WSL2 → Secret Service. Requires `gnome-keyring` (or KDE's `kwallet`) running. On WSL2 you may need `sudo apt install gnome-keyring` and to start it (`dbus-launch gnome-keyring-daemon --start`), or fall back to the encrypted file backend in `keyrings.alt`.

### Examples

`examples/rules/atlassian.yaml` and `examples/rules/gitlab.yaml` show worked configurations for Atlassian Cloud (Basic auth) and GitLab (PRIVATE-TOKEN), including the `keyring set ...` command for each.

## Claude agent: auth modes

`--anthropic` and `--bedrock` are mutually exclusive and one is required for `agent-uplink claude`.

- **`--anthropic`**: requires `~/.claude/.credentials.json` on the host (populated by `claude login`). The real OAuth `accessToken` is embedded directly into the mitmproxy rules; the container gets a *fake* `.credentials.json` (`sk-ant-oat01-agent-uplink-*` tokens, `expiresAt` pinned ~10 years out) so the Claude CLI takes the OAuth code path and shows the welcome banner. There are no fallback auth paths in this mode — if the credentials file is missing or unparseable, startup fails.
- **`--bedrock`**: injects `AWS_BEARER_TOKEN_BEDROCK=placeholder` into the container's settings.json. mitmproxy swaps it for the real bearer (from `keyring get bedrock key`) on `bedrock-runtime.<region>.amazonaws.com`. If `settings.json` sets `env.AWS_PROFILE`, that profile is added to the sigv4-proxy sidecar list automatically (in addition to anything from `--aws-profiles`).

## AWS SigV4 routing

When one or more `--aws-profiles` are supplied (directly or via an agent's `discover_aws_profiles()` hook), the container's `~/.aws/credentials` is populated with **dummy** values: a deterministic dummy AKIA per profile (`AKIA` + first 16 hex chars of `sha256(profile)`) plus a fixed dummy secret. The container's AWS SDK signs requests with these fake creds; the resulting signature is bogus and never goes to AWS.

The mitm addon detects requests whose host ends in `.amazonaws.com` and whose `Authorization` header is `AWS4-HMAC-SHA256`. It extracts the AKIA from the `Credential=` field, looks it up in the `aws_sigv4_routes` map, strips the `Authorization` / `X-Amz-Date` / `X-Amz-Security-Token` / `X-Amz-Content-Sha256` headers, and reroutes the request to the matching `aws-sigv4-proxy` sidecar over plain HTTP on a per-session docker network. The original `Host` header is preserved so the sidecar can determine the target service/region and re-sign with the real credentials before forwarding to AWS.

Requests to `*.amazonaws.com` with no matching SigV4 route return `403`. Requests with no `Authorization: AWS4-HMAC-SHA256` header fall through to the normal allow-list (e.g. anonymous `GET` to a public S3 bucket).

Real AWS credentials are obtained on the host via `aws configure export-credentials` (with an `aws sso login` fallback), formatted as a single-profile shared-credentials-file INI blob, and stored in a per-profile `LockedSecret` (mlock'd `/dev/shm` file, mode 0600). The sidecar bind-mounts that file read-only at `/aws/credentials` and reads it via `AWS_SHARED_CREDENTIALS_FILE`; `AWS_PROFILE` is the only AWS-related env var on the container. This avoids `docker run -e AWS_SECRET_ACCESS_KEY=...`, which would expose creds to any host user with docker access (`docker inspect`) and to the sidecar's `/proc/<pid>/environ`. Creds never enter the agent container, never hit disk, and the sidecar is on a docker network unreachable from the agent container (`--network none`).
