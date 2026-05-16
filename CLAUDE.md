# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**agent-uplink** runs Claude in a hardened Docker container with all outbound traffic intercepted by mitmproxy. The Claude container has `--network none`; instead, `socat` inside the container bridges a Unix socket to a local TCP port (8090), which in turn is forwarded by `socat` on the host to the mitmproxy container. This gives full TLS inspection of Claude's traffic without direct network access.

AWS requests get an extra hop: the container holds only dummy AWS credentials, mitmproxy detects the SigV4 `Authorization` header, strips it, and reroutes the request to an `aws-sigv4-proxy` sidecar (one per `--aws-profiles` profile) that re-signs with the real credentials kept on the host. Real AWS keys never enter the Claude container.

## Commands

```bash
# Install (editable)
pip install -e .
pip install -e ".[tests]"   # includes pytest

# Run (one of --anthropic / --bedrock is required)
agent-uplink --anthropic
agent-uplink --bedrock --aws-profiles profile1 profile2   # bedrock + extra AWS creds
agent-uplink --anthropic --force-rebuild
agent-uplink --anthropic --claude-image my-image
agent-uplink --anthropic --mitmproxy-image mitmproxy/mitmproxy:latest
agent-uplink --anthropic --rules examples/rules/atlassian.yaml   # extra allow rules + injected creds
agent-uplink --anthropic --rules my.yaml --no-default-rules      # disable defaults (you must supply auth for bedrock)
agent-uplink --anthropic --runtime runc                          # override gVisor default
agent-uplink --anthropic --debug                                  # mount claude debug logs to host

# Tests (no tests exist yet, but the runner is)
pytest
```

**Runtime requirements** (must be on PATH): `docker`, `socat`. `aws` CLI is needed only when `--aws-profiles` is used or when `--bedrock` mode resolves an `AWS_PROFILE` from `settings.json`.

## Architecture

### Startup sequence

1. Load `~/.claude/settings.json` from the host.
2. Generate mitmproxy TLS certs into `~/.agent_uplink/mitm/` (once, via a throwaway mitmproxy container).
3. Build the Claude image (`agent-uplink-claude` by default) — certs are copied into the image at build time so the container trusts mitmproxy's CA. Rebuilds also fire if the existing image is older than 24 h (`CLAUDE_IMAGE_MAX_AGE_SECONDS`).
4. Create a per-session directory `~/.agent_uplink/<uuid>/`.
5. Resolve auth for the chosen mode:
   - `--anthropic`: read `~/.claude/.credentials.json` (refreshing it on the host via `claude auth status` if the OAuth token is near expiry), then write a *fake* `.credentials.json` to the session dir (real `accessToken`/`refreshToken` replaced with `sk-ant-oat01-agent-uplink-*` / `sk-ant-ort01-agent-uplink-*`, `expiresAt` pinned ~10 years out) for read-only mounting into the container. The real bearer is stashed for mitmproxy injection. No env-var placeholder is set in this mode.
   - `--bedrock`: inject `AWS_BEARER_TOKEN_BEDROCK=placeholder` into the filtered settings.json so the Claude CLI takes the bedrock auth path; mitmproxy substitutes the real bearer.
6. Write a filtered copy of the Claude config (strips `awsAuthRefresh`, `sandbox`; adds `skipDangerousModePermissionPrompt`; merges in the per-mode env placeholders from step 5).
7. For each `--aws-profiles` profile (plus the `env.AWS_PROFILE` from settings.json under `--bedrock`): export the real AWS env vars on the host, write them as a shared-credentials-file INI blob into a per-profile `LockedSecret` (mlock'd `/dev/shm`, mode 0600) for bind-mounting into the sidecar; and write a dummy `~/.aws/credentials` file (mode 0600) with a deterministic dummy AKIA per profile for the Claude container.
8. Resolve rules: merge `default_rules.yaml` with the user's `--rules` file, expand `{{keyring:...}}` placeholders via the host's OS keyring, append the per-mode auth rule (for `--anthropic` this is a literal `Authorization: Bearer <real-oauth-token>` from step 5; for `--bedrock` it's `{{keyring:bedrock:key}}`), embed the `aws_sigv4_routes` map (dummy AKIA → sidecar host/port), and store the resolved JSON in a `LockedSecret` (mlock'd `/dev/shm` file, mode 0600) for read-only mounting into the mitmproxy container.
9. If there are AWS profiles, create a per-session docker network `agent-uplink-net-<id>`.
10. Start mitmproxy container on a random host port (attached to the docker network if present) with the addon (`mitm_addon/filter.py`) and resolved rules mounted read-only; start host-side `socat` forwarding `~/.agent_uplink/<uuid>/sockets/uplink.sock` → `127.0.0.1:<port>`.
11. For each AWS profile, start an `aws-sigv4-proxy` sidecar on the docker network. The per-profile `LockedSecret` is bind-mounted read-only at `/aws/credentials`; `AWS_SHARED_CREDENTIALS_FILE` and `AWS_PROFILE` are set so the sidecar's SDK reads creds from the file. The sidecar runs as the host uid/gid so it can read the host-owned 0600 file under `--cap-drop=ALL`. mitmproxy reaches sidecars by container name via docker's embedded DNS.
12. Start the Claude container (interactive, `--network none`, default `--runtime=runsc`). `entrypoint.sh` starts container-side `socat` bridging TCP 8090 → the Unix socket, then `cd`s to `$WORKDIR` and runs `claude --dangerously-skip-permissions`.
13. On SIGINT/SIGTERM: stop all containers (mitm + sidecars + claude, 3 s timeout), terminate background processes, scrub `LockedSecret`s, remove the docker network, delete the session directory.

### Key constraints

- **Working directory**: `agent-uplink` must be run from within `/home/<USER>/` (validated in both Python and `entrypoint.sh`). Running it from elsewhere (e.g. `/root/` or a path outside the container home) is rejected.
- **Image rebuild triggers**: the Claude image is (re)built whenever mitmproxy certs are newly generated, `--force-rebuild` is passed, the image doesn't exist, or it's older than `CLAUDE_IMAGE_MAX_AGE_SECONDS` (24 h). Certs are baked into the image, so if certs change the image must be rebuilt.
- **File mounts**: `~/.claude/CLAUDE.md`, `commands/`, and `skills/` are mounted read-only if they exist. `history.jsonl` is mounted read-write if it exists. The filtered `settings.json` is mounted read-only from the session dir. Under `--anthropic`, the *fake* session-dir `credentials.json` is mounted read-only at `~/.claude/.credentials.json` inside the container — the host's real OAuth file is never bind-mounted. The host project directory (`~/.claude/projects/<path-derived-id>/`) is mounted read-write so Claude state persists across sessions. `~/.claude.json` is mounted read-write.
- **Security posture**: `--cap-drop=ALL`, `--read-only` root FS, `--pids-limit 300`, `--security-opt no-new-privileges`. Memory is 1 GiB for the Claude container, 0.5 GiB for mitmproxy, 128 MiB for each sigv4-proxy sidecar; `--cpus 1` on all of them.

### Module layout

| File | Responsibility |
|---|---|
| `agent_uplink/__main__.py` | Entry point shim — re-exports `cli.main` so `python -m agent_uplink` works |
| `agent_uplink/cli.py` | Arg parsing, signal handler wiring, top-level orchestration; resolves anthropic OAuth vs bedrock env-var auth |
| `agent_uplink/config.py` | Load/filter Claude settings; `AUTH_MODES` + per-mode env placeholders; refresh + read host `.credentials.json` and produce a fake one for the container; generate dummy AKIA per AWS profile and write a dummy `~/.aws/credentials`; export real AWS env vars and format them as a shared-credentials-file INI blob for sidecars |
| `agent_uplink/docker_ops.py` | All `docker` invocations + `DOCKER_RUN_FLAGS` shared by all containers; per-session network + sigv4-proxy sidecar launch; mount layout (incl. the fake `.credentials.json` for anthropic mode) |
| `agent_uplink/process.py` | `run_command`, `run_command_background`, `get_free_port` |
| `agent_uplink/session.py` | `Session` dataclass: tracks containers/processes/secrets; idempotent `cleanup()` |
| `agent_uplink/secret.py` | `LockedSecret`: mlock'd `/dev/shm` file (mode 0600) used to ferry rules JSON and AWS creds into containers without env vars or on-disk persistence |
| `agent_uplink/rules.py` | Load YAML rules, merge defaults, append per-mode auth rule (anthropic: literal OAuth bearer from the host file; bedrock: `{{keyring:bedrock:key}}`), resolve any remaining keyring placeholders, store the resolved JSON in a `LockedSecret` |
| `agent_uplink/default_rules.yaml` | Bundled defaults: allow `GET` / `OPTIONS` / `HEAD` to any host plus a few specific POST/GET allow-rules for Claude telemetry/changelog/downloads |
| `agent_uplink/mitm_addon/filter.py` | mitmproxy addon — enforces allow-list, injects pre-resolved headers, and reroutes AWS SigV4 requests to sidecars by dummy AKIA (stdlib only; runs inside the mitmproxy container) |
| `agent_uplink/claude_container/Dockerfile` | Claude container image (Ubuntu 24.04, Claude CLI, AWS CLI v2, dev tools) |
| `agent_uplink/claude_container/entrypoint.sh` | Container init: validates `$WORKDIR`, starts socat proxy bridge, execs Claude |
| `agent_uplink/claude_container/certs/` | Runtime-generated mitmproxy certs (gitignored, copied in at image build) |

## Rules and credential injection

`agent-uplink` enforces an allow-list policy on every request leaving the Claude container. Credentials it injects come from one of two places: the host's OS keyring (for user-supplied rules and the `--bedrock` auth rule) or the host's `~/.claude/.credentials.json` (for the `--anthropic` auth rule). Either way, the real secret stays on the host and is only added to requests inside the mitmproxy container.

### Default behaviour

With no `--rules` flag, the bundled `default_rules.yaml` is loaded: `GET` / `OPTIONS` / `HEAD` to any host are allowed, plus narrow POST/GET rules for Datadog logs (`/api/v2/logs`), the Claude Code `CHANGELOG.md`, and `downloads.claude.ai`. Everything else returns `403`. The auth rule for the chosen `--anthropic` / `--bedrock` mode is appended on top.

When `--rules <file>` is supplied, the user's rules are **appended** to the defaults. Pass `--no-default-rules`, or set `replace_defaults: true` at the top of the YAML, to use only the user's rules. Under `--no-default-rules`, the per-mode auth rule is *also* skipped — for `--bedrock` you must then inject `Authorization` yourself; for `--anthropic` requests to `api.anthropic.com` will be denied.

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

The resolved JSON is stored in a `LockedSecret` (mlock'd `/dev/shm` file, mode `0o600`) and bind-mounted read-only into the mitmproxy container; the Claude container never sees it.

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

## Auth modes

`--anthropic` and `--bedrock` are mutually exclusive and one is required.

- **`--anthropic`**: requires `~/.claude/.credentials.json` on the host (populated by `claude login`). The real OAuth `accessToken` is embedded directly into the mitmproxy rules; the container gets a *fake* `.credentials.json` (`sk-ant-oat01-agent-uplink-*` tokens, `expiresAt` pinned ~10 years out) so the Claude CLI takes the OAuth code path and shows the welcome banner. There are no fallback auth paths in this mode — if the credentials file is missing or unparseable, startup fails.
- **`--bedrock`**: injects `AWS_BEARER_TOKEN_BEDROCK=placeholder` into the container's settings.json. mitmproxy swaps it for the real bearer (from `keyring get bedrock key`) on `bedrock-runtime.<region>.amazonaws.com`. If `settings.json` sets `env.AWS_PROFILE`, that profile is added to the sigv4-proxy sidecar list automatically (in addition to anything from `--aws-profiles`).

## AWS SigV4 routing

When one or more `--aws-profiles` are supplied, the container's `~/.aws/credentials` is populated with **dummy** values: a deterministic dummy AKIA per profile (`AKIA` + first 16 hex chars of `sha256(profile)`) plus a fixed dummy secret. The container's AWS SDK signs requests with these fake creds; the resulting signature is bogus and never goes to AWS.

The mitm addon detects requests whose host ends in `.amazonaws.com` and whose `Authorization` header is `AWS4-HMAC-SHA256`. It extracts the AKIA from the `Credential=` field, looks it up in the `aws_sigv4_routes` map, strips the `Authorization` / `X-Amz-Date` / `X-Amz-Security-Token` / `X-Amz-Content-Sha256` headers, and reroutes the request to the matching `aws-sigv4-proxy` sidecar over plain HTTP on a per-session docker network. The original `Host` header is preserved so the sidecar can determine the target service/region and re-sign with the real credentials before forwarding to AWS.

Requests to `*.amazonaws.com` with no matching SigV4 route return `403`. Requests with no `Authorization: AWS4-HMAC-SHA256` header fall through to the normal allow-list (e.g. anonymous `GET` to a public S3 bucket).

Real AWS credentials are obtained on the host via `aws configure export-credentials` (with an `aws sso login` fallback), formatted as a single-profile shared-credentials-file INI blob, and stored in a per-profile `LockedSecret` (mlock'd `/dev/shm` file, mode 0600). The sidecar bind-mounts that file read-only at `/aws/credentials` and reads it via `AWS_SHARED_CREDENTIALS_FILE`; `AWS_PROFILE` is the only AWS-related env var on the container. This avoids `docker run -e AWS_SECRET_ACCESS_KEY=...`, which would expose creds to any host user with docker access (`docker inspect`) and to the sidecar's `/proc/<pid>/environ`. Creds never enter the Claude container, never hit disk, and the sidecar is on a docker network unreachable from the Claude container (`--network none`).
