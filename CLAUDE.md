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

# Run
agent-uplink
agent-uplink --aws-profiles profile1 profile2   # pass AWS credentials
agent-uplink --force-rebuild                     # rebuild Claude image
agent-uplink --claude-image my-image            # custom image name
agent-uplink --mitmproxy-image mitmproxy/mitmproxy:latest
agent-uplink --rules examples/rules/atlassian.yaml      # extra allow rules + injected creds
agent-uplink --rules my.yaml --no-default-rules         # disable default GET/OPTIONS allow

# Tests (no tests exist yet, but the runner is)
pytest
```

**Runtime requirements** (must be on PATH): `docker`, `socat`. `aws` CLI is needed only when `--aws-profiles` is used.

## Architecture

### Startup sequence

1. Load `~/.claude/settings.json` from the host.
2. Generate mitmproxy TLS certs into `~/.agent_uplink/mitm/` (once, via a throwaway mitmproxy container).
3. Build the Claude image (`agent-uplink-claude` by default) — certs are copied into the image at build time so the container trusts mitmproxy's CA.
4. Create a per-session directory `~/.agent_uplink/<uuid>/`.
5. Write a filtered copy of the Claude config (strips `awsAuthRefresh`, `sandbox`, `permissions`; adds `skipDangerousModePermissionPrompt`).
6. For each `--aws-profiles` profile: export the real AWS env vars (kept in host memory, passed only to the sidecar `docker run -e ...`), and write a dummy `~/.aws/credentials` file (mode 0600) with a deterministic dummy AKIA per profile.
7. Resolve rules: merge `default_rules.yaml` with the user's `--rules` file, expand `{{keyring:...}}` placeholders via the host's OS keyring, embed the `aws_sigv4_routes` map (dummy AKIA → sidecar host/port), and store the resolved JSON in a `LockedSecret` (mlock'd `/dev/shm` file, mode 0600) for read-only mounting into the mitmproxy container.
8. If there are AWS profiles, create a per-session docker network `agent-uplink-net-<id>`.
9. Start mitmproxy container on a random host port (attached to the docker network if present) with the addon (`mitm_addon/filter.py`) and resolved rules mounted read-only; start host-side `socat` forwarding `~/.agent_uplink/<uuid>/sockets/uplink.sock` → `127.0.0.1:<port>`.
10. For each AWS profile, start an `aws-sigv4-proxy` sidecar on the docker network, with the real AWS env vars passed via `-e`. mitmproxy reaches sidecars by container name via docker's embedded DNS.
11. Start the Claude container (interactive, `--network none`). `entrypoint.sh` starts container-side `socat` bridging TCP 8090 → the Unix socket, then `cd`s to `$WORKDIR` and runs `claude --dangerously-skip-permissions`.
12. On SIGINT/SIGTERM: stop all containers (mitm + sidecars + claude, 3 s timeout), terminate background processes, scrub `LockedSecret`s, remove the docker network, delete the session directory.

### Key constraints

- **Working directory**: `agent-uplink` must be run from within `/home/<USER>/` (validated in both Python and `entrypoint.sh`). Running it from elsewhere (e.g. `/root/` or a path outside the container home) is rejected.
- **Image rebuild triggers**: the Claude image is (re)built whenever mitmproxy certs are newly generated, `--force-rebuild` is passed, or the image doesn't exist. Certs are baked into the image, so if certs change the image must be rebuilt.
- **File mounts**: `~/.claude/CLAUDE.md`, `commands/`, and `skills/` are mounted read-only if they exist. `.credentials.json` and `history.jsonl` are mounted read-write if they exist. The filtered `settings.json` is mounted read-only from the session dir. The host project directory (`~/.claude/projects/<path-derived-id>/`) is mounted read-write so Claude state persists across sessions.
- **Security posture**: `--cap-drop=ALL`, `--read-only` root FS, `--pids-limit 100`, `--memory=0.5g`, `--cpus 1`, `--security-opt no-new-privileges`.

### Module layout

| File | Responsibility |
|---|---|
| `agent_uplink/__main__.py` | Entry point shim — re-exports `cli.main` so `python -m agent_uplink` works |
| `agent_uplink/cli.py` | Arg parsing, signal handler wiring, top-level orchestration |
| `agent_uplink/config.py` | Load/filter Claude settings; generate dummy AKIA per AWS profile and write a dummy `~/.aws/credentials` for the container; export real AWS env vars for sidecars |
| `agent_uplink/docker_ops.py` | All `docker` invocations + `DOCKER_RUN_FLAGS` shared by all containers; per-session network + sigv4-proxy sidecar launch |
| `agent_uplink/process.py` | `run_command`, `run_command_background`, `get_free_port` |
| `agent_uplink/session.py` | `Session` dataclass: tracks containers/processes; idempotent `cleanup()` |
| `agent_uplink/rules.py` | Load YAML rules, merge defaults, resolve keyring placeholders, write 0600 JSON |
| `agent_uplink/default_rules.yaml` | Bundled defaults: allow `GET` / `OPTIONS` everywhere |
| `agent_uplink/mitm_addon/filter.py` | mitmproxy addon — enforces allow-list, injects pre-resolved headers, and reroutes AWS SigV4 requests to sidecars by dummy AKIA (stdlib only; runs inside the mitmproxy container) |
| `agent_uplink/claude_container/Dockerfile` | Claude container image (Ubuntu 24.04, Claude CLI, AWS CLI v2, dev tools) |
| `agent_uplink/claude_container/entrypoint.sh` | Container init: validates `$WORKDIR`, starts socat proxy bridge, execs Claude |
| `agent_uplink/claude_container/certs/` | Runtime-generated mitmproxy certs (gitignored, copied in at image build) |

## Rules and credential injection

`agent-uplink` enforces an allow-list policy on every request leaving the Claude container, and can inject credentials from the host's OS keyring so the secret values never enter the container.

### Default behaviour

With no `--rules` flag, the bundled `default_rules.yaml` is loaded: `GET` and `OPTIONS` to any host are allowed, everything else returns `403`.

When `--rules <file>` is supplied, the user's rules are **appended** to the defaults (so `GET`/`OPTIONS` stay allowed). Pass `--no-default-rules`, or set `replace_defaults: true` at the top of the YAML, to use only the user's rules.

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

Rules iterate in order; first match wins. Header values may contain any number of `{{keyring:SERVICE:USERNAME}}` placeholders, which are resolved on the host via `keyring.get_password()` before the mitmproxy container starts. A failed lookup (or any validation error) aborts startup with no containers launched.

The resolved JSON is written to the per-session dir with mode `0o600` and mounted read-only into the mitmproxy container; the Claude container never sees it.

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

## AWS SigV4 routing

When one or more `--aws-profiles` are supplied, the container's `~/.aws/credentials` is populated with **dummy** values: a deterministic dummy AKIA per profile (`AKIA` + first 16 hex chars of `sha256(profile)`) plus a fixed dummy secret. The container's AWS SDK signs requests with these fake creds; the resulting signature is bogus and never goes to AWS.

The mitm addon detects requests whose host ends in `.amazonaws.com` and whose `Authorization` header is `AWS4-HMAC-SHA256`. It extracts the AKIA from the `Credential=` field, looks it up in the `aws_sigv4_routes` map, strips the `Authorization` / `X-Amz-Date` / `X-Amz-Security-Token` / `X-Amz-Content-Sha256` headers, and reroutes the request to the matching `aws-sigv4-proxy` sidecar over plain HTTP on a per-session docker network. The original `Host` header is preserved so the sidecar can determine the target service/region and re-sign with the real credentials before forwarding to AWS.

Requests to `*.amazonaws.com` with no matching SigV4 route return `403`. Requests with no `Authorization: AWS4-HMAC-SHA256` header fall through to the normal allow-list (e.g. anonymous `GET` to a public S3 bucket).

Real AWS credentials are obtained on the host via `aws configure export-credentials` (with an `aws sso login` fallback) and passed directly to the sidecar container via `docker run -e ...`. They never enter the Claude container, are never written to disk in the session dir, and the sidecar is on a docker network unreachable from the Claude container (`--network none`).
