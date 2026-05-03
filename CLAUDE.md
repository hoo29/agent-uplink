# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**agent-uplink** runs Claude in a hardened Docker container with all outbound traffic intercepted by mitmproxy. The Claude container has `--network none`; instead, `socat` inside the container bridges a Unix socket to a local TCP port (8090), which in turn is forwarded by `socat` on the host to the mitmproxy container. This gives full TLS inspection of Claude's traffic without direct network access.

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
6. Export AWS credentials to `~/.agent_uplink/<uuid>/aws_credentials` (temporary; cleaned up on exit).
7. Resolve rules: merge `default_rules.yaml` with the user's `--rules` file, expand `{{keyring:...}}` placeholders via the host's OS keyring, write `~/.agent_uplink/<uuid>/rules.json` with mode 0600.
8. Start mitmproxy container on a random host port with the addon (`mitm_addon/filter.py`) and resolved rules mounted read-only; start host-side `socat` forwarding `~/.agent_uplink/<uuid>/sockets/uplink.sock` → `127.0.0.1:<port>`.
9. Start the Claude container (interactive, `--network none`). `entrypoint.sh` starts container-side `socat` bridging TCP 8090 → the Unix socket, then `cd`s to `$WORKDIR` and runs `claude --dangerously-skip-permissions`.
10. On SIGINT/SIGTERM: stop both containers (3 s timeout), terminate background processes, delete the session directory.

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
| `agent_uplink/config.py` | Load/filter Claude settings; export AWS credentials with `0o600` |
| `agent_uplink/docker_ops.py` | All `docker` invocations + `HARDENED_RUN_FLAGS` shared by both containers |
| `agent_uplink/process.py` | `run_command`, `run_command_background`, `get_free_port` |
| `agent_uplink/session.py` | `Session` dataclass: tracks containers/processes; idempotent `cleanup()` |
| `agent_uplink/rules.py` | Load YAML rules, merge defaults, resolve keyring placeholders, write 0600 JSON |
| `agent_uplink/default_rules.yaml` | Bundled defaults: allow `GET` / `OPTIONS` everywhere |
| `agent_uplink/mitm_addon/filter.py` | mitmproxy addon — enforces allow-list + injects pre-resolved headers (stdlib only; runs inside the mitmproxy container) |
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
