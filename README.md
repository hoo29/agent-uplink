# agent-uplink

Run Claude Code in a hardened container with no direct network access. All outbound traffic is routed through a mitmproxy sidecar that enforces an allow-list and can inject credentials from your OS keyring, so secrets never enter the Claude container.

AWS requests get the same treatment via SigV4 re-signing: the container holds only dummy AWS credentials, and mitmproxy reroutes signed AWS requests to an `aws-sigv4-proxy` sidecar (one per profile) that re-signs with the real keys kept on the host. See [AWS profiles](#aws-profiles).

**Linux only.** The design depends on gVisor (`runsc`), Linux paths (`/home/<user>/...`), and Unix-socket bind-mount semantics that Docker Desktop on macOS/Windows does not provide. WSL2 works.

## Install

```bash
pip install -e .
```

Requires `docker`, `socat`, and Python 3.10+ on `PATH`. `aws` CLI is needed only for `--aws-profiles`. Run from inside your home directory.

## Usage

One of `--anthropic` or `--bedrock` is required — it picks the provider env var injected into the container and the auth rule injected on top of the defaults.

```bash
agent-uplink --anthropic                                       # Anthropic API
agent-uplink --bedrock                                         # AWS Bedrock (bearer token)
agent-uplink --anthropic --rules examples/rules/atlassian.yaml # add rules on top of defaults
agent-uplink --anthropic --rules my.yaml --no-default-rules    # use only your rules (you must supply auth)
agent-uplink --bedrock --aws-profiles profile1 profile2        # also inject AWS credentials
agent-uplink --anthropic --force-rebuild                       # rebuild the Claude image
```

Other flags: `--claude-image`, `--mitmproxy-image`, `--sigv4-proxy-image`, `--runtime` (see [Runtime](#runtime)).

State lives under `~/.agent_uplink/`; each run gets a session directory that is cleaned up on exit.

### Required keyring secrets per mode

The mode's auth rule injects a bearer token from the host keyring. Populate before first run:

| Mode | Keyring entry | Populate with |
| --- | --- | --- |
| `--anthropic` | service `anthropic`, user `key` | `jq -r '.claudeAiOauth.accessToken // .apiKey' ~/.claude/.credentials.json \| keyring set anthropic key` |
| `--bedrock` | service `bedrock`, user `key` | `keyring set bedrock key` (paste the value of `AWS_BEARER_TOKEN_BEDROCK`) |

Anthropic OAuth access tokens from `claude login` expire (hours) and the container has no way to refresh them; re-run the extract command when they expire, or use a long-lived API key.

`--no-default-rules` skips the mode's auth rule too — you must supply your own in `--rules`.

## Runtime

The Claude container defaults to `--runtime=runsc` ([gVisor](https://gvisor.dev/)) for a stronger isolation boundary than `runc`. Override with `--runtime runc` if gVisor isn't installed.

gVisor must be registered in `/etc/docker/daemon.json` with `--host-uds=all` so the container can reach the host-side Unix socket that bridges to mitmproxy:

```json
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--network=host",
                "--host-uds=all"
            ]
        }
    }
}
```

Restart Docker after editing (`sudo systemctl restart docker`).

## Rules

Rules are YAML, evaluated in order; first match wins. Your rules are appended to the bundled defaults unless `--no-default-rules` is passed.

```yaml
rules:
  - name: my-rule
    host: '<regex>'             # required, matched with re.fullmatch
    methods: [GET, POST]        # optional, default = any
    paths: ['<regex>']          # optional, default = any
    inject:                     # optional
      headers:
        Authorization: 'Bearer {{keyring:my-service:my-user}}'
```

`{{keyring:SERVICE:USERNAME}}` placeholders are resolved on the host before any container starts; a failed lookup aborts startup. Store secrets with:

```bash
keyring set my-service my-user
```

On Linux/WSL2 this needs Secret Service (e.g. `gnome-keyring`) running, or the encrypted file backend from `keyrings.alt`.

See `examples/rules/atlassian.yaml` and `examples/rules/gitlab.yaml` for worked configurations.

## AWS profiles

`--aws-profiles foo bar` reads the named profiles from your host AWS config (`aws configure export-credentials`, with an `aws sso login` fallback). For each profile:

- The container's `~/.aws/credentials` is populated with **dummy** values: a deterministic dummy access key per profile (`AKIA` + first 16 hex chars of `sha256(profile)`) and a fixed dummy secret. Real keys never enter the Claude container.
- A small `aws-sigv4-proxy` sidecar is started on a per-session docker network with the real AWS env vars passed via `docker run -e ...`.
- The mitmproxy addon detects `*.amazonaws.com` requests signed with `AWS4-HMAC-SHA256`, extracts the dummy AKIA from the `Credential=` field, strips the signature headers, and reroutes the request over plain HTTP to the matching sidecar — preserving the original `Host` so the sidecar signs for the right service/region before forwarding to AWS.

The Claude container stays on `--network none`; sidecars live on a docker network it can't reach. STS credentials are exported once at startup, so long sessions may need a restart when they expire.

Requests to `*.amazonaws.com` with no matching SigV4 route return `403`. Unsigned requests (e.g. anonymous `GET` to a public S3 bucket) fall through to the normal allow-list.

`--bedrock` mode is a separate path: it injects a bearer token at the mitm layer (no AWS signing needed), so `--bedrock` doesn't require `--aws-profiles` unless you also want non-Bedrock AWS access.

## Security posture

Designed to contain rogue AI behaviour but is not a malware sandbox even with gvisor.

The root filesystem is read-only. A handful of paths are writable as ephemeral `tmpfs` (wiped on container exit, `noexec`, `nosuid`):

| Path in container | Size |
| --- | --- |
| `/tmp` | 200m |
| `~/.claude/` | 200m |
| `~/.local/share/applications/` | 200m |

These host paths are bind-mounted writable, because Claude state needs to persist across sessions:

| Path in container | Purpose |
| --- | --- |
| `<cwd>` | your project working directory |
| `~/.claude.json` | Claude global config |
| `~/.claude/projects/<project-id>/` | per-project history and state |
| `~/.claude/.credentials.json` | Claude credentials (if present) |
| `~/.claude/history.jsonl` | shell history (if present) |

Everything else under `~/.claude/` (`settings.json`, `CLAUDE.md`, `commands/`, `skills/`) and the mitmproxy CA are mounted read-only.
