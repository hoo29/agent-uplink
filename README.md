# agent-uplink

Run Claude Code in a hardened Docker container with all outbound traffic forced through mitmproxy.

The Claude container has no direct network access (`--network none`). A Unix socket bridges it to a mitmproxy
container on the host, which inspects every request and applies an allow-list. Hosts, methods, and paths not
on the list return `403`.
Credentials can be injected from your OS keyring for secrets apart from AWS so they never enter the Claude container.
For AWS, temporary credentials are generated on start for the profiles specified.

## Requirements

- `docker`, `socat`, and Python 3.10+ on `PATH`
- `aws` CLI only if you use `--aws-profiles`
- Must be run from inside your home directory (`/home/<user>/...`)

## Install

```bash
pip install -e .
```

## Usage

```bash
# Run with defaults (allows GET and OPTIONS to any host; blocks everything else)
agent-uplink

# Use additional rules from a YAML file
agent-uplink --rules examples/rules/atlassian.yaml

# Use only your rules, no defaults
agent-uplink --rules my.yaml --no-default-rules

# Pass AWS credentials from named profiles
agent-uplink --aws-profiles profile1 profile2

# Rebuild the Claude image
agent-uplink --force-rebuild
```

Other flags:

- `--claude-image <name>` - override the Claude image name
- `--mitmproxy-image <name>` - override the mitmproxy image

State is kept under `~/.agent_uplink/`. Each run gets its own session directory, cleaned up on exit.

## Rules

A rule file is YAML:

```yaml
replace_defaults: false   # optional; same as --no-default-rules

rules:
  - name: my-rule
    host: '<regex>'             # required, matched with re.fullmatch
    methods: [GET, POST]        # optional, default = any
    paths: ['<regex>']          # optional, default = any
    inject:                     # optional
      headers:
        Authorization: 'Bearer {{keyring:my-service:my-user}}'
```

Rules are evaluated in order; the first match wins. By default, the rules in your file are appended to the bundled defaults.

`{{keyring:SERVICE:USERNAME}}` placeholders are resolved on the host via the OS keyring before any container starts. A failed lookup aborts startup.

See `examples/rules/atlassian.yaml` and `examples/rules/gitlab.yaml` for full examples.

### Storing credentials

```bash
keyring set my-service my-user   # prompts for the secret
keyring get my-service my-user   # verify
```

- macOS uses Keychain; Windows uses Credential Locker. Both work out of the box.
- Linux/WSL2 needs Secret Service (e.g. `gnome-keyring`) running, or the encrypted file backend from `keyrings.alt`.

## Container security posture

Designed to contain rogue AI commands such as unintended shell calls, API requests, or secrets leaked via prompt injection. It is not a malware sandbox;
containers are not a security boundary and it won't stop code that's actively trying to escape.

- `--network none`, `--cap-drop=ALL`, `--read-only`, `--security-opt no-new-privileges`
- `--pids-limit 100`, `--memory 0.5g`, `--cpus 1`
- mitmproxy CA is baked into the image at build time so TLS interception is transparent

The root filesystem is read-only. Only the following paths are writable, and only those needed for Claude state to persist across sessions are bind-mounted from the host:

| Path in container | Backing | Purpose |
| --- | --- | --- |
| `<cwd>` | host bind | your project working directory |
| `~/.claude.json` | host bind | Claude global config |
| `~/.claude/projects/<project-id>/` | host bind | per-project history and state |
| `~/.claude/.credentials.json` | host bind (if present) | Claude credentials |
| `~/.claude/history.jsonl` | host bind (if present) | shell history |

Everything else under `~/.claude/` (`settings.json`, `CLAUDE.md`, `commands/`, `skills/`) and the mitmproxy CA are mounted read-only.

## TODO

- don't write raw creds to disk for mitmproxy rules
