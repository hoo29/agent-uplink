# Claude agent

## Auth modes

`--anthropic` and `--bedrock` are mutually exclusive and one is required for `agent-uplink claude`.

- **`--anthropic`**: requires `~/.claude/.credentials.json` on the host (populated by `claude login`). The real OAuth `accessToken` is embedded directly into the mitm rules; the pod gets a *fake* `.credentials.json` (`sk-ant-oat01-agent-uplink-*` tokens, `expiresAt` pinned ~10 years out) so the Claude CLI takes the OAuth code path and shows the welcome banner. There are no fallback auth paths in this mode — if the credentials file is missing or unparseable, startup fails.
- **`--bedrock`**: injects `AWS_BEARER_TOKEN_BEDROCK=placeholder` into the pod's settings.json. mitm swaps it for the real bearer (from `keyring get bedrock key`) on `bedrock-runtime.<region>.amazonaws.com`. If `settings.json` sets `env.AWS_PROFILE`, that profile is added to the SigV4 re-signing credential map automatically (in addition to anything from `--aws-profiles`) — note that wires the agent to that profile's full IAM scope via the re-signing hop (above), gated on your rules.

**Known limitation — host settings.json is copied wholesale.** `claude_settings_bytes` currently copies the host `settings.json` into the pod *as-is*: it drops only the top-level `sandbox` key, replaces `permissions`, and merges the mode's injected placeholder into `env`. It does **not** implement an allow-list, so secret-bearing keys — `apiKeyHelper` and any secret `env` entries (e.g. API tokens) — in your host `settings.json` **do** reach the agent container's `~/.claude/settings.json`. Keep secrets out of your host `settings.json` for now. The same applies to the managed settings below.

## /etc/claude-code/managed-settings.json (enterprise policy)

If the host has `/etc/claude-code/managed-settings.json`, it is shipped into the pod as a Secret and mounted read-only at the
same path, so Claude's own precedence rules apply unchanged — managed settings still outrank the pod's `~/.claude/settings.json`.
A host without the file is the common case and mounts nothing. `managed_settings_bytes` sanitizes the copy; the host file is left
untouched:

- the top-level `sandbox` key is dropped (the pod *is* the sandbox), as for the user settings;
- `permissions` is replaced with `defaultMode: auto` (plus `skipDangerousModePermissionPrompt`), exactly as for the user settings.
  Managed settings outrank user settings in Claude's merge, so a host policy's `permissions` left intact would override the `auto`
  mode set on `~/.claude/settings.json` and the agent would prompt inside the sandbox;
- each MCP server's `Authorization` header is redacted, exactly as in `~/.claude.json`;
- the auth mode's placeholder `env` (e.g. `AWS_BEARER_TOKEN_BEDROCK=placeholder`) is merged in and **wins** over the host's value.
  Managed settings outrank user settings, so a real credential in the host policy's `env` would otherwise reach the agent
  container and defeat the placeholder shipped in `settings.json`.

## ~/.claude.json (MCP Authorization header)

The host `~/.claude.json` is **not** mounted into the pod directly. `sanitized_claude_json_bytes`
copies it into the session scratch dir with each MCP server's `Authorization` header redacted, and
that copy is mounted read-write at `~/.claude.json`. In both the top-level `mcpServers` map and each
`projects.<path>.mcpServers` map, an `Authorization` header value (match is case-insensitive) is
replaced with the literal `PLACEHOLDER`. The header key is kept, so Claude still treats the server
as configured.

Consequences:

- The agent's runtime writes go to the session copy — the real host `~/.claude.json` is never
  read-write mounted or mutated.
- Only the `Authorization` header is redacted. An http/sse MCP server that uses it works once you
  add a mitm rule injecting the real bearer (same model as `--anthropic`/`--bedrock`).
- Everything else is left intact and **does enter the pod**: all other headers, every `env` value
  (so a stdio server's `env`-based token works as-is but is exposed to the agent), command-line
  `args`, and any credential embedded in a server `url`. Keep those in mind when deciding what MCP
  servers to configure on the host.

## Java / Maven

The image bundles OpenJDK 21 + Maven. Maven support is **opt-in via `--maven`** (a claude-agent flag, since the JDK and
truststore bits are baked into the claude image). With `--maven` the agent pod gets:

- `~/.m2/settings.xml` mounted **read-only**, `~/.m2/repository` mounted **read-write** (the agent writes downloaded artifacts straight into the host's real local repo).
- `MAVEN_OPTS` set to point the Maven JVM at `mitm:8080` — the JVM does **not** read `HTTPS_PROXY` (dockerd does), and the pod can egress only to mitm.
- `CODEARTIFACT_AUTH_TOKEN=placeholder` so `${env.CODEARTIFACT_AUTH_TOKEN}` in `settings.xml` expands; the real CodeArtifact auth is injected by mitm (see `examples/rules/codeartifact.yaml`), never entering the pod.

`--maven` is a shortcut for `--mount-ro ~/.m2/settings.xml --mount-rw ~/.m2/repository` plus the Maven proxy env above;
the mount half can be reproduced with the generic flags, but the env half only comes with `--maven`.

The mitm CA is added to the JVM truststore at image build (the JDK pulls in `ca-certificates-java`, which `update-ca-certificates` feeds from the system store), so Maven trusts mitm's TLS interception of HTTPS dependency downloads.

## Ansible

The image bundles `ansible` (in a venv). It is **not** auto-configured. To share the host's defaults, mount the config
read-only with the generic flag: `--mount-ro ~/.ansible.cfg`. Unlike credentials, the file's contents enter the pod
verbatim — it bypasses mitm — so keep inline secrets (or `vault_password_file` references) out of it.

## Private docker registry auth

`~/.docker/config.json` is **not** mounted into the pod. Private registry pulls (ECR, etc.) are handled purely by mitm rules, the same mechanism as every other credential — there is no docker-specific code path. The in-pod `dockerd` makes anonymous registry requests; a rule matching the registry host injects the `Authorization` header (header injection adds it even when the request had none), so the registry accepts the pull. The credential is resolved on the host and never enters the pod.

ECR uses HTTP **Basic** auth (`AWS:<token>`, token from `aws ecr get-login-password`), so a single `{{exec:...}}` rule on the registry host suffices — see `examples/rules/ecr.yaml`. Blob downloads redirect to presigned S3 URLs on a different host (no `Authorization` header) and fall through to the default `GET` allow rule. (This is unrelated to the SigV4 re-signing in `docs/aws-resigning.md`: ECR's Basic-auth `Authorization` header is not `AWS4-HMAC-SHA256`, so it is never picked up by the re-signer.)
