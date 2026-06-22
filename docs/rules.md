# Rules and credential injection

`agent-uplink` enforces an allow-list policy on every request leaving the agent pod. Credentials it injects come from one of two places: the host's OS keyring (for user-supplied rules and any agent auth rule referencing `{{keyring:...}}`) or files the agent reads directly on the host (e.g. Claude's `~/.claude/.credentials.json`). Either way, the real secret stays on the host and is only added to requests inside the mitm pod.

## Default behaviour

With no `--rules` flag, three layers apply: the agent's per-mode auth rule, agent-specific defaults (e.g. Claude's Datadog logs), and the generic catch-all (`GET`/`OPTIONS`/`HEAD` anywhere). Everything else returns `403`.

When `--rules <file>` is supplied, the user's rules are added. `--rules` is repeatable (`--rules a.yaml b.yaml`) and the user layer can also be defined inline in `.agent-uplink.yaml` under the `rules:` key (file paths and inline rule mappings can be mixed). `rules.resolve()` takes a list of sources (each a `Path` to a YAML file or an inline rule `dict`) and concatenates them in order to form the single user layer — an earlier source wins first-match over a later one; a bare `Path`/`None` is still accepted as shorthand. **Match priority is by layer, not regex length** — first match wins in this order: agent auth rule → kube rules → user rules → agent defaults → generic catch-all (evaluated last). Auth and kube rules lead so a broad user allow rule on an overlapping host (e.g. `.*\.amazonaws\.com`) can't win first-match and strip an injected credential — a real failure mode for `--bedrock`, whose auth is a header inject on `bedrock-runtime.<region>.amazonaws.com`. The user's rules still beat the per-agent and generic defaults, and the broad `GET` catch-all is always considered last. Pass `--no-default-rules`, or set `replace_defaults: true` at the top of any rules file, to use only the user's rules; the agent's auth rule is then *also* skipped — the user supplies any auth the chosen mode needs.

## Rule schema

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

## Populating the keyring

```bash
keyring set my-svc my-user           # prompts for the secret
keyring get my-svc my-user           # verify
```

- macOS → Keychain. Works out of the box.
- Windows → Credential Locker. Works out of the box.
- Linux/WSL2 → Secret Service. Requires `gnome-keyring` (or KDE's `kwallet`) running. On WSL2 you may need `sudo apt install gnome-keyring` and to start it (`dbus-launch gnome-keyring-daemon --start`), or fall back to the encrypted file backend in `keyrings.alt`.

## Examples

`examples/rules/atlassian.yaml` and `examples/rules/gitlab.yaml` show worked configurations for Atlassian Cloud (Basic auth) and GitLab (PRIVATE-TOKEN), including the `keyring set ...` command for each. `examples/rules/codeartifact.yaml` shows `{{exec:...}}` generating a CodeArtifact auth token on the host and injecting it as Maven Basic auth.
