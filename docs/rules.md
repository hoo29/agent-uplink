# Rules and credential injection

`agent-uplink` enforces an allow-list policy on every request leaving the agent pod. Credentials it injects come from one of two
places: the host's OS keyring (for user-supplied rules and any agent auth rule referencing `{{keyring:...}}`) or files the agent
reads directly on the host (e.g. Claude's `~/.claude/.credentials.json`). Either way, the real secret stays on the host and is
only added to requests inside the mitm pod.

## Default behaviour

With no `--rules` flag, three layers apply: the agent's per-mode auth rule, agent-specific defaults (e.g. Claude's Datadog logs),
and the generic catch-all (`GET`/`OPTIONS`/`HEAD` anywhere). Everything else returns `403`.

When `--rules <file>` is supplied, the user's rules are added. `--rules` is repeatable (`--rules a.yaml b.yaml`) and the user
layer can also be defined inline in `.agent-uplink.yaml` under the `rules:` key (file paths and inline rule mappings can be
mixed). `rules.resolve()` takes a list of sources (each a `Path` to a YAML file or an inline rule `dict`) and concatenates them
in order into the single user layer (a bare `Path`/`None` is accepted as shorthand); an earlier source wins first-match over a
later one.

Match priority is by layer, not regex length — first match wins in this order: agent auth rule → kube rules → user rules →
agent defaults → generic catch-all. Auth and kube rules lead so a broad user allow rule on an overlapping host (e.g.
`.*\.amazonaws\.com`) can't win first-match and strip an injected credential — a failure mode for `--bedrock`, whose auth is a
header inject on `bedrock-runtime.<region>.amazonaws.com`.

Pass `--no-default-rules`, or set `replace_defaults: true` at the top of any rules file, to use only the user's rules; the
agent's auth rule is then also skipped, so the user supplies any auth the chosen mode needs.

## Rule schema

```yaml
replace_defaults: false   # optional; CLI --no-default-rules takes precedence

rules:
  - name: my-rule         # human-readable label, shown in mitm logs
    hosts: ['<regex>']    # required; list of regexes, each re.fullmatch'ed against
                          #   the request host; the rule matches if ANY entry matches
    methods: [GET, POST]  # optional; default = allow any method
    paths: ['<regex>']    # optional; default = allow any path (any matches)
    inject:               # optional
      headers:
        Authorization: 'Bearer {{keyring:my-svc:my-user}}'
```

Rules are evaluated in layer order (agent auth → kube → user → agent defaults → generic catch-all; see Default behaviour above),
first match wins. An empty `paths: []` is rejected (omit `paths` to allow any path). Header values may contain any number of
placeholders, resolved on the host before the mitm pod starts:

- `{{keyring:SERVICE:USERNAME}}` — static secret from the OS keyring (`keyring.get_password()`).
- `{{exec:COMMAND}}` — stdout (trailing newline stripped) of a host shell command, run at startup. For short-lived dynamic
  credentials keyring can't hold (e.g. an AWS CodeArtifact auth token). Requires `--allow-exec`; without it, a rules file
  containing an `{{exec:...}}` placeholder aborts startup (so a rules file alone can't run host commands).

Resolution is single-pass, so a resolved secret value is never re-scanned for placeholders. A failed lookup/command (or any
validation error) aborts startup with no pods launched. Header injection overwrites any same-named header already on the
request.

The resolved JSON is stored as a K8s `Secret` (`rules-json`) and mounted read-only into the mitm pod; the agent pod never sees it.

## L4 (raw TCP) passthrough — `l4_forward`

By default mitm terminates TLS: it decrypts each connection, applies the allow-list, optionally injects headers, then re-encrypts
to the upstream. That makes mutual TLS impossible — the agent's client certificate is consumed by mitm during the agent→mitm
handshake and never reaches the server, and mitm has no private key to present one upstream itself (it only ever saw the public
cert). This is inherent to any terminating proxy.

An `l4_forward` rule switches a matched connection to a raw TCP tunnel: mitm relays encrypted bytes without decrypting, so the
agent's TLS — including any `curl --cert/--key` client certificate — runs end-to-end to the upstream.

```yaml
rules:
  - name: corp-mtls
    l4_forward: true
    hosts: ['secure\.corp\.example\.com']   # regexes; matched only when the CONNECT target is a hostname
    cidrs:                               # matched only when the target is a literal IP in the request
      - '192.168.149.0/24'
      - '10.1.2.3/32'
```

Matching is on the CONNECT target — the host or IP the client asked for, before any DNS resolution — decided in mitmproxy's
`next_layer` hook before TLS is touched:

- `hosts` — list of regexes, each `re.fullmatch`ed only when the target is a hostname; the rule matches if any entry matches.
- `cidrs` — list of CIDRs (host bits are normalised), matched only when the target is a literal IP in the request. A hostname
  that would resolve to an IP in the range is not matched — only an IP the client put in the request directly.

Set `hosts`, `cidrs`, or both; at least one is required. An `l4_forward` rule must not set `methods`, `paths`, or `inject` —
mitm never sees the plaintext, so those have no meaning (supplying any is a startup error).

Security: an `l4_forward` connection bypasses the allow-list, header injection, and AWS re-signing entirely — mitm cannot see
inside the tunnel. The egress perimeter still holds (traffic flows through the mitm pod under the unchanged NetworkPolicy), but
the request content is not inspected. Match as narrowly as possible. See `examples/rules/l4-passthrough.yaml`.

Tunnelled connections are relayed without being recorded (`TCPLayer(ignore=True)`). mitm logs one `L4-FORWARD` line per
connection with the matching rule and target, but the relayed bytes are never buffered or dumped — not even under
`--mitm-debug` — so a tunnelled transfer stays flat in memory regardless of size. The bytes are ciphertext, so nothing is lost.

## Populating the keyring

```bash
keyring set my-svc my-user           # prompts for the secret
keyring get my-svc my-user           # verify
```

- macOS → Keychain. Works out of the box.
- Windows → Credential Locker. Works out of the box.
- Linux/WSL2 → Secret Service. Requires `gnome-keyring` (or KDE's `kwallet`) running. On WSL2 you may need
  `sudo apt install gnome-keyring` and to start it (`dbus-launch gnome-keyring-daemon --start`), or fall back to the encrypted
  file backend in `keyrings.alt`.

## Examples

`examples/rules/atlassian.yaml` and `examples/rules/gitlab.yaml` show worked configurations for Atlassian Cloud (Basic auth) and
GitLab (PRIVATE-TOKEN), including the `keyring set ...` command for each. `examples/rules/codeartifact.yaml` shows `{{exec:...}}`
generating a CodeArtifact auth token on the host and injecting it as Maven Basic auth.
`examples/rules/l4-passthrough.yaml` shows `l4_forward` raw-TCP passthrough for an mTLS upstream (by hostname and by IP CIDR).
