# Configuration file

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
  `git_https_rewrite`, `kube_context`, `rules`) accumulate across every config file and the CLI. This relies on argparse's
  `extend` action extending the `set_defaults` list default with the CLI values. The passthrough positional (`claude_args`,
  after `--`) is the exception: a CLI `-- …` replaces a config `claude_args:`.
- **Inline rules.** The `rules` list is special-cased (`config._STRUCTURED_LIST_DESTS`): a list item that is a mapping is
  treated as an inline rule (same schema as a rules-file entry) and passed through verbatim rather than coerced to a
  `Path`. File paths and inline rules can be mixed in one list; `rules.resolve()` concatenates all sources in order
  (earlier sources win first-match). So rules can be defined entirely inline in `.agent-uplink.yaml` with no separate file.
- **store_const flags** that share a dest (`--anthropic`/`--bedrock` → `auth_mode`) are settable by option name
  (`anthropic: true`) or dest (`auth_mode: anthropic`). Because config can supply the mode, the claude subparser's mode
  group is not argparse-`required`; `ClaudeAgent.__init__` enforces that one was supplied by either route.
- Values are coerced with each action's `type` (so a config `rules:` becomes a `Path`, `~` expanded). A malformed YAML,
  unknown key, or invalid value raises `config.ConfigError` and aborts startup before any pod is launched.

See `examples/agent-uplink.yaml` for a worked file.
