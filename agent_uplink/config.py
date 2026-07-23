"""Load runtime config from `.agent-uplink.yaml` files into the argparse defaults
so every CLI flag can be set from a file.

Discovery walks from the working directory up to `~/.agent-uplink.yaml`.
Precedence low->high: home file -> ... -> cwd file -> CLI args. The schema is
derived from the chosen subparser's actions, so any new flag is configurable
automatically; keys are the flag's dest or long option (dashes/underscores
interchangeable), values coerced with the action's own `type`.

Two shapes get special handling:

  - Repeatable flags (`--aws-profiles`, `--rules`, ...) are *additive* — every
    file's values accumulate; a scalar is a one-element list. A `rules` item may
    be a mapping (an inline rule, see `_STRUCTURED_LIST_DESTS`) passed through
    verbatim; files and inline rules mix and resolve in order.
  - store_const flags sharing a dest (`--anthropic`/`--bedrock` -> `auth_mode`)
    set by option name (`anthropic: true`) or dest (`auth_mode: anthropic`).

This module computes the per-dest values; the caller's `set_defaults(**values)`
is where the additive-list / scalar-override behaviour comes from."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

CONFIG_FILENAME = ".agent-uplink.yaml"

# Never settable from a config file: the subcommand selector and the help flag.
_EXCLUDED_DESTS = {"help", "agent_name"}

# List dests whose items may be inline-rule mappings, passed through verbatim
# (not run through the flag's `type`) for the rule resolver to validate later.
_STRUCTURED_LIST_DESTS = {"rules"}


class ConfigError(ValueError):
    """A `.agent-uplink.yaml` is malformed or references an unknown/invalid key.
    Raised before any cluster work so a bad config never launches pods."""


def _norm(key: str) -> str:
    """Canonicalise a key/option to its dest form: drop leading dashes, dashes to
    underscores. So `--mount-rw`, `mount-rw` and `mount_rw` all map to one key."""
    return key.lstrip("-").replace("-", "_")


@dataclass
class _Spec:
    """The configurable surface of one subparser, derived from its actions."""

    by_dest: dict[str, argparse.Action] = field(default_factory=dict)
    # option-form key (e.g. "anthropic") -> (dest, const value) for store_const
    # flags that set a non-bool const, so `anthropic: true` sets auth_mode.
    const_keys: dict[str, tuple[str, Any]] = field(default_factory=dict)
    # dest -> the set of valid const values, so `auth_mode: anthropic` validates.
    const_dests: dict[str, set[Any]] = field(default_factory=dict)
    list_dests: set[str] = field(default_factory=set)


def _is_list_action(action: argparse.Action) -> bool:
    return isinstance(action, argparse._AppendAction) or action.nargs in ("*", "+")


def _build_spec(parser: argparse.ArgumentParser) -> _Spec:
    spec = _Spec()
    for action in parser._actions:
        dest = action.dest
        if dest in _EXCLUDED_DESTS or dest == argparse.SUPPRESS:
            continue
        if isinstance(action, argparse._SubParsersAction):
            continue
        spec.by_dest[_norm(dest)] = action
        if _is_list_action(action):
            spec.list_dests.add(dest)
        # store_const with a non-bool const (--anthropic/--bedrock);
        # store_true/false carry bool consts and are plain flags below.
        if isinstance(action, argparse._StoreConstAction) and not isinstance(
            action.const, bool
        ):
            spec.const_dests.setdefault(dest, set()).add(action.const)
            for opt in action.option_strings:
                spec.const_keys[_norm(opt)] = (dest, action.const)
    return spec


def _coerce(action: argparse.Action, value: Any, file: Path) -> Any:
    """Apply the action's `type` so config values match what the CLI produces
    (e.g. a Path, not a str). Path values are expanduser'd so `~/...` works."""
    conv = action.type
    if conv is None or value is None:
        return value
    try:
        coerced = conv(value)  # type: ignore[call-arg]
    except (ValueError, TypeError) as exc:
        raise ConfigError(
            f"{file}: invalid value {value!r} for '{action.dest}': {exc}"
        ) from exc
    if isinstance(coerced, Path):
        coerced = coerced.expanduser()
    return coerced


def discover_config_files(cwd: Path, home: Path) -> list[Path]:
    """Every `.agent-uplink.yaml` from `cwd` up to and including `home`, ordered
    least-specific first (home -> ... -> cwd) so later files override earlier
    ones. The walk is bounded by `home` and never reads above it."""
    cwd = cwd.resolve()
    home = home.resolve()
    found: list[Path] = []
    d = cwd
    while True:
        f = d / CONFIG_FILENAME
        if f.is_file():
            found.append(f)
        if d == home or home not in d.parents:
            break
        d = d.parent
    found.reverse()
    return found


def _require_bool(raw_key: str, value: Any, file: Path) -> None:
    """Flags take only real YAML booleans. A quoted string would coerce by
    truthiness (`"false"` -> True), silently inverting the user's intent."""
    if not isinstance(value, bool):
        raise ConfigError(
            f"{file}: {raw_key!r} expects a boolean (true/false), got {value!r}"
        )


def _merge_file(merged: dict[str, Any], data: dict, spec: _Spec, file: Path) -> None:
    for raw_key, value in data.items():
        if not isinstance(raw_key, str):
            raise ConfigError(f"{file}: config keys must be strings, got {raw_key!r}")
        nk = _norm(raw_key)

        # Option-form key for a store_const flag, e.g. `anthropic: true`.
        if nk in spec.const_keys:
            dest, const = spec.const_keys[nk]
            _require_bool(raw_key, value, file)
            if value:
                merged[dest] = const
            continue

        action = spec.by_dest.get(nk)
        if action is None:
            raise ConfigError(
                f"{file}: unknown config key {raw_key!r}; expected one of the "
                f"agent's CLI flags (e.g. {', '.join(sorted(spec.by_dest)[:6])}, ...)"
            )
        dest = action.dest

        # dest-form key for a store_const flag, e.g. `auth_mode: anthropic`.
        if dest in spec.const_dests:
            if value not in spec.const_dests[dest]:
                valid = ", ".join(sorted(map(str, spec.const_dests[dest])))
                raise ConfigError(
                    f"{file}: invalid value {value!r} for {raw_key!r}; "
                    f"expected one of: {valid}"
                )
            merged[dest] = value
            continue

        if dest in spec.list_dests:
            items = value if isinstance(value, list) else [value]
            structured = dest in _STRUCTURED_LIST_DESTS
            coerced = [
                v if structured and isinstance(v, dict) else _coerce(action, v, file)
                for v in items
            ]
            merged.setdefault(dest, []).extend(coerced)
            continue

        # Plain flag (store_true/store_false/BooleanOptionalAction) has nargs 0.
        if action.nargs == 0:
            _require_bool(raw_key, value, file)
            merged[dest] = value
            continue

        merged[dest] = _coerce(action, value, file)


def load_config(
    parser: argparse.ArgumentParser, cwd: Path, home: Path
) -> dict[str, Any]:
    """Resolve `.agent-uplink.yaml` files for `parser` into a dest->value map
    ready for `parser.set_defaults(**map)`. Empty when no config files exist."""
    spec = _build_spec(parser)
    merged: dict[str, Any] = {}
    for file in discover_config_files(cwd, home):
        try:
            loaded = yaml.safe_load(file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise ConfigError(f"{file}: invalid YAML: {exc}") from exc
        if loaded is None:
            continue
        if not isinstance(loaded, dict):
            raise ConfigError(f"{file}: expected a YAML mapping at top level")
        _merge_file(merged, loaded, spec, file)
    return merged
