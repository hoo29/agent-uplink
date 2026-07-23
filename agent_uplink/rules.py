"""Layer + resolve the YAML rule files into the JSON the mitm addon reads. Two
header-placeholder forms are resolved here on the host so the addon never touches
the keyring, YAML, or shell:

  {{keyring:SERVICE:USERNAME}}  static secret from the OS keyring
  {{exec:COMMAND}}              stdout of a host shell command, run at startup

`{{exec:...}}` runs an arbitrary shell command with the user's host credentials
(gated behind --allow-exec) — for short-lived dynamic tokens keyring can't hold.
Only use `--rules` files you trust. The command can't contain a literal `}}`."""

import ipaddress
import json
import logging
import re
import subprocess
from pathlib import Path
from typing import Any

import keyring
import yaml

from .agents.base import Agent

LOGGER = logging.getLogger("agent-uplink")

GENERIC_DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "default_rules.yaml"


VALID_METHODS = {
    "GET", "POST", "PUT", "DELETE", "PATCH",
    "HEAD", "OPTIONS", "CONNECT", "TRACE",
}

# One combined pattern in a single pass, so a resolved secret is never re-scanned
# (a keyring value containing "{{exec:...}}" must not be executed). keyring:
# service excludes ':'/'}', username excludes '}'; exec: non-greedy up to '}}'.
_PLACEHOLDER_RE = re.compile(
    r"\{\{(?:keyring:(?P<service>[^:}]+):(?P<username>[^}]+)"
    r"|exec:(?P<cmd>.+?))\}\}",
    re.DOTALL,
)


def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at top level")
    return data


def _run_exec(cmd: str) -> str:
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, check=True
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            f"exec placeholder failed (exit {e.returncode}): {cmd!r}\n"
            f"{e.stderr.strip()}"
        ) from e
    return result.stdout.strip()


def _resolve_placeholders(value: str, allow_exec: bool) -> str:
    def sub(m: re.Match) -> str:
        if m.group("cmd") is not None:
            if not allow_exec:
                raise RuntimeError(
                    "rules file uses an {{exec:...}} placeholder, which runs a host "
                    "shell command at startup; re-run with --allow-exec to permit it"
                )
            return _run_exec(m.group("cmd"))
        service, username = m.group("service"), m.group("username")
        secret = keyring.get_password(service, username)
        if secret is None:
            raise RuntimeError(
                f"keyring entry not found: service={service!r} username={username!r}"
            )
        return secret

    return _PLACEHOLDER_RE.sub(sub, value)


def _validate_hosts(rule: dict, name: str) -> list[str]:
    """Validate the required `hosts` field: a non-empty list of regex strings,
    each a valid pattern. Returns the list unchanged."""
    hosts = rule.get("hosts")
    if not isinstance(hosts, list) or not all(isinstance(h, str) for h in hosts):
        raise ValueError(f"{name}: 'hosts' must be a list of regex strings")
    if not hosts:
        raise ValueError(f"{name}: 'hosts' is an empty list; list at least one host")
    for h in hosts:
        try:
            re.compile(h)
        except re.error as e:
            raise ValueError(f"{name}: invalid host regex {h!r}: {e}") from e
    return hosts


def _validate_l4_forward_rule(rule: dict, name: str) -> dict:
    """An l4_forward rule tunnels raw TCP without terminating TLS, so it takes no
    methods/paths/inject (mitm never sees the plaintext) and matches on `hosts`
    (hostname regexes) and/or `cidrs` (literal-IP targets); at least one."""
    hosts = rule.get("hosts")
    cidrs = rule.get("cidrs")
    if hosts is None and cidrs is None:
        raise ValueError(f"{name}: l4_forward rule needs 'hosts' and/or 'cidrs'")
    for forbidden in ("methods", "paths", "inject"):
        if forbidden in rule:
            raise ValueError(
                f"{name}: l4_forward rule cannot set {forbidden!r} — mitm tunnels "
                "the raw connection and never sees the plaintext request"
            )
    out: dict[str, Any] = {"name": name, "l4_forward": True}
    if hosts is not None:
        out["hosts"] = _validate_hosts(rule, name)
    if cidrs is not None:
        if not isinstance(cidrs, list) or not all(isinstance(c, str) for c in cidrs):
            raise ValueError(f"{name}: 'cidrs' must be a list of CIDR strings")
        if not cidrs:
            raise ValueError(f"{name}: 'cidrs' is an empty list; omit it instead")
        normalised: list[str] = []
        for c in cidrs:
            try:
                normalised.append(str(ipaddress.ip_network(c, strict=False)))
            except ValueError as e:
                raise ValueError(f"{name}: invalid CIDR {c!r}: {e}") from e
        out["cidrs"] = normalised
    return out


def _validate_and_resolve_rule(rule: dict, idx: int, allow_exec: bool) -> dict:
    name = rule.get("name", f"<rule[{idx}]>")
    if rule.get("l4_forward"):
        return _validate_l4_forward_rule(rule, name)
    if "hosts" not in rule:
        raise ValueError(f"{name}: missing required field 'hosts'")
    hosts = _validate_hosts(rule, name)

    methods = rule.get("methods")
    if methods is not None:
        if not isinstance(methods, list) or not all(
            isinstance(m, str) for m in methods
        ):
            raise ValueError(f"{name}: 'methods' must be a list of strings")
        bad = [m for m in methods if m not in VALID_METHODS]
        if bad:
            raise ValueError(
                f"{name}: invalid method(s) {bad}; must be uppercase HTTP verbs"
            )

    paths = rule.get("paths")
    if paths is not None:
        if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
            raise ValueError(f"{name}: 'paths' must be a list of regex strings")
        if not paths:
            raise ValueError(
                f"{name}: 'paths' is an empty list, which would match no path; "
                "omit 'paths' entirely to allow any path"
            )
        for p in paths:
            try:
                re.compile(p)
            except re.error as e:
                raise ValueError(f"{name}: invalid path regex {p!r}: {e}") from e

    resolved_headers: dict[str, str] = {}
    inject = rule.get("inject")
    if inject is not None:
        headers = inject.get("headers")
        if headers is not None:
            if not isinstance(headers, dict):
                raise ValueError(f"{name}: 'inject.headers' must be a mapping")
            for k, v in headers.items():
                if not isinstance(v, str):
                    raise ValueError(f"{name}: header {k!r} must be a string")
                resolved_headers[k] = _resolve_placeholders(v, allow_exec)

    out: dict[str, Any] = {"name": name, "hosts": hosts}
    if methods is not None:
        out["methods"] = methods
    if paths is not None:
        out["paths"] = paths
    if resolved_headers:
        out["inject"] = {"headers": resolved_headers}
    return out


def resolve(
    user_rules: "Path | list[Path | dict] | None",
    no_default_rules: bool,
    agent: Agent,
    auth_rules: list[dict],
    *,
    allow_exec: bool = False,
    kube_rules: list[dict] | None = None,
) -> bytes:
    """Build the resolved rules JSON. First match wins in the addon, so priority
    is by LAYER (declaration order preserved within each):

      1. agent auth rules   (per-mode credential injection, from prepare())
      2. kube rules         (from --kube-context)
      3. user rules         (the operator's added destinations)
      4. agents/<name>/default_rules.yaml   (per-agent)
      5. agent_uplink/default_rules.yaml    (generic catch-all, LAST)

    Auth and kube rules sit ABOVE user rules deliberately: each injects a
    credential on a narrow host, and a broad user allow rule on an overlapping
    host would otherwise win first-match and strip it. Use --no-default-rules to
    take over auth entirely.

    `user_rules` is a sequence of rule *sources* forming the user layer, first
    source winning: a `Path` (a YAML `{rules: [...], replace_defaults?}` file) or
    a `dict` (a single inline rule). A bare `Path`/`None` is shorthand.

    `--no-default-rules` (or `replace_defaults: true` in a file) drops the auth
    and per-agent/generic layers, keeping only kube + user rules. `kube_rules`
    are always included when non-empty. `allow_exec` gates `{{exec:...}}`."""
    if user_rules is None:
        sources: list = []
    elif isinstance(user_rules, (str, Path)):
        sources = [user_rules]
    else:
        sources = list(user_rules)

    # `replace_defaults` in any file source switches off the built-in layers.
    user_layer: list[dict] = []
    replace_defaults = False
    for source in sources:
        if isinstance(source, dict):
            user_layer.append(source)
            continue
        cfg = _load_yaml(Path(source))
        if cfg.get("replace_defaults", False):
            replace_defaults = True
        user_layer.extend(cfg.get("rules") or [])

    use_defaults = not (no_default_rules or replace_defaults)

    layered: list[dict] = []
    if use_defaults:
        layered.extend(auth_rules)
    # Always included (dropping them would block all kubectl traffic); above user
    # rules for the same shadow-protection reason as auth rules.
    layered.extend(kube_rules or [])
    layered.extend(user_layer)
    if use_defaults:
        layered.extend(agent.default_rules())
        layered.extend(_load_yaml(GENERIC_DEFAULT_RULES_PATH).get("rules") or [])

    if not layered:
        raise ValueError("no rules loaded; agent-uplink would deny everything")

    resolved = [
        _validate_and_resolve_rule(r, i, allow_exec) for i, r in enumerate(layered)
    ]
    out: dict[str, Any] = {"rules": resolved}
    LOGGER.info(f"resolved {len(resolved)} rules")
    return json.dumps(out, indent=2).encode("utf-8")
