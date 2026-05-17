import json
import logging
import re
from pathlib import Path
from typing import Any

import keyring
import yaml

from .agents.base import Agent
from .secret import LockedSecret

LOGGER = logging.getLogger("agent-uplink")

GENERIC_DEFAULT_RULES_PATH = Path(__file__).resolve().parent / "default_rules.yaml"


VALID_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "CONNECT",
    "TRACE",
}

# {{keyring:SERVICE:USERNAME}} service can't contain ':' or '}',
# username can't contain '}' (so usernames with ':' are still allowed).
_PLACEHOLDER_RE = re.compile(r"\{\{keyring:([^:}]+):([^}]+)\}\}")


def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a YAML mapping at top level")
    return data


def _resolve_placeholders(value: str) -> str:
    def sub(m: re.Match) -> str:
        service, username = m.group(1), m.group(2)
        secret = keyring.get_password(service, username)
        if secret is None:
            raise RuntimeError(
                f"keyring entry not found: service={service!r} username={username!r}"
            )
        return secret

    return _PLACEHOLDER_RE.sub(sub, value)


def _validate_and_resolve_rule(rule: dict, idx: int) -> dict:
    name = rule.get("name", f"<rule[{idx}]>")
    if "host" not in rule:
        raise ValueError(f"{name}: missing required field 'host'")
    if not isinstance(rule["host"], str):
        raise ValueError(f"{name}: 'host' must be a string regex")
    try:
        re.compile(rule["host"])
    except re.error as e:
        raise ValueError(f"{name}: invalid host regex {rule['host']!r}: {e}")

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
            raise ValueError(
                f"{name}: 'paths' must be a list of regex strings")
        for p in paths:
            try:
                re.compile(p)
            except re.error as e:
                raise ValueError(f"{name}: invalid path regex {p!r}: {e}")

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
                resolved_headers[k] = _resolve_placeholders(v)

    out: dict[str, Any] = {"name": name, "host": rule["host"]}
    if methods is not None:
        out["methods"] = methods
    if paths is not None:
        out["paths"] = paths
    if resolved_headers:
        out["inject"] = {"headers": resolved_headers}
    return out


def resolve(
    user_rules_path: Path | None,
    no_default_rules: bool,
    agent: Agent,
    aws_sigv4_routes: dict[str, dict[str, Any]] | None = None,
) -> LockedSecret:
    """Build resolved rules JSON in an anonymous, mlock'd memfd.

    Layering when defaults are enabled:
      1. agent_uplink/default_rules.yaml          (generic baseline)
      2. agents/<name>/default_rules.yaml         (per-agent)
      3. agent.auth_rules()                       (per-mode auth header injection)
      4. user-supplied YAML                       (always appended)

    `--no-default-rules` (or `replace_defaults: true` in the user's YAML)
    skips layers 1-3 — the user becomes responsible for supplying any auth
    rule needed by the chosen mode.

    `aws_sigv4_routes` maps dummy AKIA → {upstream_host, upstream_port} so the
    addon can route AWS requests to the matching aws-sigv4-proxy sidecar.

    Returned LockedSecret must be close()d after the mitmproxy container is
    stopped; until then its bind_source can be passed as a docker `-v` source.
    """
    user_config: dict = {}
    if user_rules_path is not None:
        user_config = _load_yaml(user_rules_path)

    use_defaults = not (no_default_rules or user_config.get(
        "replace_defaults", False))
    rules: list[dict] = []
    if use_defaults:
        rules.extend(_load_yaml(GENERIC_DEFAULT_RULES_PATH).get("rules") or [])
        rules.extend(agent.default_rules())
        rules.extend(agent.auth_rules())
    rules.extend(user_config.get("rules") or [])

    if not rules:
        raise ValueError("no rules loaded; agent-uplink would deny everything")

    resolved = sorted(
        [_validate_and_resolve_rule(r, i) for i, r in enumerate(rules)],
        key=lambda r: len(r["host"]),
        reverse=True,
    )
    out: dict[str, Any] = {"rules": resolved}
    if aws_sigv4_routes:
        out["aws_sigv4_routes"] = aws_sigv4_routes
    payload = json.dumps(out, indent=2).encode("utf-8")

    secret = LockedSecret("agent-uplink-rules", payload)
    LOGGER.info(
        f"resolved {len(resolved)} rules"
        + (f", {len(aws_sigv4_routes)} sigv4 routes" if aws_sigv4_routes else "")
        + " into locked memfd"
    )
    return secret
