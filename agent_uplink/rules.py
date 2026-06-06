"""Layer + resolve the YAML rule files into the JSON blob the mitm addon reads.

Pure functions; the caller wraps the returned bytes in a K8s Secret. Two header
placeholder forms are resolved here on the host (so the addon never touches the
user's keyring, YAML, or shell):

  {{keyring:SERVICE:USERNAME}}  static secret from the OS keyring
  {{exec:COMMAND}}              stdout of a host shell command, run at startup

`{{exec:...}}` runs an arbitrary command via the shell with the user's host
environment and credentials — identical trust to a `{{keyring:...}}` lookup or
to typing the command in your own terminal. Only use `--rules` files you trust.
It exists for short-lived dynamic credentials (e.g. an AWS CodeArtifact auth
token) that keyring can't hold. The command can't contain a literal `}}`.
"""

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

# One combined pattern, resolved in a single pass so a resolved secret value is
# never re-scanned (a keyring value that happened to contain "{{exec:...}}" must
# not be executed). keyring: service can't contain ':' or '}', username can't
# contain '}' (usernames with ':' still allowed). exec: non-greedy up to '}}'.
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


def _validate_and_resolve_rule(rule: dict, idx: int, allow_exec: bool) -> dict:
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
                resolved_headers[k] = _resolve_placeholders(v, allow_exec)

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
    auth_rules: list[dict],
    *,
    allow_exec: bool = False,
    aws_sigv4_routes: dict[str, dict[str, Any]] | None = None,
    kube_rules: list[dict] | None = None,
) -> bytes:
    """Build the resolved rules JSON.

    Match priority is by LAYER, not by regex length — first match wins in the
    addon, so the order here is the precedence:

      1. user-supplied YAML        (the operator's intent wins)
      2. kube rules                (auto-generated from --kube-context; always
                                    included when kube is enabled, regardless of
                                    --no-default-rules, so k8s traffic is allowed)
      3. agent auth rules          (per-mode auth header injection, from prepare())
      4. agents/<name>/default_rules.yaml   (per-agent)
      5. agent_uplink/default_rules.yaml    (generic catch-all, evaluated LAST)

    Within a layer, declaration order is preserved. Ordering by layer (rather
    than the old sort-by-host-length heuristic) means the broad generic rule is
    always considered last and a user rule always beats a default.

    `--no-default-rules` (or `replace_defaults: true` in the user's YAML) keeps
    only layers 1–2 and drops the auth rule too — the user becomes responsible for
    supplying any auth the chosen mode needs.

    `allow_exec` permits `{{exec:...}}` placeholders to run host shell commands.
    `aws_sigv4_routes` maps dummy AKIA → {upstream_host, upstream_port} so the
    addon can route AWS requests to the matching aws-sigv4-proxy Service.
    `kube_rules` are synthetic rules produced by kube.resolve(); they are always
    included when non-empty so that k8s traffic is allowed regardless of
    --no-default-rules.
    """
    user_config: dict = {}
    if user_rules_path is not None:
        user_config = _load_yaml(user_rules_path)

    use_defaults = not (no_default_rules or user_config.get("replace_defaults", False))

    layered: list[dict] = list(user_config.get("rules") or [])
    # Kube rules are always included when provided — dropping them via
    # --no-default-rules would silently block all kubectl traffic.
    layered.extend(kube_rules or [])
    if use_defaults:
        layered.extend(auth_rules)
        layered.extend(agent.default_rules())
        layered.extend(_load_yaml(GENERIC_DEFAULT_RULES_PATH).get("rules") or [])

    if not layered:
        raise ValueError("no rules loaded; agent-uplink would deny everything")

    resolved = [
        _validate_and_resolve_rule(r, i, allow_exec) for i, r in enumerate(layered)
    ]
    out: dict[str, Any] = {"rules": resolved}
    if aws_sigv4_routes:
        out["aws_sigv4_routes"] = aws_sigv4_routes
    LOGGER.info(
        f"resolved {len(resolved)} rules"
        + (f", {len(aws_sigv4_routes)} sigv4 routes" if aws_sigv4_routes else "")
    )
    return json.dumps(out, indent=2).encode("utf-8")
