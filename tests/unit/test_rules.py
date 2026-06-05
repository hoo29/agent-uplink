"""Unit tests for the host-side rule resolver. No cluster needed — these pin the
layering precedence, schema validation, and the credential-placeholder
resolution that the addon then relies on."""

import json

import pytest

from agent_uplink import rules
from agent_uplink.agents.base import Agent, PreparedAgent


class _Agent(Agent):
    """Test agent with configurable per-agent default rules."""

    name = "unit"

    def __init__(self, defaults=None):
        super().__init__(args=None)
        self._defaults = defaults or []

    @classmethod
    def add_cli_args(cls, parser):  # pragma: no cover
        pass

    def default_rules(self):
        return list(self._defaults)

    def discover_aws_profiles(self):
        return []

    def prepare(self, session, aws_profile_names):
        return PreparedAgent()


def _write(tmp_path, text):
    p = tmp_path / "rules.yaml"
    p.write_text(text)
    return p


def _resolve(path, agent=None, *, no_default_rules=False, auth_rules=None,
             allow_exec=False, sigv4_routes=None):
    return json.loads(
        rules.resolve(
            path,
            no_default_rules,
            agent or _Agent(),
            auth_rules or [],
            allow_exec=allow_exec,
            aws_sigv4_routes=sigv4_routes,
        )
    )


# --------------------------------------------------------------------------- #
# Layering / precedence
# --------------------------------------------------------------------------- #


def test_layers_in_precedence_order(tmp_path):
    path = _write(tmp_path, "rules:\n  - {name: user, host: 'u'}\n")
    agent = _Agent(defaults=[{"name": "agent-default", "host": "d"}])
    out = _resolve(path, agent, auth_rules=[{"name": "auth", "host": "a"}])
    names = [r["name"] for r in out["rules"]]
    # user -> auth -> agent defaults -> generic catch-all (evaluated last)
    assert names == ["user", "auth", "agent-default", "default-readonly"]


def test_generic_catch_all_is_last(tmp_path):
    out = _resolve(None)  # defaults only
    assert out["rules"][-1]["name"] == "default-readonly"
    assert out["rules"][-1]["host"] == ".*"


def test_no_default_rules_keeps_only_user_layer(tmp_path):
    path = _write(tmp_path, "rules:\n  - {name: user, host: 'u'}\n")
    out = _resolve(path, no_default_rules=True,
                   auth_rules=[{"name": "auth", "host": "a"}])
    assert [r["name"] for r in out["rules"]] == ["user"]


def test_replace_defaults_in_yaml(tmp_path):
    path = _write(
        tmp_path, "replace_defaults: true\nrules:\n  - {name: only, host: 'h'}\n"
    )
    out = _resolve(path, auth_rules=[{"name": "auth", "host": "a"}])
    assert [r["name"] for r in out["rules"]] == ["only"]


def test_no_rules_at_all_raises(tmp_path):
    path = _write(tmp_path, "replace_defaults: true\nrules: []\n")
    with pytest.raises(ValueError, match="no rules loaded"):
        _resolve(path)


# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #


def test_missing_host_rejected(tmp_path):
    path = _write(tmp_path, "rules:\n  - {name: bad, methods: [GET]}\n")
    with pytest.raises(ValueError, match="missing required field 'host'"):
        _resolve(path)


def test_empty_paths_list_rejected(tmp_path):
    path = _write(tmp_path, "rules:\n  - {name: bad, host: 'h', paths: []}\n")
    with pytest.raises(ValueError, match="empty list"):
        _resolve(path)


def test_invalid_method_rejected(tmp_path):
    path = _write(tmp_path, "rules:\n  - {name: bad, host: 'h', methods: [FETCH]}\n")
    with pytest.raises(ValueError, match="invalid method"):
        _resolve(path)


def test_invalid_host_regex_rejected(tmp_path):
    path = _write(tmp_path, "rules:\n  - {name: bad, host: '('}\n")
    with pytest.raises(ValueError, match="invalid host regex"):
        _resolve(path)


# --------------------------------------------------------------------------- #
# Placeholder resolution
# --------------------------------------------------------------------------- #


def test_keyring_placeholder_resolved(tmp_path, monkeypatch):
    monkeypatch.setattr(
        rules.keyring, "get_password",
        lambda service, user: "s3cr3t" if (service, user) == ("svc", "u") else None,
    )
    path = _write(
        tmp_path,
        "rules:\n  - name: r\n    host: 'h'\n    inject:\n      headers:\n"
        "        Authorization: 'Basic {{keyring:svc:u}}'\n",
    )
    out = _resolve(path)
    assert out["rules"][0]["inject"]["headers"]["Authorization"] == "Basic s3cr3t"


def test_keyring_missing_entry_aborts(tmp_path, monkeypatch):
    monkeypatch.setattr(rules.keyring, "get_password", lambda s, u: None)
    path = _write(
        tmp_path,
        "rules:\n  - name: r\n    host: 'h'\n    inject:\n      headers:\n"
        "        Authorization: '{{keyring:svc:u}}'\n",
    )
    with pytest.raises(RuntimeError, match="keyring entry not found"):
        _resolve(path)


def test_exec_placeholder_blocked_without_allow_exec(tmp_path):
    path = _write(
        tmp_path,
        "rules:\n  - name: r\n    host: 'h'\n    inject:\n      headers:\n"
        "        X: '{{exec:echo hi}}'\n",
    )
    with pytest.raises(RuntimeError, match="--allow-exec"):
        _resolve(path, allow_exec=False)


def test_exec_placeholder_runs_with_allow_exec(tmp_path):
    path = _write(
        tmp_path,
        "rules:\n  - name: r\n    host: 'h'\n    inject:\n      headers:\n"
        "        X: '{{exec:printf hello}}'\n",
    )
    out = _resolve(path, allow_exec=True)
    assert out["rules"][0]["inject"]["headers"]["X"] == "hello"


def test_resolution_is_single_pass(tmp_path, monkeypatch):
    # A secret whose VALUE looks like an {{exec:...}} placeholder must not be
    # re-scanned and executed — resolution is single-pass by design.
    monkeypatch.setattr(
        rules.keyring, "get_password", lambda s, u: "{{exec:touch /tmp/pwned}}"
    )
    path = _write(
        tmp_path,
        "rules:\n  - name: r\n    host: 'h'\n    inject:\n      headers:\n"
        "        X: '{{keyring:svc:u}}'\n",
    )
    out = _resolve(path, allow_exec=True)
    assert out["rules"][0]["inject"]["headers"]["X"] == "{{exec:touch /tmp/pwned}}"


# --------------------------------------------------------------------------- #
# SigV4 route embedding
# --------------------------------------------------------------------------- #


def test_sigv4_routes_embedded(tmp_path):
    routes = {"AKIAEXAMPLE": {"upstream_host": "sigv4-p", "upstream_port": 8080}}
    out = _resolve(None, sigv4_routes=routes)
    assert out["aws_sigv4_routes"] == routes
