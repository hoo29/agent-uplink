"""Unit tests for the Agent ABC's shared behaviour: loading per-agent default
rules from disk, the locked-down default pod contribution any new agent inherits,
and the --image repo override. These guard the contract a future agent gets for
free — in particular that the default security context stays hardened (only an
agent that explicitly needs it, like Claude's in-pod dockerd, relaxes it)."""

import argparse
from pathlib import Path

from agent_uplink.agents.base import Agent, PodBuildContext, PreparedAgent


class _BaseAgent(Agent):
    """Minimal concrete Agent that doesn't override pod_contribution, so the
    base-class default is what gets exercised. container_dir() is redirected to a
    test-controlled directory via the _dir class attribute."""

    name = "basetest"
    _dir: Path = Path("/nonexistent")

    @classmethod
    def add_cli_args(cls, parser):  # pragma: no cover - unused
        pass

    @classmethod
    def container_dir(cls) -> Path:
        return cls._dir

    def discover_aws_profiles(self):
        return []

    def prepare(self, session, aws_profile_names):
        return PreparedAgent()


def _agent(image=None, dir_override=None) -> _BaseAgent:
    if dir_override is not None:
        _BaseAgent._dir = dir_override
    return _BaseAgent(argparse.Namespace(image=image))


# --------------------------------------------------------------------------- #
# default_rules: real file I/O + YAML parse
# --------------------------------------------------------------------------- #


def test_default_rules_loads_from_yaml(tmp_path):
    (tmp_path / "default_rules.yaml").write_text(
        "rules:\n  - {name: test_rule, hosts: [example.com]}\n"
    )
    assert _agent(dir_override=tmp_path).default_rules() == [
        {"name": "test_rule", "hosts": ["example.com"]}
    ]


def test_default_rules_empty_when_file_absent(tmp_path):
    # No default_rules.yaml in the dir -> no agent defaults, not an error.
    assert _agent(dir_override=tmp_path).default_rules() == []


# --------------------------------------------------------------------------- #
# default pod_contribution stays hardened
# --------------------------------------------------------------------------- #


def test_default_pod_contribution_is_hardened(tmp_path):
    ctx = PodBuildContext(
        cwd=Path("/home/u/proj"), username="u", uid=1000, gid=1000,
        aws_creds_secret_name=None, debug_host_dir=None, debug=False,
        session_dir=tmp_path,
    )
    contribution = _agent().pod_contribution(ctx)
    sc = contribution.security_context
    assert sc is not None
    assert sc["runAsNonRoot"] is True
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert sc["seccompProfile"]["type"] == "RuntimeDefault"
    assert sc["runAsUser"] == 1000
    assert sc["runAsGroup"] == 1000
    assert contribution.init_command == ["sleep", "infinity"]
    assert contribution.command == ["bash", "-l"]


# --------------------------------------------------------------------------- #
# image repo override
# --------------------------------------------------------------------------- #


def test_image_repo_defaults_to_agent_name():
    assert _agent(image=None).image_repo == "agent-uplink-basetest"


def test_image_repo_uses_cli_override():
    assert _agent(image="my-custom-repo").image_repo == "my-custom-repo"
