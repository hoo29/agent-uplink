"""Drive the REAL shipping agent-pod assembly — ClaudeAgent.pod_contribution fed
into cli._agent_pod_manifest — and assert its mount/secret wiring, so the
credential-isolation claim is proven against the code that ships, not the
hand-built probe pod the integration tests use. No cluster needed."""

import argparse
from pathlib import Path

import pytest

from agent_uplink import cli
from agent_uplink.agents.base import PodBuildContext
from agent_uplink.agents.claude import agent as claude_agent_mod
from agent_uplink.agents.claude.agent import ClaudeAgent

# Every Secret the shipping agent pod is allowed to mount. rules-json (the real
# injected secrets) must never appear here.
SAFE_SECRET_NAMES = {
    "claude-settings",
    "claude-fake-creds",
    "claude-md",
    "agent-aws-creds",
}


def _agent(auth_mode):
    return ClaudeAgent(argparse.Namespace(auth_mode=auth_mode, image="agent-uplink-claude"))


def _build_pod(tmp_path, monkeypatch, auth_mode, *, aws_secret="agent-aws-creds"):
    # Point the agent's host-probing at a tmp dir so pod_contribution is hermetic
    # (it mkdir's a per-project dir and conditionally mounts ~/.claude/* and ~/.m2).
    monkeypatch.setattr(claude_agent_mod, "HOST_CLAUDE_DIR", tmp_path / ".claude")
    ctx = PodBuildContext(
        cwd=Path("/home/u/proj"), username="u", uid=1000, gid=1000,
        aws_creds_secret_name=aws_secret, debug_host_dir=None, debug=False,
    )
    contribution = _agent(auth_mode).pod_contribution(ctx)
    return cli._agent_pod_manifest(
        "ns", "img", contribution, Path("/home/u/proj"), "u", 1000, ""
    )


def _secret_names(pod):
    return {v["secret"]["secretName"] for v in pod["spec"]["volumes"] if "secret" in v}


@pytest.mark.parametrize("auth_mode", ["anthropic", "bedrock"])
def test_shipping_agent_pod_never_mounts_rules_secret(tmp_path, monkeypatch, auth_mode):
    pod = _build_pod(tmp_path, monkeypatch, auth_mode)
    names = _secret_names(pod)
    assert "rules-json" not in names
    # And every Secret it DOES mount is on the known-safe allow-list — so a future
    # change that mounts a secret-bearing Secret into the agent pod fails here.
    assert names <= SAFE_SECRET_NAMES, f"unexpected secret(s): {names - SAFE_SECRET_NAMES}"


def test_anthropic_mode_mounts_fake_creds_and_settings(tmp_path, monkeypatch):
    names = _secret_names(_build_pod(tmp_path, monkeypatch, "anthropic"))
    assert "claude-settings" in names
    assert "claude-fake-creds" in names  # the FAKE creds, never the real ones


def test_bedrock_mode_has_no_fake_oauth_creds(tmp_path, monkeypatch):
    names = _secret_names(_build_pod(tmp_path, monkeypatch, "bedrock"))
    assert "claude-settings" in names
    assert "claude-fake-creds" not in names


def test_agent_pod_is_labelled_for_egress_policy(tmp_path, monkeypatch):
    pod = _build_pod(tmp_path, monkeypatch, "anthropic")
    assert pod["metadata"]["labels"]["app"] == "agent"
