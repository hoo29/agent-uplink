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
    # git overlay: host identity + SSH->HTTPS rewrites, no secrets — see git.py.
    "git-config",
}


def _agent(auth_mode, claude_args=None, maven=False):
    return ClaudeAgent(argparse.Namespace(
        auth_mode=auth_mode, image="agent-uplink-claude",
        claude_args=claude_args or [], maven=maven,
    ))


def _build_pod(
    tmp_path, monkeypatch, auth_mode, *, aws_secret: str | None = "agent-aws-creds",
    git_config_secret=None, maven=False,
):
    # Point the agent's host-probing at a tmp dir so pod_contribution is hermetic
    # (it mkdir's a per-project dir and conditionally mounts ~/.claude/*; --maven
    # adds the ~/.m2 mounts).
    monkeypatch.setattr(claude_agent_mod, "HOST_CLAUDE_DIR", tmp_path / ".claude")
    ctx = PodBuildContext(
        cwd=Path("/home/u/proj"), username="u", uid=1000, gid=1000,
        aws_creds_secret_name=aws_secret, debug_host_dir=None, debug=False,
    )
    contribution = _agent(auth_mode, maven=maven).pod_contribution(ctx)
    return cli._agent_pod_manifest(
        "ns", "img", contribution, Path("/home/u/proj"), "u", 1000, "",
        cli.AgentMounts(git_config_secret=git_config_secret),
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


def test_git_config_overlay_not_mounted_by_default(tmp_path, monkeypatch):
    names = _secret_names(_build_pod(tmp_path, monkeypatch, "anthropic"))
    assert "git-config" not in names


def test_git_config_overlay_mounts_at_include_path(tmp_path, monkeypatch):
    pod = _build_pod(
        tmp_path, monkeypatch, "anthropic", git_config_secret="git-config"
    )
    assert "git-config" in _secret_names(pod)
    # And it lands at the include.path baked into /etc/gitconfig, read-only.
    container = pod["spec"]["containers"][0]
    mount = next(
        m for m in container["volumeMounts"] if m["name"] == "git-config"
    )
    assert mount["mountPath"] == "/etc/gitconfig.d/agent-uplink.inc"
    assert mount["subPath"] == "agent-uplink.inc"
    assert mount["readOnly"] is True


def _mount(pod, name):
    container = pod["spec"]["containers"][0]
    return next((m for m in container["volumeMounts"] if m["name"] == name), None)


def _claude_invocation(agent):
    # The interactive command is `runuser -u u -- bash -lc '<script>'`; return
    # the trailing bash script that ends with the `exec claude ...` line.
    return agent._container_command("u", False, agent.args.claude_args)[-1]


def test_default_invocation_allows_skip_permissions_only():
    # --allow- enables bypassPermissions in the Shift+Tab cycle without
    # activating it; the default mode is "auto" via settings.json.
    script = _claude_invocation(_agent("anthropic"))
    assert script.endswith("exec claude --allow-dangerously-skip-permissions")


def test_passthrough_args_appended_after_allow_skip_permissions():
    script = _claude_invocation(_agent("anthropic", ["--resume", "abc123"]))
    assert script.endswith(
        "exec claude --allow-dangerously-skip-permissions --resume abc123"
    )


def test_debug_flag_precedes_allow_skip_permissions_with_passthrough():
    agent = _agent("anthropic", ["-c"])
    script = agent._container_command("u", True, agent.args.claude_args)[-1]
    assert script.endswith("exec claude -d --allow-dangerously-skip-permissions -c")


def test_passthrough_args_are_shell_quoted():
    # A prompt with spaces must reach claude as a single argv element, not be
    # word-split by the bash -lc string.
    script = _claude_invocation(_agent("anthropic", ["-p", "explain this; rm -rf /"]))
    assert (
        "exec claude --allow-dangerously-skip-permissions -p 'explain this; rm -rf /'"
        in script
    )


def test_maven_not_mounted_without_flag(tmp_path, monkeypatch):
    # HOME has a ~/.m2, but without --maven nothing is mounted and no Maven env.
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".m2").mkdir()
    (tmp_path / ".m2" / "settings.xml").write_text("<settings/>\n")
    pod = _build_pod(tmp_path, monkeypatch, "anthropic", aws_secret=None, maven=False)
    assert _mount(pod, "m2-repo") is None
    assert _mount(pod, "m2-settings") is None
    assert "MAVEN_OPTS" not in _agent("anthropic", maven=False)._container_env(
        Path("/home/u/proj")
    )


def test_maven_flag_mounts_repo_and_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".m2").mkdir()
    (tmp_path / ".m2" / "settings.xml").write_text("<settings/>\n")
    pod = _build_pod(tmp_path, monkeypatch, "anthropic", aws_secret=None, maven=True)
    repo = _mount(pod, "m2-repo")
    settings = _mount(pod, "m2-settings")
    assert repo is not None and repo["mountPath"] == "/home/u/.m2/repository"
    assert repo.get("readOnly") is not True  # read-write
    assert settings is not None
    assert settings["mountPath"] == "/home/u/.m2/settings.xml"
    assert settings["readOnly"] is True


def test_maven_flag_sets_proxy_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".m2").mkdir()
    contribution = _agent("anthropic", maven=True).pod_contribution(
        PodBuildContext(
            cwd=Path("/home/u/proj"), username="u", uid=1000, gid=1000,
            aws_creds_secret_name=None, debug_host_dir=None, debug=False,
        )
    )
    assert "mitm" in contribution.env["MAVEN_OPTS"]
    assert contribution.env["CODEARTIFACT_AUTH_TOKEN"] == "placeholder"
