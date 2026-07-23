"""Unit tests for the Claude host-side credential handling that keeps the real
OAuth token out of the container."""

import json

import pytest

from agent_uplink.agents.claude import config
from agent_uplink.agents.claude.agent import _AUTH_MODE_ENV


def _real_creds(token="real-access-token-SECRET"):
    return {
        "claudeAiOauth": {
            "accessToken": token,
            "refreshToken": "real-refresh-SECRET",
            "expiresAt": 1700000000000,
            "scopes": ["user:inference"],
            "subscriptionType": "pro",
        }
    }


def test_fake_oauth_strips_real_token():
    fake_bytes, real_token = config.fake_oauth_credentials_bytes(_real_creds())
    assert real_token == "real-access-token-SECRET"
    blob = fake_bytes.decode()
    # The real access + refresh tokens must not appear in what the container gets.
    assert "real-access-token-SECRET" not in blob
    assert "real-refresh-SECRET" not in blob
    fake = json.loads(blob)
    assert fake["claudeAiOauth"]["accessToken"].startswith("sk-ant-oat01-agent-uplink-")
    assert fake["claudeAiOauth"]["refreshToken"].startswith("sk-ant-ort01-agent-uplink-")
    # expiresAt is pinned far in the future so the CLI never refreshes in-pod.
    assert fake["claudeAiOauth"]["expiresAt"] > 1700000000000


def test_fake_oauth_preserves_non_secret_fields():
    fake_bytes, _ = config.fake_oauth_credentials_bytes(_real_creds())
    fake = json.loads(fake_bytes)
    assert fake["claudeAiOauth"]["subscriptionType"] == "pro"
    assert fake["claudeAiOauth"]["scopes"] == ["user:inference"]


# --------------------------------------------------------------------------- #
# Missing / malformed host files -> actionable errors, not raw tracebacks
# --------------------------------------------------------------------------- #


def test_load_claude_config_missing_settings_is_actionable(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "HOST_CLAUDE_DIR", tmp_path)
    with pytest.raises(RuntimeError, match="settings.json.*not found"):
        config.load_claude_config()


def test_read_oauth_credentials_missing_file_is_actionable(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "HOST_CLAUDE_DIR", tmp_path)
    with pytest.raises(RuntimeError, match="log in with `claude`"):
        config.read_anthropic_oauth_credentials()


def test_refresh_oauth_missing_expiry_is_actionable(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "HOST_CLAUDE_DIR", tmp_path)
    (tmp_path / ".credentials.json").write_text(json.dumps({"claudeAiOauth": {}}))
    with pytest.raises(RuntimeError, match="expiresAt"):
        config.refresh_anthropic_oauth_if_expiring()


# --------------------------------------------------------------------------- #
# claude_settings_bytes — what reaches the pod's ~/.claude/settings.json
# --------------------------------------------------------------------------- #


def _host_settings():
    """A host settings.json with non-secret config AND secret-bearing keys."""
    return {
        "model": "opus",
        "theme": "dark",
        "apiKeyHelper": "/bin/echo SECRET_HELPER_OUTPUT",
        "env": {"AWS_REGION": "us-east-1", "MY_API_TOKEN": "host-env-secret-TOKEN"},
        "sandbox": {"enabled": True},
        "permissions": {"allow": ["Bash"]},
    }


def test_settings_drops_sandbox_and_defaults_to_auto_mode():
    out = json.loads(config.claude_settings_bytes(_host_settings(), {}))
    assert "sandbox" not in out
    assert out["permissions"] == {
        "defaultMode": "auto",
        "skipDangerousModePermissionPrompt": True,
    }
    assert out["skipDangerousModePermissionPrompt"] is True


def test_settings_injects_bedrock_placeholder_over_non_secret_env():
    out = json.loads(
        config.claude_settings_bytes(_host_settings(), _AUTH_MODE_ENV["bedrock"])
    )
    # The placeholder is injected; the real bearer is added by mitm, never here.
    assert out["env"]["AWS_BEARER_TOKEN_BEDROCK"] == "placeholder"
    # Required for defaultMode "auto" to take effect on Bedrock.
    assert out["env"]["CLAUDE_CODE_ENABLE_AUTO_MODE"] == "1"
    # Non-secret config still passes through.
    assert out["env"]["AWS_REGION"] == "us-east-1"


# --------------------------------------------------------------------------- #
# managed settings (/etc/claude-code/managed-settings.json)
# --------------------------------------------------------------------------- #


def _host_managed():
    return {
        "sandbox": {"enabled": True},
        "permissions": {"defaultMode": "plan", "deny": ["Bash(curl:*)"]},
        "model": "opus",
        "env": {"CORP_PROXY": "http://proxy.corp:3128"},
    }


def test_load_managed_settings_absent_is_none(tmp_path, monkeypatch):
    # No enterprise policy on the host is the common case, not an error — unlike
    # the user settings.json, whose absence raises.
    monkeypatch.setattr(
        config, "HOST_MANAGED_SETTINGS", tmp_path / "managed-settings.json"
    )
    assert config.load_managed_settings() is None


def test_load_managed_settings_reads_host_file(tmp_path, monkeypatch):
    path = tmp_path / "managed-settings.json"
    path.write_text(json.dumps(_host_managed()), encoding="utf8")
    monkeypatch.setattr(config, "HOST_MANAGED_SETTINGS", path)
    assert config.load_managed_settings() == _host_managed()


def test_managed_settings_drops_sandbox_and_forces_auto_mode():
    out = json.loads(config.managed_settings_bytes(_host_managed(), {}))
    assert "sandbox" not in out
    # permissions is replaced exactly as for the user settings.json — managed
    # settings outrank it in Claude's merge, so leaving the host's `plan` mode
    # would override the sandbox's `auto` and make the agent prompt in the pod.
    assert out["permissions"] == {
        "defaultMode": "auto",
        "skipDangerousModePermissionPrompt": True,
    }
    assert out["skipDangerousModePermissionPrompt"] is True
    # Non-permissions policy still passes through.
    assert out["model"] == "opus"


def test_managed_settings_auth_env_outranks_the_host_value():
    # Managed settings beat user settings in Claude's merge, so a real
    # credential in the host policy would otherwise reach the agent container
    # and defeat the placeholder shipped in settings.json.
    managed = {**_host_managed(), "env": {"AWS_BEARER_TOKEN_BEDROCK": "REAL-SECRET"}}
    out = json.loads(
        config.managed_settings_bytes(managed, _AUTH_MODE_ENV["bedrock"])
    )
    assert out["env"]["AWS_BEARER_TOKEN_BEDROCK"] == "placeholder"
    assert "REAL-SECRET" not in json.dumps(out)


def test_managed_settings_passes_through_non_secret_env():
    out = json.loads(
        config.managed_settings_bytes(_host_managed(), _AUTH_MODE_ENV["bedrock"])
    )
    assert out["env"]["CORP_PROXY"] == "http://proxy.corp:3128"
    assert out["env"]["CLAUDE_CODE_ENABLE_AUTO_MODE"] == "1"


def test_managed_settings_redacts_mcp_authorization():
    managed = {
        "mcpServers": {
            "corp": {"url": "https://mcp.corp", "headers": {"Authorization": "Bearer S"}}
        }
    }
    out = json.loads(config.managed_settings_bytes(managed, {}))
    assert out["mcpServers"]["corp"]["headers"]["Authorization"] == "PLACEHOLDER"
