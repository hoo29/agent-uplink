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


def test_settings_drops_sandbox_and_forces_permissions():
    out = json.loads(config.claude_settings_bytes(_host_settings(), {}))
    assert "sandbox" not in out
    assert out["permissions"] == {"skipDangerousModePermissionPrompt": True}
    assert out["skipDangerousModePermissionPrompt"] is True


def test_settings_injects_bedrock_placeholder_over_non_secret_env():
    out = json.loads(
        config.claude_settings_bytes(_host_settings(), _AUTH_MODE_ENV["bedrock"])
    )
    # The placeholder is injected; the real bearer is added by mitm, never here.
    assert out["env"]["AWS_BEARER_TOKEN_BEDROCK"] == "placeholder"
    # Non-secret config still passes through.
    assert out["env"]["AWS_REGION"] == "us-east-1"
