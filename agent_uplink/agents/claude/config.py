"""Claude-specific host-side config: ~/.claude/settings.json + .credentials.json.

All functions here return bytes; the orchestrator wraps them in K8s Secrets.
"""

import json
import logging
import time
import uuid
from pathlib import Path

from ...process import run_command

LOGGER = logging.getLogger("agent-uplink")

HOST_CLAUDE_DIR = Path.home() / ".claude"

# Pin fake-oauth credentials ~10 years out so Claude never tries to refresh
# from inside the container. Refresh lives on the host.
_FAKE_OAUTH_TTL_SECONDS = 10 * 365 * 24 * 3600


def load_claude_config() -> dict:
    return json.loads((HOST_CLAUDE_DIR / "settings.json").read_text(encoding="utf8"))


def refresh_anthropic_oauth_if_expiring(threshold_seconds: int = 300) -> None:
    """Refresh ~/.claude/.credentials.json on the host if its OAuth token is
    about to expire. The real token is read from this file and injected by
    mitmproxy; refreshing here avoids allow-listing the OAuth refresh endpoint
    inside the container."""
    creds_path = HOST_CLAUDE_DIR / ".credentials.json"
    creds = json.loads(creds_path.read_text(encoding="utf8"))
    expires_at_ms = creds["claudeAiOauth"]["expiresAt"]
    seconds_left = expires_at_ms / 1000 - time.time()
    if seconds_left > threshold_seconds:
        return
    LOGGER.info("refreshing claude oauth token")
    run_command(["claude", "-p", "noop"])


def read_anthropic_oauth_credentials() -> dict:
    """Return host's ~/.claude/.credentials.json contents. Raises if missing."""
    return json.loads(
        (HOST_CLAUDE_DIR / ".credentials.json").read_text(encoding="utf8")
    )


def fake_oauth_credentials_bytes(real_creds: dict) -> tuple[bytes, str]:
    """Build a fake ~/.claude/.credentials.json blob for the container.

    Claude trusts the file as OAuth-mode creds (so the welcome banner renders
    and the configured account is shown), but accessToken/refreshToken are
    bogus and expiresAt is pinned far in the future. mitmproxy swaps the
    Authorization header for the real bearer when proxying api.anthropic.com,
    so the real token never enters the container.

    Returns (json_bytes, real_access_token). The caller hands real_access_token
    to the rules layer for injection.
    """
    oauth = real_creds.get("claudeAiOauth")
    if not isinstance(oauth, dict):
        raise ValueError("~/.claude/.credentials.json missing 'claudeAiOauth' object")
    real_token = oauth.get("accessToken")
    if not isinstance(real_token, str) or not real_token:
        raise ValueError("~/.claude/.credentials.json has no 'accessToken'")

    fake_oauth = dict(oauth)
    fake_oauth["accessToken"] = f"sk-ant-oat01-agent-uplink-{uuid.uuid4().hex}"
    fake_oauth["refreshToken"] = f"sk-ant-ort01-agent-uplink-{uuid.uuid4().hex}"
    fake_oauth["expiresAt"] = (int(time.time()) + _FAKE_OAUTH_TTL_SECONDS) * 1000

    fake = dict(real_creds)
    fake["claudeAiOauth"] = fake_oauth
    return json.dumps(fake, indent=2).encode("utf-8"), real_token


def get_bedrock_aws_profile_name(claude_config: dict) -> str | None:
    return claude_config.get("env", {}).get("AWS_PROFILE")


# settings.json is the user's own config for the CLI we run, but it can hold
# secrets (env API keys, apiKeyHelper/awsCredentialExport commands), so we copy
# an ALLOW-LIST of known-safe top-level keys into the pod rather than the whole
# file minus a couple of keys. `env` is rebuilt separately (below) because it's
# both needed and the most likely place for secrets. Extend these if the in-pod
# CLI needs more — but never add `env`/`apiKeyHelper` here.
_SETTINGS_KEY_ALLOWLIST = frozenset({
    "model",
    "theme",
    "outputStyle",
    "includeCoAuthoredBy",
    "cleanupPeriodDays",
    "permissions",
    "statusLine",
    "spinnerTipsEnabled",
})

# env var NAMES forwarded into the pod. Config-only (no secrets): the bedrock /
# region routing the CLI needs, plus a few non-secret toggles. Anything not
# listed (e.g. ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN) is dropped.
_ENV_NAME_ALLOWLIST = frozenset({
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_SMALL_FAST_MODEL",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_PROFILE",
    "DISABLE_TELEMETRY",
    "DISABLE_AUTOUPDATER",
    "DISABLE_ERROR_REPORTING",
    "BASH_DEFAULT_TIMEOUT_MS",
    "BASH_MAX_TIMEOUT_MS",
    "MAX_THINKING_TOKENS",
    "MCP_TIMEOUT",
})


def claude_settings_bytes(claude_config: dict, auth_env: dict[str, str]) -> bytes:
    """Build the in-pod settings.json from an allow-list of host settings keys
    so host secrets never ride along. `auth_env` (our injected placeholders,
    e.g. AWS_BEARER_TOKEN_BEDROCK) is always merged into env and wins."""
    filtered = {
        k: v for k, v in claude_config.items() if k in _SETTINGS_KEY_ALLOWLIST
    }
    host_env = claude_config.get("env") or {}
    safe_env = {k: v for k, v in host_env.items() if k in _ENV_NAME_ALLOWLIST}
    safe_env.update(auth_env)
    if safe_env:
        filtered["env"] = safe_env
    filtered["skipDangerousModePermissionPrompt"] = True
    return json.dumps(filtered, indent=2).encode("utf-8")
