"""Claude-specific host-side config. Functions return bytes; the orchestrator
wraps them in K8s Secrets."""

import json
import logging
import time
import uuid
from pathlib import Path

from ...process import run_command

LOGGER = logging.getLogger("agent-uplink")

HOST_CLAUDE_DIR = Path.home() / ".claude"
HOST_CLAUDE_JSON = Path.home() / ".claude.json"
# Optional enterprise policy. Mounted at this same path in the pod so Claude's
# merge precedence over the user settings.json applies unchanged.
HOST_MANAGED_SETTINGS = Path("/etc/claude-code/managed-settings.json")

# Replaces an MCP server's `Authorization` header value so the real bearer never
# enters the pod; the user re-injects it via a mitm rule.
_MCP_PLACEHOLDER = "PLACEHOLDER"

# Pin fake-oauth creds far out so Claude never refreshes from the container.
_FAKE_OAUTH_TTL_SECONDS = 10 * 365 * 24 * 3600


def load_claude_config() -> dict:
    path = HOST_CLAUDE_DIR / "settings.json"
    if not path.is_file():
        raise RuntimeError(
            f"{path} not found; run `claude` on the host once so it creates its "
            "settings before starting agent-uplink"
        )
    return json.loads(path.read_text(encoding="utf8"))


def load_managed_settings() -> dict | None:
    """The host's managed-settings.json, or None when absent (the common case)."""
    if not HOST_MANAGED_SETTINGS.is_file():
        return None
    return json.loads(HOST_MANAGED_SETTINGS.read_text(encoding="utf8"))


def refresh_anthropic_oauth_if_expiring(threshold_seconds: int = 300) -> None:
    """Refresh ~/.claude/.credentials.json on the host if its OAuth token is
    about to expire. The real token is read from this file and injected by
    mitmproxy; refreshing here avoids allow-listing the OAuth refresh endpoint
    inside the container."""
    creds = read_anthropic_oauth_credentials()
    oauth = creds.get("claudeAiOauth")
    if not isinstance(oauth, dict) or "expiresAt" not in oauth:
        raise RuntimeError(
            "~/.claude/.credentials.json has no 'claudeAiOauth.expiresAt'; "
            "log in with `claude` on the host first"
        )
    seconds_left = oauth["expiresAt"] / 1000 - time.time()
    if seconds_left > threshold_seconds:
        return
    LOGGER.info("refreshing claude oauth token")
    run_command(["claude", "-p", "noop"])


def read_anthropic_oauth_credentials() -> dict:
    """Return host's ~/.claude/.credentials.json contents. Raises if missing."""
    path = HOST_CLAUDE_DIR / ".credentials.json"
    if not path.is_file():
        raise RuntimeError(
            f"{path} not found; --anthropic needs the host's Claude OAuth "
            "credentials — log in with `claude` on the host first"
        )
    return json.loads(path.read_text(encoding="utf8"))


def fake_oauth_credentials_bytes(real_creds: dict) -> tuple[bytes, str]:
    """Fake ~/.claude/.credentials.json for the container: bogus tokens with
    expiresAt pinned far out, so Claude takes the OAuth code path without a
    usable token. mitm injects the real bearer on api.anthropic.com.

    Returns (json_bytes, real_access_token) — the caller passes the token to the
    rules layer for injection."""
    oauth = real_creds.get("claudeAiOauth")
    if not isinstance(oauth, dict):
        raise ValueError(
            "~/.claude/.credentials.json missing 'claudeAiOauth' object")
    real_token = oauth.get("accessToken")
    if not isinstance(real_token, str) or not real_token:
        raise ValueError("~/.claude/.credentials.json has no 'accessToken'")

    fake_oauth = dict(oauth)
    fake_oauth["accessToken"] = f"sk-ant-oat01-agent-uplink-{uuid.uuid4().hex}"
    fake_oauth["refreshToken"] = f"sk-ant-ort01-agent-uplink-{uuid.uuid4().hex}"
    fake_oauth["expiresAt"] = (
        int(time.time()) + _FAKE_OAUTH_TTL_SECONDS) * 1000

    fake = dict(real_creds)
    fake["claudeAiOauth"] = fake_oauth
    return json.dumps(fake, indent=2).encode("utf-8"), real_token


# Appended to the container's CLAUDE.md so the agent knows it is sandboxed and
# stops cheaply when it hits a limit it cannot work around.
_SANDBOX_GUIDANCE = """
## Sandbox

- You are running in a microVM sandbox. All HTTPS egress goes through mitmproxy and is enforced against an allow-list. Most credentials will be injected there.
- A `403` with text 'request not permitted by rules' means the host is blocked by policy. Stop — do not retry or try to work around it.
- If anything fails because of the sandbox (blocked network, missing access, readonly filesystem issues etc), stop and say so. Don't waste time or money trying to fix sandbox limitations.
- SSH public keys might be available in ~/.ssh. SSH_AUTH_SOCK points at a proxy with the private keys.
- A Python venv at `~/.venv`. Use it rather than any user-mounted venv in the current directory to avoid any ABI issues with the host OS and python version.
"""


def claude_md_bytes() -> bytes:
    """Container CLAUDE.md: the host's ~/.claude/CLAUDE.md (if any) with the
    sandbox guidance appended. The host file is left untouched."""
    path = HOST_CLAUDE_DIR / "CLAUDE.md"
    base = path.read_text(encoding="utf8") if path.exists() else ""
    if base and not base.endswith("\n"):
        base += "\n"
    return (base + _SANDBOX_GUIDANCE).encode("utf-8")


def sanitized_claude_json_bytes(source: Path) -> bytes:
    """`source` (~/.claude.json) with every MCP server's `Authorization` header
    redacted, in the top-level and per-project `mcpServers` maps. Other headers
    and `env` values pass through. Returns b"{}" if `source` is absent."""
    if not source.exists():
        return b"{}"
    config = json.loads(source.read_text(encoding="utf8"))
    _redact_mcp_servers(config.get("mcpServers"))
    for project in (config.get("projects") or {}).values():
        if isinstance(project, dict):
            _redact_mcp_servers(project.get("mcpServers"))
    return json.dumps(config, indent=2).encode("utf-8")


def _redact_mcp_servers(servers: object) -> None:
    """Redact each server's `Authorization` header (case-insensitive) in place.
    No-op if `servers` is not a dict. Other headers and `env` are untouched, so
    secrets they carry still enter the pod."""
    if not isinstance(servers, dict):
        return
    for server in servers.values():
        if not isinstance(server, dict):
            continue
        headers = server.get("headers")
        if not isinstance(headers, dict):
            continue
        for name in headers:
            if name.lower() == "authorization":
                headers[name] = _MCP_PLACEHOLDER


def get_bedrock_aws_profile_name(claude_config: dict) -> str | None:
    return claude_config.get("env", {}).get("AWS_PROFILE")


def claude_settings_bytes(claude_config: dict, auth_env: dict[str, str]) -> bytes:
    """In-pod ~/.claude/settings.json: the host settings.json with `sandbox`
    dropped and `permissions` replaced by `defaultMode: auto` (the user scope is
    the only one honouring it). `skipDangerousModePermissionPrompt` keeps
    Shift+Tab into bypassPermissions prompt-free. `auth_env` placeholders are
    merged into env and win."""
    settings = dict(claude_config)
    settings.pop("sandbox", None)
    if auth_env:
        settings["env"] = {**(settings.get("env") or {}), **auth_env}
    settings["permissions"] = {
        "defaultMode": "auto",
        "skipDangerousModePermissionPrompt": True,
    }
    settings["skipDangerousModePermissionPrompt"] = True
    return json.dumps(settings, indent=2).encode("utf-8")


def managed_settings_bytes(managed: dict, auth_env: dict[str, str]) -> bytes:
    """In-pod managed-settings.json: same treatment as claude_settings_bytes
    (drop `sandbox`, force `permissions` to `auto`, merge `auth_env`), plus MCP
    `Authorization` redaction. Managed settings outrank the user settings in
    Claude's merge, so a left-intact host `permissions` or a real `env`
    credential here would override the `auto` mode and placeholders shipped in
    settings.json and reach the agent container."""
    settings = dict(managed)
    settings.pop("sandbox", None)
    _redact_mcp_servers(settings.get("mcpServers"))
    if auth_env:
        settings["env"] = {**(settings.get("env") or {}), **auth_env}
    settings["permissions"] = {
        "defaultMode": "auto",
        "skipDangerousModePermissionPrompt": True,
    }
    settings["skipDangerousModePermissionPrompt"] = True
    return json.dumps(settings, indent=2).encode("utf-8")
