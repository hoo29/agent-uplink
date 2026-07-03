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
HOST_CLAUDE_JSON = Path.home() / ".claude.json"

# An MCP server's `Authorization` header in ~/.claude.json is replaced with this
# before the file is mounted, so its bearer token never enters the pod. Claude
# still sees the header present; the user adds a mitm rule to inject the real
# value. All other headers and every `env` value are left untouched.
_MCP_PLACEHOLDER = "PLACEHOLDER"

# Pin fake-oauth credentials ~10 years out so Claude never tries to refresh
# from inside the container. Refresh lives on the host.
_FAKE_OAUTH_TTL_SECONDS = 10 * 365 * 24 * 3600


def load_claude_config() -> dict:
    path = HOST_CLAUDE_DIR / "settings.json"
    if not path.is_file():
        raise RuntimeError(
            f"{path} not found; run `claude` on the host once so it creates its "
            "settings before starting agent-uplink"
        )
    return json.loads(path.read_text(encoding="utf8"))


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

- You are running in a microVM sandbox. All HTTPS egress goes through mitmproxy and is enforced against an allow-list.
- A `403` with text 'request not permitted by rules' means the host is blocked by policy. Stop — do not retry or try to work around it.
- If anything fails because of the sandbox (blocked network, missing access, readonly filesystem issues etc), stop and say so. Don't waste time or money trying to fix sandbox limitations.
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
    """Return `source` (~/.claude.json) with each MCP server's `Authorization`
    header value redacted.

    Walks the top-level `mcpServers` map and each `projects.<path>.mcpServers`
    map; in every server, the `Authorization` header value (if present) is
    replaced with a placeholder. All other headers, every `env` value, and the
    rest of the file are passed through unchanged. Returns b"{}" if `source` is
    absent."""
    if not source.exists():
        return b"{}"
    config = json.loads(source.read_text(encoding="utf8"))
    _redact_mcp_servers(config.get("mcpServers"))
    for project in (config.get("projects") or {}).values():
        if isinstance(project, dict):
            _redact_mcp_servers(project.get("mcpServers"))
    return json.dumps(config, indent=2).encode("utf-8")


def _redact_mcp_servers(servers: object) -> None:
    """Replace the `Authorization` header value of each server in one mcpServers
    map with a placeholder, in place. No-op if `servers` is not a dict or a server
    has no `Authorization` header (match is case-insensitive). All other headers
    and every `env` value are left untouched, so any secret they carry still
    enters the pod."""
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
    """Build the in-pod settings.json by copying the host settings.json wholesale,
    with two changes: the top-level `sandbox` key is dropped, and `permissions` is
    replaced with `{defaultMode: "auto", skipDangerousModePermissionPrompt: true}`.
    The pod's settings.json mounts at ~/.claude/settings.json (user settings) — the
    only scope from which Claude honours `defaultMode: "auto"`. skipDangerousMode...
    keeps Shift+Tab into bypassPermissions prompt-free (the launch flag is
    --allow-dangerously-skip-permissions, which enables but does not activate that
    mode). `auth_env` (our injected placeholders, e.g. AWS_BEARER_TOKEN_BEDROCK and,
    in bedrock mode, CLAUDE_CODE_ENABLE_AUTO_MODE) is merged into env and wins."""
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
