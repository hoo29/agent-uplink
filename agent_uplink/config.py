import hashlib
import json
import logging
import os
import shutil
import time
import uuid
from pathlib import Path

from .process import run_command

LOGGER = logging.getLogger("agent-uplink")

HOST_CLAUDE_DIR = Path.home() / ".claude"

AUTH_MODES: tuple[str, ...] = ("anthropic", "bedrock")

# Placeholder env vars injected into the container's settings.json so the
# Claude CLI takes the chosen auth path. Anthropic mode uses a fake
# .credentials.json instead, so it has no entry here. Real credentials are
# added by mitmproxy header injection (see rules.py) and never enter the
# container.
AUTH_MODE_ENV: dict[str, dict[str, str]] = {
    "bedrock": {"AWS_BEARER_TOKEN_BEDROCK": "placeholder"},
}

# Pin fake-oauth credentials ~10 years out so Claude never tries to refresh
# from inside the container. Refresh lives on the host (see
# refresh_anthropic_oauth_if_expiring).
_FAKE_OAUTH_TTL_SECONDS = 10 * 365 * 24 * 3600

# 40-char dummy AWS secret. Real secrets are 40 base64-ish chars; SDKs don't
# validate format. The container signs with these and the signature is
# discarded by mitmproxy before re-signing in aws-sigv4-proxy.
_DUMMY_SECRET = "DUMMYsecret0000000000000000000000000000A"


def load_claude_config() -> dict:
    return json.loads((HOST_CLAUDE_DIR / "settings.json").read_text(encoding="utf8"))


def refresh_anthropic_oauth_if_expiring(threshold_seconds: int = 300) -> None:
    """Refresh ~/.claude/.credentials.json on the host if its OAuth token is
    about to expire. The file is mounted RW into the container; refreshing
    here avoids needing to allow-list the OAuth refresh endpoint inside the
    container's mitmproxy rules.

    `claude auth status` is the lightest subcommand that touches the auth
    path; if it stops triggering refresh, swap to `claude -p ping`.
    """
    creds_path = HOST_CLAUDE_DIR / ".credentials.json"
    creds = json.loads(creds_path.read_text(encoding="utf8"))
    expires_at_ms = creds["claudeAiOauth"]["expiresAt"]
    seconds_left = expires_at_ms / 1000 - time.time()
    if seconds_left > threshold_seconds:
        return
    if shutil.which("claude") is None:
        raise RuntimeError(
            f"oauth token expires in {int(seconds_left)}s but `claude` not on "
            "PATH; cannot refresh on host"
        )
    LOGGER.info(
        f"oauth token expires in {int(seconds_left)}s; refreshing via "
        "`claude auth status`"
    )
    run_command(["claude", "auth", "status", "--json"])


def read_anthropic_oauth_credentials() -> dict:
    """Return host's ~/.claude/.credentials.json contents. Required for
    anthropic auth mode; raises if missing or unreadable."""
    creds_path = HOST_CLAUDE_DIR / ".credentials.json"
    return json.loads(creds_path.read_text(encoding="utf8"))


def write_fake_oauth_credentials(
    real_creds: dict, session_dir: Path
) -> tuple[Path, str]:
    """Write a fake ~/.claude/.credentials.json for the container.

    Claude trusts the file as OAuth-mode creds (so the welcome banner renders
    and the configured account is shown), but accessToken/refreshToken are
    bogus and expiresAt is pinned far in the future. mitmproxy swaps the
    Authorization header for the real bearer when proxying api.anthropic.com,
    so the real token never enters the container.

    Returns (fake_path, real_access_token). The caller hands real_access_token
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

    path = session_dir / "credentials.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(fake, f, indent=2)
    return path, real_token


def get_bedrock_aws_profile_name(claude_config: dict) -> str | None:
    return claude_config.get("env", {}).get("AWS_PROFILE")


def write_claude_settings(
    claude_config: dict, session_dir: Path, auth_env: dict[str, str]
) -> Path:
    filtered = dict(claude_config)
    for key in ["awsAuthRefresh", "sandbox"]:
        filtered.pop(key, None)
    filtered["skipDangerousModePermissionPrompt"] = True
    if auth_env:
        filtered.setdefault("env", {}).update(auth_env)
    settings_path = session_dir / "settings.json"
    settings_path.write_text(json.dumps(filtered, indent=2))
    return settings_path


def export_aws_profile_env(profile_name: str) -> dict[str, str]:
    """Return real AWS_* env vars for the given profile (host-side only)."""
    cmd = [
        "aws",
        "configure",
        "export-credentials",
        "--format",
        "env-no-export",
        "--profile",
        profile_name,
    ]
    try:
        creds_raw = run_command(cmd)
    except Exception:
        # SSO login launches a browser, so don't run unless needed
        run_command(["aws", "sso", "login", "--profile", profile_name])
        creds_raw = run_command(cmd)
    env: dict[str, str] = {}
    for line in creds_raw.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


def real_aws_credentials_ini(profile_name: str, env: dict[str, str]) -> bytes:
    """Build a shared-credentials-file (INI) blob for one profile.

    Used to feed real creds to an aws-sigv4-proxy sidecar via a mlock'd
    /dev/shm bind-mount instead of `docker run -e ...`. Env vars on a
    container are readable by any host user with docker access via
    `docker inspect` and stick around in /proc/<pid>/environ.
    """
    key_map = {
        "AWS_ACCESS_KEY_ID": "aws_access_key_id",
        "AWS_SECRET_ACCESS_KEY": "aws_secret_access_key",
        "AWS_SESSION_TOKEN": "aws_session_token",
    }
    lines = [f"[{profile_name}]"]
    for env_key, ini_key in key_map.items():
        if env_key in env:
            lines.append(f"{ini_key} = {env[env_key]}")
    lines.append("")
    return "\n".join(lines).encode()


def dummy_akia(profile_name: str) -> str:
    """Generate a deterministic dummy AKIA-format access key for a profile.

    The mitmproxy addon parses this back out of the request's Authorization
    header to determine which aws-sigv4-proxy sidecar to forward to.
    """
    suffix = hashlib.sha256(profile_name.encode()).hexdigest()[:16].upper()
    return f"AKIA{suffix}"


def write_dummy_aws_credentials(
    aws_profile_names: list[str], aws_dir: Path
) -> tuple[Path | None, dict[str, str]]:
    """Write fake AWS creds for the container; return (mount dir, profile→akia).

    The container uses these dummy values to sign requests; mitmproxy strips
    the bogus signature and routes to an aws-sigv4-proxy sidecar that re-signs
    with the real credentials kept on the host.
    """
    if not aws_profile_names:
        return None, {}
    LOGGER.info("writing dummy aws credentials for container")
    profile_to_akia: dict[str, str] = {}
    lines: list[str] = []
    for profile_name in aws_profile_names:
        akia = dummy_akia(profile_name)
        profile_to_akia[profile_name] = akia
        lines.append(f"[{profile_name}]")
        lines.append(f"aws_access_key_id = {akia}")
        lines.append(f"aws_secret_access_key = {_DUMMY_SECRET}")
        lines.append("")
    path = aws_dir / "credentials"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines))
    return aws_dir, profile_to_akia
