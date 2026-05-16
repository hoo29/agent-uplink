import hashlib
import json
import logging
import os
from pathlib import Path

from .process import run_command

LOGGER = logging.getLogger("agent-uplink")

HOST_CLAUDE_DIR = Path.home() / ".claude"

# Placeholder values injected into the container's settings.json so the Claude
# CLI takes the chosen auth path. The real credentials are added by mitmproxy
# header injection (see rules.py) and never enter the container.
AUTH_MODE_ENV: dict[str, dict[str, str]] = {
    "anthropic": {"ANTHROPIC_AUTH_TOKEN": "placeholder"},
    "bedrock": {"AWS_BEARER_TOKEN_BEDROCK": "placeholder"},
}

# 40-char dummy AWS secret. Real secrets are 40 base64-ish chars; SDKs don't
# validate format. The container signs with these and the signature is
# discarded by mitmproxy before re-signing in aws-sigv4-proxy.
_DUMMY_SECRET = "DUMMYsecret0000000000000000000000000000A"


def load_claude_config() -> dict:
    return json.loads((HOST_CLAUDE_DIR / "settings.json").read_text(encoding="utf8"))


def get_bedrock_aws_profile_name(claude_config: dict) -> str | None:
    return claude_config.get("env", {}).get("AWS_PROFILE")


def write_claude_settings(
    claude_config: dict, session_dir: Path, auth_mode: str
) -> Path:
    filtered = dict(claude_config)
    for key in ["awsAuthRefresh", "sandbox"]:
        filtered.pop(key, None)
    filtered["skipDangerousModePermissionPrompt"] = True
    filtered.setdefault("env", {}).update(AUTH_MODE_ENV[auth_mode])
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
