import json
import logging
import os
from pathlib import Path

from .process import run_command

LOGGER = logging.getLogger("agent-uplink")

HOST_CLAUDE_DIR = Path.home() / ".claude"


def load_claude_config() -> dict:
    return json.loads((HOST_CLAUDE_DIR / "settings.json").read_text(encoding="utf8"))


def get_bedrock_aws_profile_name(claude_config: dict) -> str | None:
    return claude_config.get("env", {}).get("AWS_PROFILE")


def write_claude_settings(claude_config: dict, session_dir: Path) -> Path:
    filtered = dict(claude_config)
    for key in ["awsAuthRefresh", "sandbox", "permissions"]:
        filtered.pop(key, None)
    filtered["skipDangerousModePermissionPrompt"] = True
    settings_path = session_dir / "settings.json"
    settings_path.write_text(json.dumps(filtered, indent=2))
    return settings_path


def _export_aws_profile(profile_name: str) -> list[str]:
    cmd = [
        "aws", "configure", "export-credentials",
        "--format", "env-no-export",
        "--profile", profile_name,
    ]
    try:
        creds_raw = run_command(cmd)
    except Exception:
        # SSO login launches a browser, so don't run unless needed
        run_command(["aws", "sso", "login", "--profile", profile_name])
        creds_raw = run_command(cmd)
    creds_raw = creds_raw.splitlines()
    creds = []
    for cred_raw in creds_raw:
        cred = list(cred_raw.partition("="))
        cred[0] = cred[0].lower()
        creds.append(" ".join(cred))

    return creds


def write_aws_credentials(
    aws_profile_names: list[str], aws_dir: Path
) -> Path | None:
    if not aws_profile_names:
        return None
    LOGGER.info("generating temp aws credentials")
    lines: list[str] = []
    for profile_name in aws_profile_names:
        lines.append(f"[{profile_name}]")
        lines.extend(_export_aws_profile(profile_name))
    path = aws_dir / "credentials"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines))
    return aws_dir
