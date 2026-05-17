"""AWS profile helpers shared by all agents.

Real AWS credentials live on the host and are passed to per-profile
`aws-sigv4-proxy` sidecars via mlock'd `/dev/shm` files (see secret.py).
The agent container only sees dummy values, deterministically derived per
profile so the mitm addon can map a signed request back to a sidecar by
the AKIA in its `Authorization` header.
"""

import hashlib
import logging
import os
from pathlib import Path

from .process import run_command

LOGGER = logging.getLogger("agent-uplink")

# 40-char dummy AWS secret. Real secrets are 40 base64-ish chars; SDKs don't
# validate format. The container signs with these and the signature is
# discarded by mitmproxy before re-signing in aws-sigv4-proxy.
_DUMMY_SECRET = "DUMMYsecret0000000000000000000000000000A"


def export_aws_profile_env(profile_name: str) -> dict[str, str]:
    """Return real AWS_* env vars for the given profile (host-side only).

    Falls back to `aws sso login` (which launches a browser) if the initial
    export fails, then retries.
    """
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
    """Write fake AWS creds for an agent container; return (mount dir, profile→akia).

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


def sanitize_profile_for_container_name(profile: str) -> str:
    """Container names allow [a-zA-Z0-9_.-]; AWS profile names allow more,
    so sanitize defensively before using a profile name in a container name."""
    return "".join(c if c.isalnum() or c in "._-" else "-" for c in profile)
