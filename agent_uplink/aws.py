"""AWS profile helpers shared by all agents.

Real AWS credentials live on the host and ride into per-profile
`aws-sigv4-proxy` sidecar pods as K8s Secrets mounted at
`/aws/credentials`. The agent container only sees deterministic dummy
values per profile, derived so the mitm addon can map a signed request
back to a sidecar by the AKIA in its `Authorization` header.
"""

import hashlib
import logging
import re

from .process import run_command

LOGGER = logging.getLogger("agent-uplink")

# 40-char dummy AWS secret. Real secrets are 40 base64-ish chars; SDKs don't
# validate format. The container signs with these and the signature is
# discarded by mitmproxy before re-signing in aws-sigv4-proxy.
_DUMMY_SECRET = "DUMMYsecret0000000000000000000000000000A"

# Profile names are interpolated into INI section headers and into k8s resource
# names; restrict them to a safe charset so they can't inject INI sections or
# break manifest names.
_PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")


def validate_profile_name(profile_name: str) -> None:
    if not _PROFILE_NAME_RE.fullmatch(profile_name):
        raise ValueError(
            f"invalid AWS profile name {profile_name!r}: only letters, digits, "
            "'.', '_' and '-' are allowed"
        )


def export_aws_profile_env(profile_name: str) -> dict[str, str]:
    """Return real AWS_* env vars for the given profile (host-side only).

    Falls back to `aws sso login` (which launches a browser) if the initial
    export fails, then retries.
    """
    cmd = [
        "aws", "configure", "export-credentials",
        "--format", "env-no-export", "--profile", profile_name,
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

    Wrapped in a K8s Secret and mounted into the matching aws-sigv4-proxy
    sidecar at /aws/credentials.
    """
    validate_profile_name(profile_name)
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


def dummy_aws_credentials_ini(
    aws_profile_names: list[str],
) -> tuple[bytes, dict[str, str]]:
    """Build the dummy `~/.aws/credentials` INI for the agent container.

    Returns (ini_bytes, profile_to_akia). When `aws_profile_names` is empty,
    returns (b"", {}) so the caller can skip creating the Secret entirely.
    """
    if not aws_profile_names:
        return b"", {}
    profile_to_akia: dict[str, str] = {}
    lines: list[str] = []
    for profile_name in aws_profile_names:
        validate_profile_name(profile_name)
        akia = dummy_akia(profile_name)
        profile_to_akia[profile_name] = akia
        lines.append(f"[{profile_name}]")
        lines.append(f"aws_access_key_id = {akia}")
        lines.append(f"aws_secret_access_key = {_DUMMY_SECRET}")
        lines.append("")
    return "\n".join(lines).encode(), profile_to_akia


def sanitize_profile_for_k8s_name(profile: str) -> str:
    """RFC 1123 label rules: [a-z0-9-], starts/ends alnum, max 63 chars.
    Used in Secret/Pod/Service names."""
    out = "".join(c.lower() if c.isalnum() else "-" for c in profile)
    out = out.strip("-") or "default"
    return out[:63]
