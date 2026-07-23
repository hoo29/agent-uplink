"""AWS profile helpers shared by all agents.

Real credentials ride into the mitm pod as a Secret mapping each profile's dummy
AKIA to its real credentials. The agent container sees only the deterministic
dummy values, so the addon maps a signed request back to a real identity by the
AKIA in its `Authorization` header and re-signs."""

import hashlib
import json
import logging
import re

from .process import run_command

LOGGER = logging.getLogger("agent-uplink")

# 40-char dummy secret the container signs with; the signature is discarded and
# re-signed by the addon. SDKs don't validate the format.
_DUMMY_SECRET = "DUMMYsecret0000000000000000000000000000A"

# Profile names go into INI section headers; restrict the charset so they can't
# inject sections.
_PROFILE_NAME_RE = re.compile(r"[A-Za-z0-9._-]+")


def validate_profile_name(profile_name: str) -> None:
    if not _PROFILE_NAME_RE.fullmatch(profile_name):
        raise ValueError(
            f"invalid AWS profile name {profile_name!r}: only letters, digits, "
            "'.', '_' and '-' are allowed"
        )


def export_aws_profile_env(profile_name: str) -> dict[str, str]:
    """Real AWS_* env vars for the profile (host-side only). Falls back to
    `aws sso login` (browser) on export failure, then retries."""
    cmd = [
        "aws", "configure", "export-credentials",
        "--format", "env-no-export", "--profile", profile_name,
    ]
    try:
        creds_raw = run_command(cmd)
    except Exception as exc:
        # Log the original failure first: for a non-SSO problem (e.g. a typo'd
        # profile) `aws sso login` fails with an error that masks the real cause.
        LOGGER.info(
            f"aws export-credentials failed for profile {profile_name!r} "
            f"({exc}); attempting `aws sso login`"
        )
        run_command(["aws", "sso", "login", "--profile", profile_name])
        creds_raw = run_command(cmd)
    env: dict[str, str] = {}
    for line in creds_raw.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


def real_aws_credentials(env: dict[str, str]) -> dict[str, str]:
    """Real credential fields from an exported AWS env dict. Session token
    included only when present (IAM-user keys have none); raises if key/secret
    are missing."""
    try:
        creds = {
            "access_key_id": env["AWS_ACCESS_KEY_ID"],
            "secret_access_key": env["AWS_SECRET_ACCESS_KEY"],
        }
    except KeyError as exc:
        raise ValueError(f"missing AWS credential field: {exc.args[0]}") from exc
    if env.get("AWS_SESSION_TOKEN"):
        creds["session_token"] = env["AWS_SESSION_TOKEN"]
    return creds


def sigv4_credentials_json(akia_to_creds: dict[str, dict[str, str]]) -> bytes:
    """Serialise the dummy-AKIA -> real-credentials map for the mitm pod (never
    the agent pod)."""
    return json.dumps(akia_to_creds, indent=2).encode("utf-8")


def dummy_akia(profile_name: str) -> str:
    """Deterministic dummy AKIA for a profile; the addon parses it back out of
    the Authorization header to find the real credentials."""
    suffix = hashlib.sha256(profile_name.encode()).hexdigest()[:16].upper()
    return f"AKIA{suffix}"


def dummy_aws_credentials_ini(
    aws_profile_names: list[str],
) -> tuple[bytes, dict[str, str]]:
    """Dummy `~/.aws/credentials` INI for the agent container. Returns
    (ini_bytes, profile_to_akia), or (b"", {}) when no profiles are given."""
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
