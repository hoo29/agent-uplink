"""AWS profile helpers shared by all agents.

Real AWS credentials live on the host and ride into the mitm pod as a single
K8s Secret: a JSON map from each profile's dummy AKIA to its real credentials.
The mitm addon loads that map and re-signs requests with the matching real key.
The agent container only ever sees deterministic dummy values per profile, so
the mitm addon can map a signed request back to a real identity by the AKIA in
its `Authorization` header.
"""

import hashlib
import json
import logging
import re

from .process import run_command

LOGGER = logging.getLogger("agent-uplink")

# 40-char dummy AWS secret. Real secrets are 40 base64-ish chars; SDKs don't
# validate format. The container signs with these and the signature is discarded
# by the mitm addon, which re-signs with the real key.
_DUMMY_SECRET = "DUMMYsecret0000000000000000000000000000A"

# Profile names are interpolated into INI section headers; restrict them to a
# safe charset so they can't inject INI sections.
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
    except Exception as exc:
        # Surface the original failure before the fallback: `aws sso login`
        # fails for non-SSO problems (e.g. a typo'd profile name) with an error
        # that would otherwise mask the real cause.
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
    """Pick the real credential fields out of an exported AWS env dict.

    The session token is included only when present (long-lived IAM-user keys
    don't have one). Raises if the mandatory key/secret are missing.
    """
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
    """Serialise the dummy-AKIA -> real-credentials map for the mitm pod.

    Wrapped in a K8s Secret and mounted into the mitm pod, where the addon reads
    it to re-sign requests. Never mounted into the agent pod.
    """
    return json.dumps(akia_to_creds, indent=2).encode("utf-8")


def dummy_akia(profile_name: str) -> str:
    """Generate a deterministic dummy AKIA-format access key for a profile.

    The mitm addon parses this back out of the request's Authorization header to
    find the real credentials to re-sign with.
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
