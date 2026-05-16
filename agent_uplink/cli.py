import argparse
import logging
import os
import signal
from functools import partial
from pathlib import Path

import keyring

from .config import (
    AUTH_MODE_ENV,
    AUTH_MODES,
    export_aws_profile_env,
    get_bedrock_aws_profile_name,
    load_claude_config,
    read_anthropic_oauth_credentials,
    real_aws_credentials_ini,
    refresh_anthropic_oauth_if_expiring,
    write_claude_settings,
    write_dummy_aws_credentials,
    write_fake_oauth_credentials,
)
from .docker_ops import (
    CLAUDE_IMAGE_MAX_AGE_SECONDS,
    build_claude_image,
    build_claude_mounts,
    create_network,
    ensure_mitm_certs,
    get_claude_image_age_seconds,
    get_container_home,
    start_claude_container,
    start_mitm_proxy,
    start_sigv4_proxy,
)
from .process import get_free_port
from .rules import resolve as resolve_rules
from .secret import LockedSecret
from .session import Session, handle_signal

LOGGER = logging.getLogger("agent-uplink")

STATE_DIR = Path.home() / ".agent_uplink"

DEFAULT_SIGV4_PROXY_IMAGE = "public.ecr.aws/aws-observability/aws-sigv4-proxy:latest"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Trust is a weakness",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-a",
        "--aws-profiles",
        type=str,
        nargs="*",
        action="extend",
        default=[],
        help="AWS profiles to provide credentials for (one sigv4-proxy sidecar per profile)",
    )
    parser.add_argument(
        "-m",
        "--mitmproxy-image",
        type=str,
        default="mitmproxy/mitmproxy",
    )
    parser.add_argument(
        "-c",
        "--claude-image",
        type=str,
        default="agent-uplink-claude",
    )
    parser.add_argument(
        "--sigv4-proxy-image",
        type=str,
        default=DEFAULT_SIGV4_PROXY_IMAGE,
    )
    parser.add_argument(
        "-f",
        "--force-rebuild",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Force rebuild of the Claude container image",
    )
    parser.add_argument(
        "-r",
        "--rules",
        type=Path,
        default=None,
        help="YAML rules file (allow-list policy + credential injection)",
    )
    parser.add_argument(
        "--no-default-rules",
        action="store_true",
        help="Don't merge built-in defaults (allow GET/OPTIONS everywhere)",
    )
    parser.add_argument(
        "--runtime",
        type=str,
        default="runsc",
        help="Docker runtime for the Claude container (e.g. runsc, runc)",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Run claude with -d and mount ~/.claude/debug from the container "
        "to /tmp/agent-uplink-debug/<session-id> on the host",
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    for mode in AUTH_MODES:
        mode_group.add_argument(
            f"--{mode}",
            dest="auth_mode",
            action="store_const",
            const=mode,
            help=f"Configure container for {mode} auth",
        )
    return parser.parse_args()


def validate_cwd(username: str, cwd: Path) -> None:
    # The container bind-mounts cwd at the same path it has on the host;
    # only paths under /home/<username>/ exist on both sides.
    home = get_container_home(username)
    if cwd != home and home not in cwd.parents:
        raise ValueError(f"agent-uplink must be run from within {home}, got: {cwd}")


def _sidecar_name(session_id: str, profile: str) -> str:
    # Container names: lowercase, [a-zA-Z0-9_.-]. AWS profile names allow more,
    # so sanitize defensively.
    safe = "".join(c if c.isalnum() or c in "._-" else "-" for c in profile)
    return f"agent-uplink-sigv4-{session_id}-{safe}"


def run(session: Session, args: argparse.Namespace) -> None:
    username = os.environ["USER"]
    cwd = Path.cwd()
    validate_cwd(username, cwd)

    mitm_dir = STATE_DIR / "mitm"
    mitm_dir.mkdir(parents=True, exist_ok=True)

    claude_config = load_claude_config()
    oauth_creds_path: Path | None = None
    oauth_token: str | None = None
    bedrock_token: str | None = None
    if args.auth_mode == "anthropic":
        refresh_anthropic_oauth_if_expiring()
        real_creds = read_anthropic_oauth_credentials()
        oauth_creds_path, oauth_token = write_fake_oauth_credentials(
            real_creds, session.session_dir
        )
        LOGGER.info("using fake .credentials.json (real token via mitm)")
    elif args.auth_mode == "bedrock":
        bedrock_token = keyring.get_password("bedrock", "key")
        if bedrock_token is None:
            raise RuntimeError(
                "bedrock bearer token not found in keyring; "
                "run: keyring set bedrock key"
            )
    aws_profile_names = list(args.aws_profiles)
    bedrock_profile = get_bedrock_aws_profile_name(claude_config)
    if bedrock_profile is not None:
        aws_profile_names.append(bedrock_profile)
    # dedupe, preserve order
    aws_profile_names = list(dict.fromkeys(aws_profile_names))

    certs_generated = ensure_mitm_certs(mitm_dir, args.mitmproxy_image)
    image_age = get_claude_image_age_seconds(args.claude_image)
    if (
        certs_generated
        or args.force_rebuild
        or image_age is None
        or image_age > CLAUDE_IMAGE_MAX_AGE_SECONDS
    ):
        build_claude_image(args.claude_image, username, mitm_dir, args.force_rebuild)

    # Real AWS creds — one mlock'd /dev/shm credentials file per profile,
    # bind-mounted into the matching sidecar. Avoids `docker run -e ...`,
    # which exposes secrets to any host user via `docker inspect`.
    real_aws_creds_secrets: dict[str, LockedSecret] = {}
    for profile in aws_profile_names:
        env = export_aws_profile_env(profile)
        safe = "".join(c if c.isalnum() or c in "._-" else "-" for c in profile)
        secret = LockedSecret(f"aws-{safe}", real_aws_credentials_ini(profile, env))
        real_aws_creds_secrets[profile] = secret
        session.secrets.append(secret)
    # Fake AWS creds — written to the container's ~/.aws/credentials. The
    # dummy AKIA per profile is the key the mitm addon uses to pick the
    # right sigv4-proxy sidecar.
    aws_creds_path, profile_to_akia = write_dummy_aws_credentials(
        aws_profile_names, session.aws_dir
    )

    auth_env = dict(AUTH_MODE_ENV.get(args.auth_mode, {}))
    settings_path = write_claude_settings(claude_config, session.session_dir, auth_env)
    debug_host_dir: Path | None = None
    if args.debug:
        debug_host_dir = Path("/tmp/agent-uplink-debug") / session.id
        debug_host_dir.mkdir(parents=True, exist_ok=True)
        LOGGER.info(f"debug mode: claude logs → {debug_host_dir}")

    claude_mounts = build_claude_mounts(
        username,
        settings_path,
        aws_creds_path,
        session.socket_path,
        mitm_dir,
        cwd,
        debug_host_dir,
        oauth_creds_path,
    )

    sigv4_routes: dict[str, dict] = {}
    sidecars: list[tuple[str, str]] = []  # (profile, container_name)
    for profile, akia in profile_to_akia.items():
        name = _sidecar_name(session.id, profile)
        sigv4_routes[akia] = {"upstream_host": name, "upstream_port": 8080}
        sidecars.append((profile, name))

    rules_secret = resolve_rules(
        args.rules,
        args.no_default_rules,
        args.auth_mode,
        sigv4_routes,
        anthropic_oauth_token=oauth_token,
        bedrock_bearer_token=bedrock_token,
    )
    session.secrets.append(rules_secret)

    network_name: str | None = None
    if sidecars:
        network_name = f"agent-uplink-net-{session.id}"
        create_network(network_name)
        session.network = network_name

    port = get_free_port()
    start_mitm_proxy(
        session,
        mitm_dir,
        args.mitmproxy_image,
        port,
        rules_secret.bind_source,
        network_name,
    )
    if network_name is not None:
        for profile, name in sidecars:
            start_sigv4_proxy(
                session,
                args.sigv4_proxy_image,
                name,
                network_name,
                profile,
                real_aws_creds_secrets[profile].bind_source,
            )
    start_claude_container(
        session,
        args.claude_image,
        cwd,
        claude_mounts,
        args.runtime,
        args.debug,
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = parse_args()

    session = Session.create(STATE_DIR)

    handler = partial(handle_signal, session)
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    exit_code = 0
    try:
        run(session, args)
    except Exception:
        LOGGER.fatal("agent-uplink failed", exc_info=True)
        exit_code = 1
    finally:
        session.cleanup()
    raise SystemExit(exit_code)
