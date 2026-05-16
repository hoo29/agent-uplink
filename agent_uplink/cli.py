import argparse
import logging
import os
import signal
from functools import partial
from pathlib import Path

from .config import (
    AUTH_MODE_ENV,
    get_bedrock_aws_profile_name,
    load_claude_config,
    write_aws_credentials,
    write_claude_settings,
)
from .docker_ops import (
    build_claude_image,
    build_claude_mounts,
    check_claude_image_exists,
    ensure_mitm_certs,
    get_container_home,
    start_claude_container,
    start_mitm_proxy,
)
from .process import get_free_port
from .rules import resolve as resolve_rules
from .session import Session, handle_signal

LOGGER = logging.getLogger("agent-uplink")

STATE_DIR = Path.home() / ".agent_uplink"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Trust is a weakness",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-a", "--aws-profiles",
        type=str, nargs="*", action="extend", default=[],
        help="AWS profiles to provide credentials for",
    )
    parser.add_argument(
        "-m", "--mitmproxy-image", type=str, default="mitmproxy/mitmproxy",
    )
    parser.add_argument(
        "-c", "--claude-image", type=str, default="agent-uplink-claude",
    )
    parser.add_argument(
        "-f", "--force-rebuild",
        action=argparse.BooleanOptionalAction, default=False,
        help="Force rebuild of the Claude container image",
    )
    parser.add_argument(
        "-r", "--rules", type=Path, default=None,
        help="YAML rules file (allow-list policy + credential injection)",
    )
    parser.add_argument(
        "--no-default-rules", action="store_true",
        help="Don't merge built-in defaults (allow GET/OPTIONS everywhere)",
    )
    parser.add_argument(
        "--runtime", type=str, default="runsc",
        help="Docker runtime for the Claude container (e.g. runsc, runc)",
    )
    parser.add_argument(
        "-d", "--debug",
        action=argparse.BooleanOptionalAction, default=False,
        help="Run claude with -d and mount ~/.claude/debug from the container "
             "to /tmp/agent-uplink-debug/<session-id> on the host",
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    for mode in AUTH_MODE_ENV:
        mode_group.add_argument(
            f"--{mode}", dest="auth_mode", action="store_const", const=mode,
            help=f"Configure container for {mode} auth "
                 f"(injects placeholder {', '.join(AUTH_MODE_ENV[mode])})",
        )
    return parser.parse_args()


def validate_cwd(username: str, cwd: Path) -> None:
    # The container bind-mounts cwd at the same path it has on the host;
    # only paths under /home/<username>/ exist on both sides.
    home = get_container_home(username)
    if cwd != home and home not in cwd.parents:
        raise ValueError(
            f"agent-uplink must be run from within {home}, got: {cwd}")


def run(session: Session, args: argparse.Namespace) -> None:
    username = os.environ["USER"]
    cwd = Path.cwd()
    validate_cwd(username, cwd)

    mitm_dir = STATE_DIR / "mitm"
    mitm_dir.mkdir(parents=True, exist_ok=True)

    claude_config = load_claude_config()
    aws_profile_names = list(args.aws_profiles)
    bedrock_profile = get_bedrock_aws_profile_name(claude_config)
    if bedrock_profile is not None:
        aws_profile_names.append(bedrock_profile)

    certs_generated = ensure_mitm_certs(mitm_dir, args.mitmproxy_image)
    if (
        certs_generated
        or args.force_rebuild
        or not check_claude_image_exists(args.claude_image)
    ):
        build_claude_image(
            args.claude_image, username, mitm_dir, args.force_rebuild
        )

    aws_creds_path = write_aws_credentials(aws_profile_names, session.aws_dir)
    settings_path = write_claude_settings(
        claude_config, session.session_dir, args.auth_mode
    )
    debug_host_dir: Path | None = None
    if args.debug:
        debug_host_dir = Path("/tmp/agent-uplink-debug") / session.id
        debug_host_dir.mkdir(parents=True, exist_ok=True)
        LOGGER.info(f"debug mode: claude logs → {debug_host_dir}")

    claude_mounts = build_claude_mounts(
        username, settings_path, aws_creds_path, session.socket_path,
        mitm_dir, cwd, debug_host_dir,
    )

    rules_secret = resolve_rules(args.rules, args.no_default_rules, args.auth_mode)
    session.secrets.append(rules_secret)

    port = get_free_port()
    start_mitm_proxy(
        session, mitm_dir, args.mitmproxy_image, port, rules_secret.bind_source
    )
    start_claude_container(
        session, args.claude_image, cwd, claude_mounts, args.runtime, args.debug,
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
