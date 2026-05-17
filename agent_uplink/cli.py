import argparse
import logging
import os
import signal
from functools import partial
from pathlib import Path

from .agents import AGENTS, Agent
from .aws import (
    export_aws_profile_env,
    real_aws_credentials_ini,
    sanitize_profile_for_container_name,
    write_dummy_aws_credentials,
)
from .docker_ops import (
    AGENT_IMAGE_MAX_AGE_SECONDS,
    build_agent_image,
    create_network,
    ensure_mitm_certs,
    get_container_home,
    get_image_age_seconds,
    start_agent_container,
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


def _common_arg_parser() -> argparse.ArgumentParser:
    """Parser with the flags shared by every agent subcommand. Reused as a
    parent so each subparser inherits them and `--help` shows them."""
    common = argparse.ArgumentParser(
        add_help=False,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    common.add_argument(
        "-a",
        "--aws-profiles",
        type=str,
        nargs="*",
        action="extend",
        default=[],
        help="AWS profiles to provide credentials for (one sigv4-proxy sidecar per profile)",
    )
    common.add_argument(
        "-m",
        "--mitmproxy-image",
        type=str,
        default="mitmproxy/mitmproxy",
    )
    common.add_argument(
        "--sigv4-proxy-image",
        type=str,
        default=DEFAULT_SIGV4_PROXY_IMAGE,
    )
    common.add_argument(
        "-f",
        "--force-rebuild",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Force rebuild of the agent container image",
    )
    common.add_argument(
        "-r",
        "--rules",
        type=Path,
        default=None,
        help="YAML rules file (allow-list policy + credential injection)",
    )
    common.add_argument(
        "--no-default-rules",
        action="store_true",
        help="Don't merge built-in defaults (allow GET/OPTIONS everywhere)",
    )
    common.add_argument(
        "--runtime",
        type=str,
        default="runsc",
        help="Docker runtime for the agent container (e.g. runsc, runc)",
    )
    common.add_argument(
        "-d",
        "--debug",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Run agent in debug mode (agent-specific; e.g. claude mounts ~/.claude/debug)",
    )
    return common


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent-uplink",
        description="Trust is a weakness",
    )
    sub = parser.add_subparsers(dest="agent_name", required=True, metavar="AGENT")
    common = _common_arg_parser()
    for name, agent_cls in AGENTS.items():
        agent_parser = sub.add_parser(
            name,
            parents=[common],
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            help=f"Run the {name} agent",
        )
        agent_cls.add_cli_args(agent_parser)
    return parser.parse_args()


def validate_cwd(username: str, cwd: Path) -> None:
    # The container bind-mounts cwd at the same path it has on the host;
    # only paths under /home/<username>/ exist on both sides.
    home = get_container_home(username)
    if cwd != home and home not in cwd.parents:
        raise ValueError(f"agent-uplink must be run from within {home}, got: {cwd}")


def _sidecar_name(session_id: str, profile: str) -> str:
    return f"agent-uplink-sigv4-{session_id}-{sanitize_profile_for_container_name(profile)}"


def run(session: Session, args: argparse.Namespace, agent: Agent) -> None:
    username = os.environ["USER"]
    cwd = Path.cwd()
    validate_cwd(username, cwd)

    mitm_dir = STATE_DIR / "mitm"
    mitm_dir.mkdir(parents=True, exist_ok=True)

    agent.resolve_auth(session)

    aws_profile_names = list(args.aws_profiles)
    aws_profile_names.extend(agent.discover_aws_profiles())
    # dedupe, preserve order
    aws_profile_names = list(dict.fromkeys(aws_profile_names))

    certs_generated = ensure_mitm_certs(mitm_dir, args.mitmproxy_image)
    image_age = get_image_age_seconds(agent.image)
    if (
        certs_generated
        or args.force_rebuild
        or image_age is None
        or image_age > AGENT_IMAGE_MAX_AGE_SECONDS
    ):
        build_agent_image(
            agent.image,
            agent.container_dir(),
            username,
            mitm_dir,
            args.force_rebuild,
        )

    # Real AWS creds — one mlock'd /dev/shm credentials file per profile,
    # bind-mounted into the matching sidecar. Avoids `docker run -e ...`,
    # which exposes secrets to any host user via `docker inspect`.
    real_aws_creds_secrets: dict[str, LockedSecret] = {}
    for profile in aws_profile_names:
        env = export_aws_profile_env(profile)
        safe = sanitize_profile_for_container_name(profile)
        secret = LockedSecret(f"aws-{safe}", real_aws_credentials_ini(profile, env))
        real_aws_creds_secrets[profile] = secret
        session.secrets.append(secret)

    # Fake AWS creds — written to the container's ~/.aws/credentials. The
    # dummy AKIA per profile is the key the mitm addon uses to pick the
    # right sigv4-proxy sidecar.
    aws_creds_dir, profile_to_akia = write_dummy_aws_credentials(
        aws_profile_names, session.aws_dir
    )

    agent.write_session_files(session, aws_profile_names)

    debug_host_dir: Path | None = None
    if args.debug:
        debug_host_dir = Path("/tmp/agent-uplink-debug") / session.id
        debug_host_dir.mkdir(parents=True, exist_ok=True)
        LOGGER.info(f"debug mode: agent logs → {debug_host_dir}")

    agent_mounts = agent.build_mounts(
        session,
        cwd,
        username,
        aws_creds_dir,
        mitm_dir,
        debug_host_dir,
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
        agent,
        sigv4_routes,
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

    start_agent_container(
        session,
        agent.name,
        agent.image,
        agent_mounts,
        agent.container_env(cwd, args.debug),
        args.runtime,
        agent.memory(),
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = parse_args()

    agent_cls = AGENTS[args.agent_name]
    agent = agent_cls(args)

    session = Session.create(STATE_DIR)

    handler = partial(handle_signal, session)
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    exit_code = 0
    try:
        run(session, args, agent)
    except Exception:
        LOGGER.fatal("agent-uplink failed", exc_info=True)
        exit_code = 1
    finally:
        session.cleanup()
    raise SystemExit(exit_code)
