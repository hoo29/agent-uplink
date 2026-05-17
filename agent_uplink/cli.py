from __future__ import annotations

import argparse
import logging
import os
import signal
from functools import partial
from pathlib import Path

from .agents import AGENTS, Agent
from .aws import (
    dummy_aws_credentials_ini,
    export_aws_profile_env,
    real_aws_credentials_ini,
    sanitize_profile_for_k8s_name,
)
from .bootstrap import (
    AGENT_IMAGE_MAX_AGE_SECONDS,
    REGISTRY_IMAGE_DEFAULT,
    REGISTRY_PUSH_ENDPOINT,
    build_and_push_agent_image,
    check_registries_yaml,
    ensure_mitm_certs,
    ensure_registry,
    get_image_age_seconds,
)
from .k8s import (
    apply_manifests,
    configmap_manifest,
    exec_interactive,
    hardened_container_security_context,
    namespace_manifest,
    network_policy_manifest,
    pod_manifest,
    secret_manifest,
    service_manifest,
    tmpfs_volume,
    wait_for_pod_ready,
)
from .rules import resolve as resolve_rules
from .session import Session, handle_signal

LOGGER = logging.getLogger("agent-uplink")

STATE_DIR = Path.home() / ".agent_uplink"

DEFAULT_MITM_IMAGE = "mitmproxy/mitmproxy:latest"
DEFAULT_SIGV4_PROXY_IMAGE = "public.ecr.aws/aws-observability/aws-sigv4-proxy:latest"
DEFAULT_AGENT_RUNTIME_CLASS = "kata-clh"

MITM_PORT = 8080
SIGV4_PORT = 8080

ADDON_PATH = Path(__file__).resolve().parent / "mitm_addon" / "filter.py"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _common_arg_parser() -> argparse.ArgumentParser:
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
        help="AWS profiles to provide credentials for (one sigv4-proxy pod per profile)",
    )
    common.add_argument("--mitmproxy-image", default=DEFAULT_MITM_IMAGE)
    common.add_argument("--sigv4-proxy-image", default=DEFAULT_SIGV4_PROXY_IMAGE)
    common.add_argument("--registry-image", default=REGISTRY_IMAGE_DEFAULT)
    common.add_argument(
        "--agent-runtime-class",
        default=DEFAULT_AGENT_RUNTIME_CLASS,
        help="RuntimeClass for the agent pod (use kata-qemu for microVM isolation)",
    )
    common.add_argument(
        "--mitm-runtime-class",
        default="",
        help="RuntimeClass for the mitm pod ('' = cluster default)",
    )
    common.add_argument(
        "--sigv4-runtime-class",
        default="",
        help="RuntimeClass for sigv4-proxy pods ('' = cluster default)",
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
        "-d",
        "--debug",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Run agent in debug mode (agent-specific)",
    )
    return common


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agent-uplink", description="Trust is a weakness"
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
    home = Path(f"/home/{username}")
    if cwd != home and home not in cwd.parents:
        raise ValueError(f"agent-uplink must be run from within {home}, got: {cwd}")


# ---------------------------------------------------------------------------
# Manifest assembly
# ---------------------------------------------------------------------------


def _label(component: str) -> dict[str, str]:
    return {"app": component, "managed-by": "agent-uplink"}


def _mitm_manifests(
    ns: str,
    image: str,
    runtime_class: str,
) -> list[dict]:
    labels = _label("mitm")
    # uid 1000 = the `mitmproxy` user baked into the upstream image. The certs
    # Secret is mounted at the confdir path so the existing mitmproxy-ca.pem is
    # picked up as the signing CA and CertStore.from_store() skips create_store
    # (which would otherwise mkdir into a read-only FS).
    confdir = "/mitm-confdir"
    pod = pod_manifest(
        name="mitm",
        namespace=ns,
        labels=labels,
        image=image,
        command=["mitmdump"],
        args=[
            "--listen-host=0.0.0.0",
            f"--listen-port={MITM_PORT}",
            "--set",
            f"confdir={confdir}",
            "-s",
            "/addon/filter.py",
            "--set",
            "rules_file=/rules/rules.json",
        ],
        volumes=[
            {"name": "addon", "configMap": {"name": "mitm-addon"}},
            {"name": "rules", "secret": {"secretName": "rules-json"}},
            {"name": "certs", "secret": {"secretName": "mitm-certs"}},
            tmpfs_volume("tmp", "32Mi"),
        ],
        volume_mounts=[
            {"name": "addon", "mountPath": "/addon", "readOnly": True},
            {"name": "rules", "mountPath": "/rules", "readOnly": True},
            {"name": "certs", "mountPath": confdir, "readOnly": True},
            {"name": "tmp", "mountPath": "/tmp"},
        ],
        runtime_class=runtime_class or None,
        container_security_context=hardened_container_security_context(
            uid=1000, gid=1000
        ),
        memory="512Mi",
        cpu="1",
        ports=[{"containerPort": MITM_PORT, "protocol": "TCP"}],
        image_pull_policy="IfNotPresent",
    )
    svc = service_manifest(
        "mitm",
        ns,
        selector=labels,
        port=MITM_PORT,
        labels=labels,
    )
    return [pod, svc]


def _sigv4_manifests(
    ns: str,
    profile: str,
    safe_name: str,
    image: str,
    runtime_class: str,
) -> list[dict]:
    pod_name = f"sigv4-{safe_name}"
    labels = {"app": pod_name, "tier": "sigv4", "managed-by": "agent-uplink"}
    pod = pod_manifest(
        name=pod_name,
        namespace=ns,
        labels=labels,
        image=image,
        args=["--log-failed-requests", "--log-signing-process"],
        env={
            "AWS_SHARED_CREDENTIALS_FILE": "/aws/credentials",
            "AWS_PROFILE": profile,
            "AWS_SDK_LOAD_CONFIG": "true",
        },
        volumes=[
            {
                "name": "creds",
                "secret": {
                    "secretName": f"aws-creds-{safe_name}",
                },
            },
            tmpfs_volume("tmp", "16Mi"),
        ],
        volume_mounts=[
            {"name": "creds", "mountPath": "/aws", "readOnly": True},
            {"name": "tmp", "mountPath": "/tmp"},
        ],
        runtime_class=runtime_class or None,
        container_security_context=hardened_container_security_context(
            uid=1000, gid=1000
        ),
        memory="128Mi",
        cpu="500m",
        ports=[{"containerPort": SIGV4_PORT, "protocol": "TCP"}],
    )
    svc = service_manifest(
        pod_name, ns, selector=labels, port=SIGV4_PORT, labels=labels
    )
    return [pod, svc]


def _agent_pod_manifest(
    ns: str,
    agent: Agent,
    full_image: str,
    cwd: Path,
    username: str,
    aws_creds_secret_name: str | None,
    debug_host_dir: Path | None,
    runtime_class: str,
    debug: bool,
) -> dict:
    uid, gid = os.getuid(), os.getgid()
    volumes, mounts = agent.volumes_and_mounts(
        cwd,
        username,
        aws_creds_secret_name,
        debug_host_dir,
    )
    env = {
        "HTTPS_PROXY": f"http://mitm:{MITM_PORT}",
        "HTTP_PROXY": f"http://mitm:{MITM_PORT}",
        "NO_PROXY": "127.0.0.1,localhost",
        "WORKDIR": str(cwd),
        "USERNAME": username,
    }
    env.update(agent.container_env(cwd, debug))
    return pod_manifest(
        name="agent",
        namespace=ns,
        labels=_label("agent"),
        image=full_image,
        command=agent.container_init_command(),
        env=env,
        volumes=volumes,
        volume_mounts=mounts,
        runtime_class=runtime_class or None,
        container_security_context=agent.container_security_context(uid, gid),
        pod_security_context={"fsGroup": gid},
        memory=agent.memory(),
        cpu="1",
        stdin_open=True,
        tty=True,
        image_pull_policy="Always",
    )


def _network_policies(ns: str, has_sigv4: bool) -> list[dict]:
    """Default-deny + agent-egress + mitm-ingress + sigv4-ingress."""
    policies = [
        # Deny everything by default in this namespace.
        network_policy_manifest(
            "default-deny",
            ns,
            pod_selector={},
            ingress=[],
            egress=[],
        ),
        # Agent: egress only to mitm:8080 and kube-dns.
        network_policy_manifest(
            "agent-egress",
            ns,
            pod_selector={"matchLabels": {"app": "agent"}},
            egress=[
                {
                    "to": [{"podSelector": {"matchLabels": {"app": "mitm"}}}],
                    "ports": [{"protocol": "TCP", "port": MITM_PORT}],
                },
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {
                                    "kubernetes.io/metadata.name": "kube-system"
                                }
                            },
                            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                        }
                    ],
                    "ports": [
                        {"protocol": "UDP", "port": 53},
                    ],
                },
            ],
        ),
        # mitm: accepts ingress from agent on 8080; egress unrestricted (out to
        # the internet for normal requests, in to sigv4 services for AWS).
        network_policy_manifest(
            "mitm-policy",
            ns,
            pod_selector={"matchLabels": {"app": "mitm"}},
            ingress=[
                {
                    "from": [{"podSelector": {"matchLabels": {"app": "agent"}}}],
                    "ports": [{"protocol": "TCP", "port": MITM_PORT}],
                }
            ],
            egress=[{}],
        ),
    ]
    if has_sigv4:
        # sigv4-*: accepts ingress from mitm only; egress unrestricted (to AWS).
        policies.append(
            network_policy_manifest(
                "sigv4-policy",
                ns,
                pod_selector={"matchLabels": {"tier": "sigv4"}},
                ingress=[
                    {
                        "from": [{"podSelector": {"matchLabels": {"app": "mitm"}}}],
                        "ports": [{"protocol": "TCP", "port": SIGV4_PORT}],
                    }
                ],
                egress=[{}],
            )
        )
    return policies


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def run(session: Session, args: argparse.Namespace, agent: Agent) -> int:
    username = os.environ["USER"]
    cwd = Path.cwd()
    validate_cwd(username, cwd)

    mitm_dir = STATE_DIR / "mitm"

    LOGGER.info("checking registry + k3s registries.yaml")
    check_registries_yaml()
    ensure_registry(args.registry_image)

    certs_generated = ensure_mitm_certs(mitm_dir, args.mitmproxy_image)

    aws_profile_names = list(args.aws_profiles)
    aws_profile_names.extend(agent.discover_aws_profiles())
    aws_profile_names = list(dict.fromkeys(aws_profile_names))

    agent.prepare(session, aws_profile_names)

    # Image build/push — rebuild if certs changed, --force-rebuild, missing, or
    # older than the max age threshold.
    full_image = f"{REGISTRY_PUSH_ENDPOINT}/{agent.image_repo}:latest"
    image_age = get_image_age_seconds(full_image)
    if (
        certs_generated
        or args.force_rebuild
        or image_age is None
        or image_age > AGENT_IMAGE_MAX_AGE_SECONDS
    ):
        full_image = build_and_push_agent_image(
            agent.image_repo,
            agent.container_dir(),
            username,
            mitm_dir,
            force_rebuild=args.force_rebuild,
        )

    # Per-profile sigv4 plumbing.
    profile_safe: dict[str, str] = {
        p: sanitize_profile_for_k8s_name(p) for p in aws_profile_names
    }
    real_aws_secrets: list[dict] = []
    sigv4_routes: dict[str, dict] = {}
    for profile in aws_profile_names:
        env = export_aws_profile_env(profile)
        safe = profile_safe[profile]
        real_aws_secrets.append(
            secret_manifest(
                f"aws-creds-{safe}",
                session.namespace,
                {"credentials": real_aws_credentials_ini(profile, env)},
            )
        )

    dummy_ini, profile_to_akia = dummy_aws_credentials_ini(aws_profile_names)
    agent_aws_secret_name: str | None = None
    if dummy_ini:
        agent_aws_secret_name = "agent-aws-creds"

    for profile, akia in profile_to_akia.items():
        sigv4_routes[akia] = {
            "upstream_host": f"sigv4-{profile_safe[profile]}",
            "upstream_port": SIGV4_PORT,
        }

    # Rules JSON (resolved + cred-substituted), addon ConfigMap, certs Secret.
    rules_bytes = resolve_rules(
        args.rules,
        args.no_default_rules,
        agent,
        sigv4_routes,
    )

    mitm_ca_cert = (mitm_dir / "mitmproxy-ca-cert.pem").read_bytes()
    mitm_ca_full = (mitm_dir / "mitmproxy-ca.pem").read_bytes()  # cert + key
    mitm_dhparam = (mitm_dir / "mitmproxy-dhparam.pem").read_bytes()

    debug_host_dir: Path | None = None
    if args.debug:
        debug_host_dir = Path("/tmp/agent-uplink-debug") / session.id
        debug_host_dir.mkdir(parents=True, exist_ok=True)
        LOGGER.info(f"debug mode: agent logs → {debug_host_dir}")

    # Build the full manifest set.
    manifests: list[dict] = [
        namespace_manifest(
            session.namespace,
            labels={
                "managed-by": "agent-uplink",
                "pod-security.kubernetes.io/enforce": "privileged",  # hostpaths mean can't use anything better
            },
        ),
        configmap_manifest(
            "mitm-addon",
            session.namespace,
            {"filter.py": ADDON_PATH.read_text(encoding="utf-8")},
        ),
        secret_manifest("rules-json", session.namespace, {"rules.json": rules_bytes}),
        secret_manifest(
            "mitm-certs",
            session.namespace,
            {
                "mitmproxy-ca.pem": mitm_ca_full,
                "mitmproxy-ca-cert.pem": mitm_ca_cert,
                "mitmproxy-dhparam.pem": mitm_dhparam,
            },
        ),
    ]
    manifests.extend(real_aws_secrets)
    if agent_aws_secret_name is not None:
        manifests.append(
            secret_manifest(
                agent_aws_secret_name,
                session.namespace,
                {"credentials": dummy_ini},
            )
        )
    for name, files in agent.secret_payloads().items():
        manifests.append(secret_manifest(name, session.namespace, files))

    manifests.extend(_network_policies(session.namespace, bool(aws_profile_names)))
    manifests.extend(
        _mitm_manifests(
            session.namespace,
            args.mitmproxy_image,
            args.mitm_runtime_class,
        )
    )
    for profile in aws_profile_names:
        manifests.extend(
            _sigv4_manifests(
                session.namespace,
                profile,
                profile_safe[profile],
                args.sigv4_proxy_image,
                args.sigv4_runtime_class,
            )
        )
    manifests.append(
        _agent_pod_manifest(
            session.namespace,
            agent,
            full_image,
            cwd,
            username,
            agent_aws_secret_name,
            debug_host_dir,
            args.agent_runtime_class,
            args.debug,
        )
    )

    LOGGER.info(f"applying {len(manifests)} manifests to ns/{session.namespace}")
    apply_manifests(manifests)

    LOGGER.info("waiting for support pods")
    wait_for_pod_ready(session.namespace, "mitm", timeout=90)
    for profile in aws_profile_names:
        wait_for_pod_ready(
            session.namespace,
            f"sigv4-{profile_safe[profile]}",
            timeout=90,
        )
    LOGGER.info("waiting for agent pod (kata cold-start)")
    wait_for_pod_ready(session.namespace, "agent", timeout=180)

    LOGGER.info("attaching to agent")
    return exec_interactive(
        session.namespace,
        "agent",
        container="main",
        command=agent.container_command(username, args.debug),
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
        exit_code = run(session, args, agent)
    except Exception:
        LOGGER.fatal("agent-uplink failed", exc_info=True)
        exit_code = 1
    finally:
        session.cleanup()
    raise SystemExit(exit_code)
