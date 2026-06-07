from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import pwd
import signal
from functools import partial
from pathlib import Path

from .agents import AGENTS, Agent
from .agents.base import PodBuildContext, PodContribution
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
from .git import build_overlay as build_git_overlay
from .k8s import (
    Resources,
    Stdio,
    apply_manifests,
    configmap_manifest,
    configmap_volume,
    container_spec,
    emptydir_volume,
    exec_interactive,
    hardened_container_security_context,
    hostpath_volume,
    namespace_manifest,
    network_policy_manifest,
    pod_manifest,
    pod_spec,
    secret_manifest,
    secret_volume,
    service_manifest,
    set_kube_context,
    wait_for_pod_ready,
)
from .kube import KubePlan, resolve as resolve_kube
from .rules import resolve as resolve_rules
from .session import Session, handle_signal

LOGGER = logging.getLogger("agent-uplink")

STATE_DIR = Path.home() / ".agent_uplink"

DEFAULT_MITM_IMAGE = "mitmproxy/mitmproxy:12"
DEFAULT_SIGV4_PROXY_IMAGE = "public.ecr.aws/aws-observability/aws-sigv4-proxy:latest"
DEFAULT_AGENT_RUNTIME_CLASS = "kata-clh"
DEFAULT_DEPLOY_CONTEXT = "local-k8s-admin"

PROXY_PORT = 8080  # mitm and aws-sigv4-proxy both listen on this port

AGENT_CONTAINER_NAME = "main"

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
    common.add_argument("--sigv4-proxy-image",
                        default=DEFAULT_SIGV4_PROXY_IMAGE)
    common.add_argument("--registry-image", default=REGISTRY_IMAGE_DEFAULT)
    common.add_argument(
        "--deploy-context",
        default=DEFAULT_DEPLOY_CONTEXT,
        metavar="CONTEXT",
        help="kubeconfig context agent-uplink deploys the session into (registry, "
        "mitm, sigv4, agent pods). Distinct from --kube-context, which exposes "
        "clusters to the agent. Pass '' to use the kubeconfig's current-context.",
    )
    common.add_argument(
        "--agent-runtime-class",
        default=DEFAULT_AGENT_RUNTIME_CLASS,
        help="RuntimeClass for the agent pod (default kata-clh; kata-qemu / kata-fc also work)",
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
        "--allow-exec",
        action="store_true",
        help="Permit {{exec:...}} placeholders in rules files to run host shell "
        "commands at startup (off by default)",
    )
    common.add_argument(
        "--ssh-cidr",
        type=str,
        nargs="*",
        action="extend",
        default=[],
        metavar="CIDR",
        help="CIDR(s) the agent may reach over SSH (TCP 22 only). Repeatable; "
        "a bare IP is treated as /32. Egress to anything else stays denied. "
        "SSH bypasses mitm, so this ipBlock set is the only control on it.",
    )
    common.add_argument(
        "--ssh-key-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Host directory of SSH private keys to mount read-only at the "
        "agent's ~/.ssh (the directory need not be named .ssh)",
    )
    common.add_argument(
        "--git-https-rewrite",
        type=str,
        nargs="*",
        action="extend",
        default=[],
        metavar="HOST",
        help="Extra git host(s) whose SSH URLs are rewritten to HTTPS so they "
        "route through mitm, in addition to the baked-in github.com, gitlab.com, "
        "bitbucket.org. Auth still requires a matching --rules entry.",
    )
    common.add_argument(
        "--no-git-identity",
        action="store_true",
        help="Don't surface the host's git identity (user.name/user.email) into "
        "the agent; commits are then unattributed unless set in-repo",
    )
    common.add_argument(
        "--add-dir",
        type=Path,
        nargs="*",
        action="extend",
        default=[],
        metavar="DIR",
        help="Additional host folder(s) to mount read-write into the agent at their "
        "identical path, for cross-repo work. The working directory is always mounted; "
        "these add to it. Each must be under /home/<user>/ and must not overlap "
        "(be nested within) the working directory or another --add-dir folder.",
    )
    common.add_argument(
        "--kube-context",
        type=str,
        nargs="*",
        action="extend",
        default=[],
        metavar="CONTEXT",
        help="kubeconfig context(s) to expose to the agent. Supported auth: static "
        "bearer token, client certificate. exec/auth-provider contexts are refused. "
        "Traffic to each API server flows through mitm under the allow-list; the pod "
        "kubeconfig trusts the mitm CA and carries no real credentials.",
    )
    common.add_argument(
        "--kubeconfig",
        type=Path,
        default=None,
        metavar="PATH",
        help="kubeconfig file to read contexts from (default: $KUBECONFIG then "
        "~/.kube/config)",
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
    sub = parser.add_subparsers(
        dest="agent_name", required=True, metavar="AGENT")
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


def _under_home(username: str, path: Path) -> bool:
    home = Path(f"/home/{username}")
    return path == home or home in path.parents


def validate_cwd(username: str, cwd: Path) -> None:
    if not _under_home(username, cwd):
        raise ValueError(
            f"agent-uplink must be run from within /home/{username}, got: {cwd}")


def validate_extra_dirs(
    username: str, cwd: Path, add_dir: list[Path]
) -> list[Path]:
    """Resolve, validate, and de-duplicate --add-dir folders.

    Each must be an existing directory under /home/<user>/ and must not overlap
    (be nested within, contain, or equal) the cwd or another extra dir. Returns
    the resolved, de-duplicated list."""
    resolved: list[Path] = []
    for raw in add_dir:
        d = raw.expanduser().resolve()
        if not d.is_dir():
            raise ValueError(f"--add-dir {d} does not exist or is not a directory")
        if not _under_home(username, d):
            raise ValueError(f"--add-dir {d} must be under /home/{username}")
        if d not in resolved:
            resolved.append(d)

    all_dirs = [cwd, *resolved]
    for i, a in enumerate(all_dirs):
        for b in all_dirs[i + 1:]:
            if a == b:
                raise ValueError(
                    f"--add-dir {b} is the working directory, already mounted")
            if a in b.parents or b in a.parents:
                raise ValueError(
                    f"--add-dir paths overlap: {a} and {b} are nested; "
                    "mount non-overlapping folders only")
    return resolved


def validate_ssh_args(
    ssh_cidr: list[str], ssh_key_dir: Path | None
) -> tuple[list[str], Path | None]:
    """Validate + normalise the SSH egress options. Returns (cidrs, key_dir).

    CIDRs are normalised to their network address (a bare IP becomes /32) so the
    ipBlock the NetworkPolicy emits is always canonical. A missing key dir or a
    malformed CIDR aborts startup before any pod is launched."""
    cidrs: list[str] = []
    for raw in ssh_cidr:
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as exc:
            raise ValueError(f"--ssh-cidr {raw!r} is not a valid CIDR: {exc}") from exc
        cidrs.append(str(net))

    key_dir: Path | None = None
    if ssh_key_dir is not None:
        key_dir = ssh_key_dir.expanduser().resolve()
        if not key_dir.is_dir():
            raise ValueError(
                f"--ssh-key-dir {key_dir} does not exist or is not a directory"
            )

    if key_dir is not None and not cidrs:
        LOGGER.warning(
            "--ssh-key-dir set without --ssh-cidr: SSH egress stays denied, so "
            "the agent has keys but can reach nothing on TCP 22"
        )
    if cidrs and key_dir is None:
        LOGGER.warning(
            "--ssh-cidr set without --ssh-key-dir: TCP 22 egress to %s is open "
            "but no SSH keys are mounted",
            ", ".join(cidrs),
        )
    return cidrs, key_dir


# ---------------------------------------------------------------------------
# Manifest assembly
# ---------------------------------------------------------------------------


def _label(component: str) -> dict[str, str]:
    return {"app": component, "managed-by": "agent-uplink"}


def _mitm_manifests(
    ns: str,
    image: str,
    runtime_class: str,
    *,
    kube_client_certs_secret: str | None = None,
    kube_upstream_ca_secret: str | None = None,
) -> list[dict]:
    labels = _label("mitm")
    # uid 1000 = the `mitmproxy` user baked into the upstream image. The certs
    # Secret is mounted at the confdir path so mitmproxy picks up the existing CA
    # as its signing CA instead of trying to generate one (which would fail
    # writing into the read-only root filesystem).
    confdir = "/mitm-confdir"

    mitm_args = [
        "--listen-host=0.0.0.0",
        f"--listen-port={PROXY_PORT}",
        "--set",
        f"confdir={confdir}",
        "-s",
        "/addon/filter.py",
        "--set",
        "rules_file=/rules/rules.json",
    ]
    volume_mounts = [
        {"name": "addon", "mountPath": "/addon", "readOnly": True},
        {"name": "rules", "mountPath": "/rules", "readOnly": True},
        {"name": "certs", "mountPath": confdir, "readOnly": True},
        {"name": "tmp", "mountPath": "/tmp"},
    ]
    volumes = [
        configmap_volume("addon", "mitm-addon"),
        secret_volume("rules", "rules-json"),
        secret_volume("certs", "mitm-certs"),
        emptydir_volume("tmp", "32Mi"),
    ]

    # When k8s contexts are configured, mount the client certs directory (one
    # <host>.pem per cluster) and the combined upstream CA bundle so mitmproxy
    # presents the right client cert and trusts each cluster's serving CA.
    if kube_client_certs_secret:
        volume_mounts.append(
            {"name": "kube-client-certs", "mountPath": "/kube-client-certs", "readOnly": True}
        )
        volumes.append(secret_volume("kube-client-certs", kube_client_certs_secret))
        mitm_args.extend(["--set", "client_certs=/kube-client-certs"])
    if kube_upstream_ca_secret:
        volume_mounts.append(
            {"name": "kube-upstream-ca", "mountPath": "/kube-upstream-ca", "readOnly": True}
        )
        volumes.append(secret_volume("kube-upstream-ca", kube_upstream_ca_secret))
        mitm_args.extend(["--set", "ssl_verify_upstream_trusted_ca=/kube-upstream-ca/bundle.pem"])

    container = container_spec(
        name="mitm",
        image=image,
        command=["mitmdump"],
        args=mitm_args,
        volume_mounts=volume_mounts,
        security_context=hardened_container_security_context(uid=1000, gid=1000),
        resources=Resources(
            memory="512Mi", cpu="500m", memory_request="96Mi", cpu_request="50m"
        ),
        ports=[{"containerPort": PROXY_PORT, "protocol": "TCP"}],
    )
    spec = pod_spec(
        container=container,
        volumes=volumes,
        runtime_class=runtime_class or None,
    )
    pod = pod_manifest("mitm", ns, labels=labels, spec=spec)
    svc = service_manifest("mitm", ns, selector=labels, port=PROXY_PORT, labels=labels)
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
    container = container_spec(
        image=image,
        args=["--log-failed-requests", "--log-signing-process"],
        env={
            "AWS_SHARED_CREDENTIALS_FILE": "/aws/credentials",
            "AWS_PROFILE": profile,
            "AWS_SDK_LOAD_CONFIG": "true",
        },
        volume_mounts=[
            {"name": "creds", "mountPath": "/aws", "readOnly": True},
            {"name": "tmp", "mountPath": "/tmp"},
        ],
        security_context=hardened_container_security_context(uid=1000, gid=1000),
        resources=Resources(
            memory="128Mi", cpu="100m", memory_request="48Mi", cpu_request="25m"
        ),
        ports=[{"containerPort": PROXY_PORT, "protocol": "TCP"}],
    )
    spec = pod_spec(
        container=container,
        volumes=[
            secret_volume("creds", f"aws-creds-{safe_name}"),
            emptydir_volume("tmp", "16Mi"),
        ],
        runtime_class=runtime_class or None,
    )
    pod = pod_manifest(pod_name, ns, labels=labels, spec=spec)
    svc = service_manifest(pod_name, ns, selector=labels, port=PROXY_PORT, labels=labels)
    return [pod, svc]


def _agent_env(cwd: Path, username: str) -> dict[str, str]:
    """Universal env for the agent pod: force every client through mitm. Built
    from a single proxy address so the upper/lower-case pairs can't drift."""
    proxy = f"http://mitm:{PROXY_PORT}"
    no_proxy = "localhost,127.0.0.1,::1,.local"
    env: dict[str, str] = {
        "WORKDIR": str(cwd),
        "USERNAME": username,
        # mitm injects git auth, so a credential prompt is never useful; fail
        # fast on unconfigured/denied auth instead of hanging the agent.
        "GIT_TERMINAL_PROMPT": "0",
        # dockerd reads the upper-case DOCKER_* forms.
        "DOCKER_HTTP_PROXY": proxy,
        "DOCKER_HTTPS_PROXY": proxy,
        # gcloud SDK uses its own proxy vars.
        "CLOUDSDK_PROXY_TYPE": "http",
        "CLOUDSDK_PROXY_ADDRESS": "mitm",
        "CLOUDSDK_PROXY_PORT": str(PROXY_PORT),
    }
    for base in ("HTTP_PROXY", "HTTPS_PROXY"):
        env[base] = env[base.lower()] = proxy
    env["NO_PROXY"] = env["no_proxy"] = no_proxy
    return env


def _agent_pod_manifest(
    ns: str,
    full_image: str,
    contribution: PodContribution,
    cwd: Path,
    username: str,
    gid: int,
    runtime_class: str,
    ssh_key_dir: Path | None = None,
    kube_config_secret: str | None = None,
    git_config_secret: str | None = None,
    extra_dirs: list[Path] | None = None,
) -> dict:
    env = _agent_env(cwd, username)
    env.update(contribution.env)
    volumes = list(contribution.volumes)
    mounts = list(contribution.mounts)
    # SSH private keys: the host dir is mounted read-only at the agent user's
    # ~/.ssh so `ssh` discovers them. Read-only keeps the untrusted agent from
    # tampering with the host keys (cost: known_hosts can't be persisted back).
    # The container user shares the host UID (Dockerfile USER_UID), so 0600 host
    # keys are readable. Reachability is gated by the --ssh-cidr egress rule.
    if ssh_key_dir is not None:
        volumes.append(
            hostpath_volume("ssh-keys", str(ssh_key_dir), hp_type="Directory")
        )
        mounts.append(
            {
                "name": "ssh-keys",
                "mountPath": f"/home/{username}/.ssh",
                "readOnly": True,
            }
        )
    # Sanitized kubeconfig: trusts mitm CA, carries placeholder creds. Mounted
    # outside the home dir so readOnlyRootFilesystem doesn't block the mount.
    # kubectl's cache writes (~/.kube/cache) are non-fatal when they fail.
    if kube_config_secret is not None:
        volumes.append(secret_volume("kube-config", kube_config_secret))
        mounts.append(
            {
                "name": "kube-config",
                "mountPath": "/etc/agent-uplink/kube",
                "readOnly": True,
            }
        )
        env["KUBECONFIG"] = "/etc/agent-uplink/kube/config"
    # git overlay (host identity + --git-https-rewrite hosts): pulled in by the
    # include.path in the baked /etc/gitconfig. Mounted read-only at that path;
    # carries no secrets, so it's safe in the agent pod. The agent's ~/.gitconfig
    # is untouched and stays writable.
    if git_config_secret is not None:
        volumes.append(secret_volume("git-config", git_config_secret))
        mounts.append(
            {
                "name": "git-config",
                "mountPath": "/etc/gitconfig.d/agent-uplink.inc",
                "subPath": "agent-uplink.inc",
                "readOnly": True,
            }
        )
    for i, d in enumerate(extra_dirs or []):
        name = f"add-dir-{i}"
        volumes.append(hostpath_volume(name, str(d), hp_type="Directory"))
        mounts.append({"name": name, "mountPath": str(d)})
    container = container_spec(
        name=AGENT_CONTAINER_NAME,
        image=full_image,
        command=contribution.init_command,
        env=env,
        volume_mounts=mounts,
        security_context=contribution.security_context,
        # Reserve modestly so the pod schedules on small nodes; the limit is the
        # real ceiling the in-pod dockerd needs (tmpfs /var/lib/docker counts
        # against memory).
        resources=Resources(
            memory=contribution.memory, cpu="1", memory_request="1Gi", cpu_request="250m"
        ),
        stdio=Stdio(stdin=True, tty=True),
        image_pull_policy="Always",
    )
    spec = pod_spec(
        container=container,
        volumes=volumes,
        runtime_class=runtime_class or None,
        pod_security_context={"fsGroup": gid},
    )
    return pod_manifest("agent", ns, labels=_label("agent"), spec=spec)


def _network_policies(
    ns: str, has_sigv4: bool, ssh_cidrs: list[str] | None = None
) -> list[dict]:
    """Default-deny + agent-egress + mitm-ingress + sigv4-ingress."""
    # Agent egress: mitm:8080 and kube-dns by default; optionally TCP 22 to an
    # explicit CIDR set.
    agent_egress: list[dict] = [
        {
            "to": [{"podSelector": {"matchLabels": {"app": "mitm"}}}],
            "ports": [{"protocol": "TCP", "port": PROXY_PORT}],
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
                {"protocol": "TCP", "port": 53},
            ],
        },
    ]
    # SSH egress: TCP 22 only, to the given CIDRs only. This bypasses mitm
    # (SSH is not HTTP — no allow-list, no credential injection), so the ipBlock
    # set is the sole control; kube-dns above still resolves the target name.
    if ssh_cidrs:
        agent_egress.append(
            {
                "to": [{"ipBlock": {"cidr": cidr}} for cidr in ssh_cidrs],
                "ports": [{"protocol": "TCP", "port": 22}],
            }
        )
    policies = [
        # Deny everything by default in this namespace.
        network_policy_manifest(
            "default-deny",
            ns,
            pod_selector={},
            ingress=[],
            egress=[],
        ),
        # Agent: egress only to mitm:8080, kube-dns, and any --ssh-cidr ranges.
        network_policy_manifest(
            "agent-egress",
            ns,
            pod_selector={"matchLabels": {"app": "agent"}},
            egress=agent_egress,
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
                    "ports": [{"protocol": "TCP", "port": PROXY_PORT}],
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
                        "ports": [{"protocol": "TCP", "port": PROXY_PORT}],
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
    username = os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name
    cwd = Path.cwd()
    validate_cwd(username, cwd)
    ssh_cidrs, ssh_key_dir = validate_ssh_args(args.ssh_cidr, args.ssh_key_dir)
    extra_dirs = validate_extra_dirs(username, cwd, args.add_dir)

    mitm_dir = STATE_DIR / "mitm"

    LOGGER.info("checking registry + k3s registries.yaml")
    check_registries_yaml()
    ensure_registry(args.registry_image)

    certs_generated = ensure_mitm_certs(mitm_dir, args.mitmproxy_image)

    aws_profile_names = list(args.aws_profiles)
    aws_profile_names.extend(agent.discover_aws_profiles())
    aws_profile_names = list(dict.fromkeys(aws_profile_names))

    prepared = agent.prepare(session, aws_profile_names)

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

    # Per-profile sigv4 plumbing. Guard against two profiles colliding to the
    # same k8s-safe name (which would emit duplicate Pod/Service manifests).
    profile_safe: dict[str, str] = {
        p: sanitize_profile_for_k8s_name(p) for p in aws_profile_names
    }
    seen_safe: dict[str, str] = {}
    for profile, safe in profile_safe.items():
        if safe in seen_safe:
            raise ValueError(
                f"AWS profiles {seen_safe[safe]!r} and {profile!r} both map to the "
                f"k8s-safe name {safe!r}; rename one to disambiguate"
            )
        seen_safe[safe] = profile

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
            "upstream_port": PROXY_PORT,
        }

    mitm_ca_cert = (mitm_dir / "mitmproxy-ca-cert.pem").read_bytes()
    mitm_ca_full = (mitm_dir / "mitmproxy-ca.pem").read_bytes()  # cert + key
    mitm_dhparam = (mitm_dir / "mitmproxy-dhparam.pem").read_bytes()

    # Kubernetes context resolution. Done before rule assembly so the synthetic
    # kube rules (bearer injection / host allow) can be layered in.
    kube_plan: KubePlan | None = None
    if args.kube_context:
        LOGGER.info(f"resolving kube contexts: {args.kube_context}")
        kube_plan = resolve_kube(args.kubeconfig, args.kube_context, mitm_ca_cert)

    # Rules JSON (resolved + cred-substituted), addon ConfigMap, certs Secret.
    rules_bytes = resolve_rules(
        args.rules,
        args.no_default_rules,
        agent,
        prepared.auth_rules,
        allow_exec=args.allow_exec,
        aws_sigv4_routes=sigv4_routes,
        kube_rules=kube_plan.rules if kube_plan else None,
    )

    debug_host_dir: Path | None = None
    if args.debug:
        debug_host_dir = Path("/tmp/agent-uplink-debug") / session.id
        debug_host_dir.mkdir(parents=True, exist_ok=True)
        LOGGER.info(f"debug mode: agent logs → {debug_host_dir}")

    uid, gid = os.getuid(), os.getgid()
    contribution = agent.pod_contribution(
        PodBuildContext(
            cwd=cwd,
            username=username,
            uid=uid,
            gid=gid,
            aws_creds_secret_name=agent_aws_secret_name,
            debug_host_dir=debug_host_dir,
            debug=args.debug,
        )
    )

    # Build the full manifest set.
    manifests: list[dict] = [
        namespace_manifest(
            session.namespace,
            labels={
                "managed-by": "agent-uplink",
                # hostpaths mean can't use anything better
                "pod-security.kubernetes.io/enforce": "privileged",
            },
        ),
        configmap_manifest(
            "mitm-addon",
            session.namespace,
            {"filter.py": ADDON_PATH.read_text(encoding="utf-8")},
        ),
        secret_manifest("rules-json", session.namespace,
                        {"rules.json": rules_bytes}),
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
    for name, files in prepared.secret_payloads.items():
        manifests.append(secret_manifest(name, session.namespace, files))

    # Kube secrets: sanitized kubeconfig for the agent pod, client certs and
    # upstream CA bundle for the mitm pod. Only created when --kube-context is set.
    kube_config_secret: str | None = None
    kube_client_certs_secret: str | None = None
    kube_upstream_ca_secret: str | None = None
    if kube_plan is not None:
        kube_config_secret = "kube-config"
        manifests.append(
            secret_manifest(kube_config_secret, session.namespace,
                            {"config": kube_plan.pod_kubeconfig})
        )
        if kube_plan.client_certs:
            kube_client_certs_secret = "kube-client-certs"
            manifests.append(
                secret_manifest(kube_client_certs_secret, session.namespace,
                                kube_plan.client_certs)
            )
        if kube_plan.upstream_ca_bundle:
            kube_upstream_ca_secret = "kube-upstream-ca"
            manifests.append(
                secret_manifest(kube_upstream_ca_secret, session.namespace,
                                {"bundle.pem": kube_plan.upstream_ca_bundle})
            )

    # git overlay: host identity + extra SSH->HTTPS rewrites, included by the
    # baked /etc/gitconfig. Only created when it would be non-empty.
    git_config_secret: str | None = None
    git_overlay = build_git_overlay(
        args.git_https_rewrite, include_identity=not args.no_git_identity
    )
    if git_overlay is not None:
        git_config_secret = "git-config"
        manifests.append(
            secret_manifest(git_config_secret, session.namespace,
                            {"agent-uplink.inc": git_overlay})
        )

    manifests.extend(_network_policies(
        session.namespace, bool(aws_profile_names), ssh_cidrs))
    manifests.extend(
        _mitm_manifests(
            session.namespace,
            args.mitmproxy_image,
            args.mitm_runtime_class,
            kube_client_certs_secret=kube_client_certs_secret,
            kube_upstream_ca_secret=kube_upstream_ca_secret,
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
            full_image,
            contribution,
            cwd,
            username,
            gid,
            args.agent_runtime_class,
            ssh_key_dir,
            kube_config_secret,
            git_config_secret,
            extra_dirs=extra_dirs,
        )
    )

    LOGGER.info(
        f"applying {len(manifests)} manifests to ns/{session.namespace}")
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
    if contribution.command is None:
        raise RuntimeError(
            f"agent {args.agent_name!r} produced no interactive command"
        )
    return exec_interactive(
        session.namespace,
        "agent",
        container=AGENT_CONTAINER_NAME,
        command=contribution.command,
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = parse_args()

    # Target every deploy-side kubectl call (incl. signal-handler cleanup) at the
    # chosen context before anything can shell out to kubectl.
    set_kube_context(args.deploy_context)

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
