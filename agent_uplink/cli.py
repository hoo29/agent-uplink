from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import pwd
import signal
import sys
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from . import config
from .agents import AGENTS, Agent
from .agents.base import PodBuildContext, PodContribution, PreparedAgent
from .aws import (
    dummy_aws_credentials_ini,
    export_aws_profile_env,
    real_aws_credentials,
    sigv4_credentials_json,
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
    tmpfs_volume,
    wait_for_pod_ready,
)
from .kube import KubePlan, resolve as resolve_kube
from .rules import resolve as resolve_rules
from .session import Session, handle_signal
from . import reaper
from . import sshagent

LOGGER = logging.getLogger("agent-uplink")

STATE_DIR = Path.home() / ".agent_uplink"

DEFAULT_MITM_IMAGE = "mitmproxy/mitmproxy:12"
DEFAULT_AGENT_RUNTIME_CLASS = "kata-clh"
DEFAULT_DEPLOY_CONTEXT = "local-k8s-admin"

PROXY_PORT = 8080  # mitm listens here
SSH_AGENT_PORT = 8765  # ssh-agent holder's socat TCP bridge
SSH_AUTH_SOCK_PATH = "/ssh-agent/agent.sock"  # bridged agent socket in the agent pod

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
        help="AWS profiles to provide credentials for (re-signed by mitm per request)",
    )
    common.add_argument("--mitmproxy-image", default=DEFAULT_MITM_IMAGE)
    common.add_argument("--registry-image", default=REGISTRY_IMAGE_DEFAULT)
    common.add_argument(
        "--deploy-context",
        default=DEFAULT_DEPLOY_CONTEXT,
        metavar="CONTEXT",
        help="kubeconfig context agent-uplink deploys the session into (registry, "
        "mitm, agent pods). Distinct from --kube-context, which exposes "
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
        nargs="*",
        action="extend",
        default=[],
        metavar="FILE",
        help="YAML rules file(s) (allow-list policy + credential injection). "
        "Repeatable; files are concatenated in order, earlier files winning "
        "first-match. Inline rules can also be set in .agent-uplink.yaml.",
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
        help="Host directory of SSH private keys. The private keys are loaded "
        "into an ssh-agent in a separate holder pod and never enter the agent "
        "pod; the agent gets only the public keys + any `config` (in "
        "~/.ssh) and signs via the holder. Pin a key to a host with "
        "IdentityFile ~/.ssh/<name>.pub + IdentitiesOnly yes. Keys must be "
        "passphraseless (the holder loads them non-interactively).",
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
        "--mount-rw",
        type=Path,
        nargs="*",
        action="extend",
        default=[],
        metavar="PATH",
        help="Host file(s)/dir(s) to mount read-write into the agent at their "
        "identical path, e.g. extra repos for cross-repo work. The working "
        "directory is always mounted; these add to it. Each must be under "
        "/home/<user>/. Writable directories must not overlap (be nested within) "
        "the working directory or each other.",
    )
    common.add_argument(
        "--mount-ro",
        type=Path,
        nargs="*",
        action="extend",
        default=[],
        metavar="PATH",
        help="Host file(s)/dir(s) to mount read-only into the agent at their "
        "identical path, e.g. ~/.ansible.cfg or a shared config dir. Each must be "
        "under /home/<user>/.",
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
    common.add_argument(
        "--mitm-debug",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable verbose mitmproxy debug logging (flow details + debug level). "
        "WARNING: may log plaintext credentials (headers, bodies, re-signed AWS "
        "requests) to the mitm pod's stdout. Off by default.",
    )
    return common


def build_parser() -> tuple[argparse.ArgumentParser, dict[str, argparse.ArgumentParser]]:
    """The top-level parser plus the per-agent subparsers (by name), so config
    defaults can be applied to the right subparser before the real parse."""
    parser = argparse.ArgumentParser(
        prog="agent-uplink", description="Trust is a weakness"
    )
    sub = parser.add_subparsers(
        dest="agent_name", required=True, metavar="AGENT")
    common = _common_arg_parser()
    agent_parsers: dict[str, argparse.ArgumentParser] = {}
    for name, agent_cls in AGENTS.items():
        agent_parser = sub.add_parser(
            name,
            parents=[common],
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            help=f"Run the {name} agent",
        )
        agent_cls.add_cli_args(agent_parser)
        agent_parsers[name] = agent_parser
    _add_management_commands(sub)
    return parser, agent_parsers


def _peek_subcommand(
    argv: list[str], names: dict[str, argparse.ArgumentParser]
) -> str | None:
    """The agent subcommand on the command line, if any, found before the real
    parse so config can be layered onto its subparser. The subcommand is the
    first positional; anything before it would be a top-level flag (only -h)."""
    for token in argv:
        if token in names:
            return token
        if not token.startswith("-"):
            return None
    return None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser, agent_parsers = build_parser()
    # Config applies only to an agent run (not list/clean): fold every
    # .agent-uplink.yaml from cwd up to ~ into that subparser's defaults so the
    # subsequent parse treats them as defaults and CLI args still win.
    name = _peek_subcommand(argv, agent_parsers)
    if name is not None:
        try:
            defaults = config.load_config(
                agent_parsers[name], Path.cwd(), Path.home()
            )
        except config.ConfigError as exc:
            parser.error(str(exc))
        if defaults:
            agent_parsers[name].set_defaults(**defaults)
    return parser.parse_args(argv)


def _add_deploy_context_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--deploy-context",
        default=DEFAULT_DEPLOY_CONTEXT,
        metavar="CONTEXT",
        help="kubeconfig context to operate on (pass '' for current-context)",
    )


def _add_management_commands(sub) -> None:
    """`list` / `clean` — manage leftover session namespaces (orphan reaper).
    Separate from the agent subcommands: no image build, no pods, no run."""
    list_p = sub.add_parser(
        "list", help="List active agent-uplink session namespaces"
    )
    _add_deploy_context_arg(list_p)

    clean_p = sub.add_parser(
        "clean",
        help="Delete agent-uplink session namespaces left by killed/crashed runs",
    )
    clean_p.add_argument(
        "ids",
        nargs="*",
        metavar="SESSION",
        help="Session id(s) or namespace(s) to delete. Omit when using "
        "--all or --older-than.",
    )
    clean_p.add_argument(
        "--all", action="store_true", help="Delete every session namespace"
    )
    clean_p.add_argument(
        "--older-than",
        metavar="DURATION",
        default=None,
        help="Delete sessions older than DURATION (e.g. 30m, 2h, 1d)",
    )
    clean_p.add_argument(
        "-y", "--yes", action="store_true", help="Skip the confirmation prompt"
    )
    clean_p.add_argument(
        "--wait",
        action="store_true",
        help="Block until each namespace is fully deleted",
    )
    _add_deploy_context_arg(clean_p)


def _under_home(username: str, path: Path) -> bool:
    home = Path(f"/home/{username}")
    return path == home or home in path.parents


def validate_cwd(username: str, cwd: Path) -> None:
    if not _under_home(username, cwd):
        raise ValueError(
            f"agent-uplink must be run from within /home/{username}, got: {cwd}")


@dataclass
class HostMount:
    """A host path mounted into the agent at its identical path, read-only or
    read-write. Built from --mount-ro / --mount-rw."""

    host_path: Path
    read_only: bool


def validate_mounts(
    username: str, cwd: Path, mount_rw: list[Path], mount_ro: list[Path]
) -> list[HostMount]:
    """Resolve, validate, and de-duplicate --mount-rw / --mount-ro paths.

    Each must exist (file or dir) under /home/<user>/. The same path may not be
    requested both read-write and read-only. Writable directories must not
    overlap (be nested within, contain, or equal) the cwd or each other, so a
    write can't land in two overlapping trees; read-only mounts and files may sit
    anywhere. Returns the resolved, de-duplicated list (read-write first)."""
    resolved: list[HostMount] = []
    seen: dict[Path, bool] = {}  # host path -> read_only

    def add(raw: Path, read_only: bool) -> None:
        flag = "--mount-ro" if read_only else "--mount-rw"
        p = raw.expanduser().resolve()
        if not p.exists():
            raise ValueError(f"{flag} {p} does not exist")
        if not _under_home(username, p):
            raise ValueError(f"{flag} {p} must be under /home/{username}")
        if p == cwd:
            raise ValueError(f"{flag} {p} is the working directory, already mounted")
        if p in seen:
            if seen[p] != read_only:
                raise ValueError(
                    f"{p} is requested both read-write and read-only; pick one")
            return
        seen[p] = read_only
        resolved.append(HostMount(p, read_only))

    for raw in mount_rw:
        add(raw, read_only=False)
    for raw in mount_ro:
        add(raw, read_only=True)

    rw_dirs = [cwd] + [m.host_path for m in resolved if not m.read_only and m.host_path.is_dir()]
    for i, a in enumerate(rw_dirs):
        for b in rw_dirs[i + 1:]:
            if a in b.parents or b in a.parents:
                raise ValueError(
                    f"writable mounts overlap: {a} and {b} are nested; "
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
    aws_creds_secret: str | None = None,
    kube_client_certs_secret: str | None = None,
    kube_upstream_ca_secret: str | None = None,
    debug: bool = False,
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
        # Stream bodies over 1MB instead of buffering them whole in memory.
        # Large git packs (clone/fetch over HTTPS) would otherwise hold the
        # entire response in RAM and OOM the pod. The addon only inspects and
        # injects headers, so streaming bodies is safe.
        "--set",
        "stream_large_bodies=1m",
        "-s",
        "/addon/filter.py",
        "--set",
        "rules_file=/rules/rules.json",
    ]
    if debug:
        # Verbose flow logging. WARNING: flow_detail=3 dumps headers and bodies,
        # including re-signed AWS Authorization headers and request payloads, to
        # the mitm pod's stdout in plaintext. Off by default; opt in with
        # --mitm-debug only when diagnosing.
        mitm_args.extend(
            ["--set", "termlog_verbosity=debug", "--set", "flow_detail=3"]
        )
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

    # When AWS profiles are configured, mount the real-credentials map (keyed by
    # dummy AKIA) so the addon can re-sign requests. It lives only in this pod.
    if aws_creds_secret:
        volume_mounts.append(
            {"name": "aws-creds", "mountPath": "/aws-creds", "readOnly": True}
        )
        volumes.append(secret_volume("aws-creds", aws_creds_secret))
        mitm_args.extend(["--set", "aws_creds_file=/aws-creds/creds.json"])

    # When k8s contexts are configured, mount the client certs directory (one
    # <host>.pem per cluster) and the combined upstream CA bundle so mitmproxy
    # presents the right client cert and trusts each cluster's serving CA.
    if kube_client_certs_secret:
        volume_mounts.append(
            {"name": "kube-client-certs", "mountPath": "/kube-client-certs", "readOnly": True}
        )
        volumes.append(secret_volume("kube-client-certs", kube_client_certs_secret))
        mitm_args.extend(["--set", "client_certs=/kube-client-certs"])
    # mitmproxy's ssl_verify_upstream_trusted_ca *replaces* its default trust
    # store (certifi) rather than adding to it — pointing it straight at the
    # cluster CAs would make every public upstream (pypi.org, etc.) fail TLS
    # verification. So at startup we concatenate the image's own certifi bundle
    # (the exact public roots mitmdump would otherwise use) with the cluster CAs
    # into the writable /tmp and trust that combined file.
    command = ["mitmdump"]
    if kube_upstream_ca_secret:
        volume_mounts.append(
            {"name": "kube-upstream-ca", "mountPath": "/kube-upstream-ca", "readOnly": True}
        )
        volumes.append(secret_volume("kube-upstream-ca", kube_upstream_ca_secret))
        combined_ca = "/tmp/upstream-ca-bundle.pem"
        mitm_args.extend(["--set", f"ssl_verify_upstream_trusted_ca={combined_ca}"])
        command = [
            "sh",
            "-c",
            'cat "$(python -c \'import certifi; print(certifi.where())\')" '
            f"/kube-upstream-ca/bundle.pem > {combined_ca} && exec mitmdump \"$@\"",
            "--",
        ]

    container = container_spec(
        name="mitm",
        image=image,
        command=command,
        args=mitm_args,
        volume_mounts=volume_mounts,
        security_context=hardened_container_security_context(uid=1000, gid=1000),
        resources=Resources(
            memory="512Mi", cpu=None, memory_request="96Mi", cpu_request="500m"
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


def _ssh_agent_manifests(
    ns: str, image: str, runtime_class: str, *, uid: int, gid: int
) -> list[dict]:
    """The SSH key holder: a hardened pod running `ssh-agent` with the private
    keys (mounted as the `ssh-agent-keys` Secret), its socket bridged to TCP by
    socat so the agent pod can request signatures without seeing the keys. Reuses
    the agent image purely for its `ssh-agent`/`ssh-add`/`socat` binaries; the
    container itself runs unprivileged, non-root, read-only-root like mitm."""
    labels = _label("ssh-agent")
    sock = "/run/ssh-agent/agent.sock"
    # ssh-agent daemonises onto `sock`; load every key the Secret provides (the
    # `*` glob skips the Secret's dotfile bookkeeping, and nullglob makes an empty
    # dir a no-op rather than a literal `/keys/*`), then bridge the socket to TCP
    # for the agent pod. Keys are piped via `ssh-add -` (stdin) because ssh-add
    # refuses a key file that is group/world-readable, and the Secret mount is
    # mode 0644 — reading from stdin skips that permission check while the key
    # bytes still never leave this pod. A per-key failure is logged and skipped
    # so one bad key cannot strand the others; the pod fails (and is retried) only
    # if no key loads at all. `rm -f` clears any socket left by a prior container
    # start (the tmpfs survives in-place restarts), which would otherwise make
    # `ssh-agent -a` fail to bind.
    script = (
        "set -e\n"
        "shopt -s nullglob\n"
        f"rm -f {sock}\n"
        f"ssh-agent -a {sock} >/dev/null\n"
        "loaded=0\n"
        "for k in /keys/*; do\n"
        f'  if SSH_AUTH_SOCK={sock} ssh-add - < "$k"; then\n'
        "    loaded=$((loaded + 1))\n"
        "  else\n"
        '    echo "agent-uplink: failed to load SSH key $(basename "$k")" >&2\n'
        "  fi\n"
        "done\n"
        '[ "$loaded" -gt 0 ] || { '
        'echo "agent-uplink: no SSH keys could be loaded" >&2; exit 1; }\n'
        f"exec socat TCP-LISTEN:{SSH_AGENT_PORT},fork,reuseaddr UNIX-CONNECT:{sock}\n"
    )
    container = container_spec(
        name="ssh-agent",
        image=image,
        command=["bash", "-c", script],
        volume_mounts=[
            {"name": "keys", "mountPath": "/keys", "readOnly": True},
            {"name": "sock", "mountPath": "/run/ssh-agent"},
        ],
        security_context=hardened_container_security_context(uid=uid, gid=gid),
        resources=Resources(
            memory="128Mi", cpu="250m", memory_request="32Mi", cpu_request="20m"
        ),
        ports=[{"containerPort": SSH_AGENT_PORT, "protocol": "TCP"}],
        image_pull_policy="Always",
    )
    # Ready only once the agent is reachable and holds at least one key; `ssh-add
    # -l` exits 0 only then. An exec probe is used (not tcpSocket) so the kubelet
    # check is not blocked by ssh-agent-policy's ingress restriction. This makes a
    # key-load failure surface as a readiness timeout rather than silently later.
    container["readinessProbe"] = {
        "exec": {"command": ["sh", "-c", f"SSH_AUTH_SOCK={sock} ssh-add -l >/dev/null"]},
        "initialDelaySeconds": 1,
        "periodSeconds": 2,
    }
    spec = pod_spec(
        container=container,
        volumes=[
            secret_volume("keys", "ssh-agent-keys"),
            # Unix socket on tmpfs: virtio-fs-backed emptyDir is unreliable for
            # sockets, and the root fs is read-only.
            tmpfs_volume("sock", "8Mi"),
        ],
        runtime_class=runtime_class or None,
        pod_security_context={"fsGroup": gid},
    )
    pod = pod_manifest("ssh-agent", ns, labels=labels, spec=spec)
    svc = service_manifest(
        "ssh-agent", ns, selector=labels, port=SSH_AGENT_PORT, labels=labels
    )
    return [pod, svc]


def _ssh_relay_sidecar(image: str, uid: int, gid: int) -> dict:
    """Sidecar in the agent pod that presents a local unix socket bridged to the
    holder's ssh-agent over TCP. Holds no secret (it only relays), so a hardened
    context is enough even next to the privileged agent container."""
    # `unlink-early` clears any socket left by a prior container start (the tmpfs
    # survives in-place restarts), which would otherwise make the bind fail.
    script = (
        f"exec socat UNIX-LISTEN:{SSH_AUTH_SOCK_PATH},fork,unlink-early,perm=0666 "
        f"TCP-CONNECT:ssh-agent:{SSH_AGENT_PORT}\n"
    )
    sidecar = container_spec(
        name="ssh-agent-relay",
        image=image,
        command=["bash", "-c", script],
        volume_mounts=[{"name": "ssh-sock", "mountPath": "/ssh-agent"}],
        security_context=hardened_container_security_context(uid=uid, gid=gid),
        resources=Resources(
            memory="64Mi", cpu="200m", memory_request="16Mi", cpu_request="10m"
        ),
        image_pull_policy="Always",
    )
    # Gate the agent pod's readiness on the bridged socket existing, so the agent
    # never sees SSH_AUTH_SOCK pointing at a not-yet-created socket on attach.
    sidecar["readinessProbe"] = {
        "exec": {"command": ["sh", "-c", f"test -S {SSH_AUTH_SOCK_PATH}"]},
        "initialDelaySeconds": 1,
        "periodSeconds": 2,
    }
    return sidecar


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


@dataclass
class AgentMounts:
    """Optional, orchestrator-level mounts layered onto the agent pod on top of
    the agent's own PodContribution. Grouped so the manifest builder takes one
    argument instead of a tail of nullable secret names."""

    ssh_pub_secret: str | None = None
    ssh_pub_files: list[str] = field(default_factory=list)
    kube_config_secret: str | None = None
    git_config_secret: str | None = None
    extra_mounts: list[HostMount] = field(default_factory=list)


def _agent_pod_manifest(
    ns: str,
    full_image: str,
    contribution: PodContribution,
    cwd: Path,
    username: str,
    gid: int,
    runtime_class: str,
    pod_mounts: AgentMounts | None = None,
    *,
    uid: int,
) -> dict:
    pod_mounts = pod_mounts or AgentMounts()
    env = _agent_env(cwd, username)
    env.update(contribution.env)
    volumes = list(contribution.volumes)
    mounts = list(contribution.mounts)
    extra_containers: list[dict] = []
    # SSH key holder relay: the private keys never enter this pod. The agent gets
    # only the public keys + the user's `config`, dropped into the standard
    # ~/.ssh via per-file subPath mounts so the directory itself stays writable
    # (ssh creates known_hosts there) and ssh reads ~/.ssh/config by default.
    # SSH_AUTH_SOCK points at a unix socket the ssh-agent-relay sidecar bridges to
    # the holder pod's ssh-agent over TCP.
    if pod_mounts.ssh_pub_secret is not None:
        ssh_dir = f"/home/{username}/.ssh"
        volumes.append(secret_volume("ssh-pub", pod_mounts.ssh_pub_secret))
        for fname in pod_mounts.ssh_pub_files:
            mounts.append(
                {
                    "name": "ssh-pub",
                    "mountPath": f"{ssh_dir}/{fname}",
                    "subPath": fname,
                    "readOnly": True,
                }
            )
        volumes.append(tmpfs_volume("ssh-sock", "8Mi"))
        mounts.append({"name": "ssh-sock", "mountPath": "/ssh-agent"})
        env["SSH_AUTH_SOCK"] = SSH_AUTH_SOCK_PATH
        extra_containers.append(_ssh_relay_sidecar(full_image, uid, gid))
    # Sanitized kubeconfig: trusts mitm CA, carries placeholder creds. Mounted
    # outside the home dir so readOnlyRootFilesystem doesn't block the mount.
    # kubectl's cache writes (~/.kube/cache) are non-fatal when they fail.
    if pod_mounts.kube_config_secret is not None:
        volumes.append(secret_volume("kube-config", pod_mounts.kube_config_secret))
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
    if pod_mounts.git_config_secret is not None:
        volumes.append(secret_volume("git-config", pod_mounts.git_config_secret))
        mounts.append(
            {
                "name": "git-config",
                "mountPath": "/etc/gitconfig.d/agent-uplink.inc",
                "subPath": "agent-uplink.inc",
                "readOnly": True,
            }
        )
    for i, m in enumerate(pod_mounts.extra_mounts):
        name = f"mount-{i}"
        hp_type = "Directory" if m.host_path.is_dir() else "File"
        volumes.append(hostpath_volume(name, str(m.host_path), hp_type=hp_type))
        mounts.append(
            {"name": name, "mountPath": str(m.host_path), "readOnly": m.read_only}
        )
    container = container_spec(
        name=AGENT_CONTAINER_NAME,
        image=full_image,
        command=contribution.init_command,
        env=env,
        volume_mounts=mounts,
        security_context=contribution.security_context,
        # Reserve modestly so the pod schedules on small nodes; the memory limit
        # is the real ceiling the in-pod dockerd needs (tmpfs /var/lib/docker
        # counts against memory). CPU is left uncapped so the agent (and its
        # dockerd workloads) can burst freely.
        resources=Resources(
            memory=contribution.memory,
            cpu=None,
            memory_request="1Gi",
            cpu_request="500m",
        ),
        stdio=Stdio(stdin=True, tty=True),
        image_pull_policy="Always",
    )
    spec = pod_spec(
        container=container,
        volumes=volumes,
        runtime_class=runtime_class or None,
        pod_security_context={"fsGroup": gid},
        extra_containers=extra_containers or None,
    )
    return pod_manifest("agent", ns, labels=_label("agent"), spec=spec)


def _network_policies(
    ns: str, ssh_cidrs: list[str] | None = None, *, ssh_relay: bool = False
) -> list[dict]:
    """Default-deny + agent-egress + mitm-ingress (+ ssh-agent holder ingress)."""
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
    # SSH key holder: the agent reaches the ssh-agent-relay sidecar locally, but
    # that sidecar egresses to the holder pod for signing. Only signatures cross
    # this hop; the actual SSH connection still leaves the agent pod via the
    # --ssh-cidr rule above.
    if ssh_relay:
        agent_egress.append(
            {
                "to": [{"podSelector": {"matchLabels": {"app": "ssh-agent"}}}],
                "ports": [{"protocol": "TCP", "port": SSH_AGENT_PORT}],
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
        # the internet, including the real AWS endpoints it re-signs for).
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
    # ssh-agent holder: accepts the signing bridge from the agent only; no egress
    # (default-deny covers it — the agent does pure crypto, no network).
    if ssh_relay:
        policies.append(
            network_policy_manifest(
                "ssh-agent-policy",
                ns,
                pod_selector={"matchLabels": {"app": "ssh-agent"}},
                ingress=[
                    {
                        "from": [{"podSelector": {"matchLabels": {"app": "agent"}}}],
                        "ports": [{"protocol": "TCP", "port": SSH_AGENT_PORT}],
                    }
                ],
            )
        )
    return policies


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


@dataclass
class MitmCerts:
    """The mitm CA material read off the host, ready to wrap in the mitm-certs
    Secret."""

    ca_cert: bytes  # public cert only (also baked into the agent image)
    ca_full: bytes  # cert + private key (the signing CA)
    dhparam: bytes


@dataclass
class AwsPlan:
    """Everything the AWS SigV4 hop contributes: the Secret manifests (the real
    per-AKIA creds for the mitm pod + the agent's dummy creds), the dummy
    Secret's name for mounting into the agent, and the real-creds Secret's name
    for mounting into mitm."""

    profile_names: list[str]
    secret_manifests: list[dict]
    dummy_secret_name: str | None
    creds_secret_name: str | None


@dataclass
class KubeSecrets:
    """Secrets produced from --kube-context resolution plus the names the agent
    and mitm pods mount them under (None when that piece is absent)."""

    manifests: list[dict] = field(default_factory=list)
    config_secret: str | None = None  # agent pod kubeconfig
    client_certs_secret: str | None = None  # mitm client-certs dir
    upstream_ca_secret: str | None = None  # mitm upstream trust bundle


def _bootstrap_infra(args: argparse.Namespace, mitm_dir: Path) -> bool:
    """Registry + registries.yaml check + mitm CA. Returns True if the CA was
    just generated (which forces an agent image rebuild downstream)."""
    LOGGER.info("checking registry + k3s registries.yaml")
    check_registries_yaml()
    ensure_registry(args.registry_image)
    return ensure_mitm_certs(mitm_dir, args.mitmproxy_image)


def _resolve_aws_profiles(args: argparse.Namespace, agent: Agent) -> list[str]:
    """`--aws-profiles` plus any the agent discovers, de-duplicated in order."""
    names = list(args.aws_profiles)
    names.extend(agent.discover_aws_profiles())
    return list(dict.fromkeys(names))


def _ensure_agent_image(
    args: argparse.Namespace,
    agent: Agent,
    username: str,
    mitm_dir: Path,
    certs_generated: bool,
) -> str:
    """Return the agent image ref, rebuilding + pushing first when certs were
    just generated, --force-rebuild is set, the image is missing, or it's stale."""
    full_image = f"{REGISTRY_PUSH_ENDPOINT}/{agent.image_repo}:latest"
    image_age = get_image_age_seconds(full_image)
    stale = image_age is not None and image_age > AGENT_IMAGE_MAX_AGE_SECONDS
    if certs_generated or args.force_rebuild or image_age is None or stale:
        full_image = build_and_push_agent_image(
            agent.image_repo,
            agent.container_dir(),
            username,
            mitm_dir,
            bust_cache=args.force_rebuild or stale,
        )
    return full_image


def _build_aws_plan(session: Session, profile_names: list[str]) -> AwsPlan:
    """Build the agent's dummy-credentials Secret and the mitm pod's real-creds
    Secret (a JSON map from each profile's dummy AKIA to its real credentials)."""
    dummy_ini, profile_to_akia = dummy_aws_credentials_ini(profile_names)
    secret_manifests: list[dict] = []
    dummy_secret_name: str | None = None
    creds_secret_name: str | None = None

    if profile_names:
        akia_to_creds = {
            profile_to_akia[profile]: real_aws_credentials(
                export_aws_profile_env(profile)
            )
            for profile in profile_names
        }
        creds_secret_name = "aws-sigv4-creds"
        secret_manifests.append(
            secret_manifest(
                creds_secret_name,
                session.namespace,
                {"creds.json": sigv4_credentials_json(akia_to_creds)},
            )
        )
        dummy_secret_name = "agent-aws-creds"
        secret_manifests.append(
            secret_manifest(
                dummy_secret_name, session.namespace, {"credentials": dummy_ini}
            )
        )

    return AwsPlan(
        profile_names=profile_names,
        secret_manifests=secret_manifests,
        dummy_secret_name=dummy_secret_name,
        creds_secret_name=creds_secret_name,
    )


def _read_mitm_certs(mitm_dir: Path) -> MitmCerts:
    return MitmCerts(
        ca_cert=(mitm_dir / "mitmproxy-ca-cert.pem").read_bytes(),
        ca_full=(mitm_dir / "mitmproxy-ca.pem").read_bytes(),
        dhparam=(mitm_dir / "mitmproxy-dhparam.pem").read_bytes(),
    )


def _kube_secrets(session: Session, kube_plan: KubePlan | None) -> KubeSecrets:
    """Wrap the KubePlan's products as Secrets, recording the names the agent and
    mitm pods mount them under. Empty KubeSecrets when --kube-context is unset."""
    if kube_plan is None:
        return KubeSecrets()
    out = KubeSecrets(config_secret="kube-config")
    out.manifests.append(
        secret_manifest(
            "kube-config", session.namespace, {"config": kube_plan.pod_kubeconfig}
        )
    )
    if kube_plan.client_certs:
        out.client_certs_secret = "kube-client-certs"
        out.manifests.append(
            secret_manifest(
                "kube-client-certs", session.namespace, kube_plan.client_certs
            )
        )
    if kube_plan.upstream_ca_bundle:
        out.upstream_ca_secret = "kube-upstream-ca"
        out.manifests.append(
            secret_manifest(
                "kube-upstream-ca",
                session.namespace,
                {"bundle.pem": kube_plan.upstream_ca_bundle},
            )
        )
    return out


def _git_secret(
    session: Session, args: argparse.Namespace
) -> tuple[dict | None, str | None]:
    """Build the git overlay Secret (host identity + extra SSH->HTTPS rewrites),
    or (None, None) when the overlay would be empty."""
    overlay = build_git_overlay(
        args.git_https_rewrite, include_identity=not args.no_git_identity
    )
    if overlay is None:
        return None, None
    manifest = secret_manifest(
        "git-config", session.namespace, {"agent-uplink.inc": overlay}
    )
    return manifest, "git-config"


def _base_manifests(
    session: Session, rules_bytes: bytes, mitm_certs: MitmCerts
) -> list[dict]:
    """Namespace + the always-present mitm inputs (addon, rules, CA)."""
    return [
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
        secret_manifest("rules-json", session.namespace, {"rules.json": rules_bytes}),
        secret_manifest(
            "mitm-certs",
            session.namespace,
            {
                "mitmproxy-ca.pem": mitm_certs.ca_full,
                "mitmproxy-ca-cert.pem": mitm_certs.ca_cert,
                "mitmproxy-dhparam.pem": mitm_certs.dhparam,
            },
        ),
    ]


def _prepare_debug_dir(args: argparse.Namespace, session: Session) -> Path | None:
    if not args.debug:
        return None
    debug_host_dir = Path("/tmp/agent-uplink-debug") / session.id
    debug_host_dir.mkdir(parents=True, exist_ok=True)
    LOGGER.info(f"debug mode: agent logs → {debug_host_dir}")
    return debug_host_dir


def _wait_for_pods(session: Session, *, ssh_relay: bool = False) -> None:
    LOGGER.info("waiting for support pods")
    wait_for_pod_ready(session.namespace, "mitm", timeout=90)
    if ssh_relay:
        # The holder's readiness probe (`ssh-add -l`) passes only once a key is
        # loaded and the agent is reachable, so a key-load failure surfaces as a
        # timeout here rather than as a silent "ssh just doesn't work" on attach.
        wait_for_pod_ready(session.namespace, "ssh-agent", timeout=90)
    LOGGER.info("waiting for agent pod (kata cold-start)")
    wait_for_pod_ready(session.namespace, "agent", timeout=180)


def _assemble_manifests(
    session: Session,
    args: argparse.Namespace,
    *,
    full_image: str,
    contribution: PodContribution,
    rules_bytes: bytes,
    mitm_certs: MitmCerts,
    aws_plan: AwsPlan,
    prepared: PreparedAgent,
    kube_secrets: KubeSecrets,
    git_manifest: dict | None,
    git_secret_name: str | None,
    cwd: Path,
    username: str,
    uid: int,
    gid: int,
    ssh_cidrs: list[str],
    ssh_plan: sshagent.SshAgentPlan | None,
    extra_mounts: list[HostMount],
) -> list[dict]:
    """The full manifest set in apply order: namespace + mitm inputs, all
    Secrets, NetworkPolicies, support pods, then the agent pod."""
    ns = session.namespace
    manifests = _base_manifests(session, rules_bytes, mitm_certs)
    manifests.extend(aws_plan.secret_manifests)
    for name, files in prepared.secret_payloads.items():
        manifests.append(secret_manifest(name, ns, files))
    manifests.extend(kube_secrets.manifests)
    if git_manifest is not None:
        manifests.append(git_manifest)
    manifests.extend(
        _network_policies(ns, ssh_cidrs, ssh_relay=ssh_plan is not None)
    )
    manifests.extend(
        _mitm_manifests(
            ns,
            args.mitmproxy_image,
            args.mitm_runtime_class,
            aws_creds_secret=aws_plan.creds_secret_name,
            kube_client_certs_secret=kube_secrets.client_certs_secret,
            kube_upstream_ca_secret=kube_secrets.upstream_ca_secret,
            debug=args.mitm_debug,
        )
    )
    if ssh_plan is not None:
        manifests.append(secret_manifest("ssh-agent-keys", ns, ssh_plan.private_keys))
        manifests.append(secret_manifest("ssh-pub", ns, ssh_plan.agent_files))
        manifests.extend(
            _ssh_agent_manifests(
                ns, full_image, args.mitm_runtime_class, uid=uid, gid=gid
            )
        )
    manifests.append(
        _agent_pod_manifest(
            ns,
            full_image,
            contribution,
            cwd,
            username,
            gid,
            args.agent_runtime_class,
            AgentMounts(
                ssh_pub_secret="ssh-pub" if ssh_plan is not None else None,
                ssh_pub_files=list(ssh_plan.agent_files) if ssh_plan is not None else [],
                kube_config_secret=kube_secrets.config_secret,
                git_config_secret=git_secret_name,
                extra_mounts=extra_mounts,
            ),
            uid=uid,
        )
    )
    return manifests


def run(session: Session, args: argparse.Namespace, agent: Agent) -> int:
    username = os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name
    cwd = Path.cwd()
    validate_cwd(username, cwd)
    ssh_cidrs, ssh_key_dir = validate_ssh_args(args.ssh_cidr, args.ssh_key_dir)
    ssh_plan = sshagent.prepare(ssh_key_dir) if ssh_key_dir is not None else None
    if ssh_plan is not None and os.getuid() == 0:
        raise ValueError(
            "--ssh-key-dir is unsupported when running agent-uplink as root: the "
            "hardened holder/relay pods run runAsNonRoot with runAsUser=0, which "
            "the kubelet refuses to start. Run as a non-root host user."
        )
    if ssh_key_dir is not None and ssh_plan is None:
        LOGGER.warning(
            "--ssh-key-dir %s holds no private keys: no ssh-agent relay started",
            ssh_key_dir,
        )
    extra_mounts = validate_mounts(username, cwd, args.mount_rw, args.mount_ro)

    mitm_dir = STATE_DIR / "mitm"
    certs_generated = _bootstrap_infra(args, mitm_dir)

    aws_profile_names = _resolve_aws_profiles(args, agent)
    prepared = agent.prepare(session, aws_profile_names)
    full_image = _ensure_agent_image(args, agent, username, mitm_dir, certs_generated)

    aws_plan = _build_aws_plan(session, aws_profile_names)
    mitm_certs = _read_mitm_certs(mitm_dir)

    # Kube context resolution feeds the rule layer, so it precedes rule assembly.
    kube_plan: KubePlan | None = None
    if args.kube_context:
        LOGGER.info(f"resolving kube contexts: {args.kube_context}")
        kube_plan = resolve_kube(args.kubeconfig, args.kube_context, mitm_certs.ca_cert)

    rules_bytes = resolve_rules(
        args.rules,
        args.no_default_rules,
        agent,
        prepared.auth_rules,
        allow_exec=args.allow_exec,
        kube_rules=kube_plan.rules if kube_plan else None,
    )

    contribution = agent.pod_contribution(
        PodBuildContext(
            cwd=cwd,
            username=username,
            uid=os.getuid(),
            gid=os.getgid(),
            aws_creds_secret_name=aws_plan.dummy_secret_name,
            debug_host_dir=_prepare_debug_dir(args, session),
            debug=args.debug,
        )
    )

    kube_secrets = _kube_secrets(session, kube_plan)
    git_manifest, git_secret_name = _git_secret(session, args)
    manifests = _assemble_manifests(
        session,
        args,
        full_image=full_image,
        contribution=contribution,
        rules_bytes=rules_bytes,
        mitm_certs=mitm_certs,
        aws_plan=aws_plan,
        prepared=prepared,
        kube_secrets=kube_secrets,
        git_manifest=git_manifest,
        git_secret_name=git_secret_name,
        cwd=cwd,
        username=username,
        uid=os.getuid(),
        gid=os.getgid(),
        ssh_cidrs=ssh_cidrs,
        ssh_plan=ssh_plan,
        extra_mounts=extra_mounts,
    )

    LOGGER.info(f"applying {len(manifests)} manifests to ns/{session.namespace}")
    apply_manifests(manifests)

    _wait_for_pods(session, ssh_relay=ssh_plan is not None)

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


def _run_management_command(args: argparse.Namespace) -> int:
    """Dispatch the non-agent subcommands (list / clean)."""
    if args.agent_name == "list":
        return reaper.cmd_list()
    if args.agent_name == "clean":
        return reaper.cmd_clean(
            ids=args.ids,
            all_sessions=args.all,
            older_than=args.older_than,
            assume_yes=args.yes,
            wait=args.wait,
        )
    raise SystemExit(f"unknown command {args.agent_name!r}")


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    args = parse_args()

    # Target every deploy-side kubectl call (incl. signal-handler cleanup) at the
    # chosen context before anything can shell out to kubectl.
    set_kube_context(args.deploy_context)

    if args.agent_name not in AGENTS:
        raise SystemExit(_run_management_command(args))

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
