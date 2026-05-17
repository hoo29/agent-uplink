import logging
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

from .process import run_command, run_command_background
from .session import Session

LOGGER = logging.getLogger("agent-uplink")

ADDON_DIR = Path(__file__).resolve().parent / "mitm_addon"


DOCKER_RUN_FLAGS: list[str] = [
    "--cap-drop=ALL",
    "--cpus",
    "1",
    "--ipc",
    "private",
    "--pids-limit",
    "300",
    "--read-only",
    "--rm",
    "--init",
    "--security-opt",
    "no-new-privileges",
]


# Per-agent image rebuild trigger: rebuild if older than this.
AGENT_IMAGE_MAX_AGE_SECONDS = 86_400


def get_container_home(username: str) -> Path:
    return Path("/home") / username


def ensure_mitm_certs(mitm_dir: Path, mitmproxy_image: str) -> bool:
    cert_file = mitm_dir / "mitmproxy-ca-cert.pem"
    if cert_file.exists():
        LOGGER.debug("mitmproxy certs exist")
        return False

    LOGGER.info("generating mitmproxy certs")
    run_command(
        [
            "docker",
            "run",
            "-u",
            f"{os.getuid()}:{os.getgid()}",
            "--rm",
            "--init",
            "--read-only",
            "-v",
            f"{mitm_dir}:/tmp/.mitmproxy",
            "--entrypoint",
            "/bin/sh",
            mitmproxy_image,
            "-c",
            "exec mitmdump --set confdir=/tmp/.mitmproxy --no-server -r /dev/null",
        ]
    )
    return True


def get_image_age_seconds(image: str) -> float | None:
    output = run_command(
        ["docker", "image", "inspect", "-f", "{{.Created}}", image],
        raise_error=False,
    ).strip()
    if not output:
        return None
    # docker returns RFC3339 like "2024-01-15T10:30:45.123456789Z"; trim
    # the trailing Z and any sub-second precision Python <3.11 can't parse.
    ts = output.rstrip("Z").split(".")[0]
    created = datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - created).total_seconds()


def build_agent_image(
    image: str,
    container_dir: Path,
    username: str,
    mitm_dir: Path,
    force_rebuild: bool = False,
) -> None:
    """Build an agent container image.

    Copies the host's mitmproxy certs into <container_dir>/certs/ so the
    Dockerfile can COPY them in (the image trusts mitmproxy's CA).
    """
    LOGGER.info(f"(re)building agent container image {image}")
    shutil.copytree(mitm_dir, container_dir / "certs", dirs_exist_ok=True)
    build_args = [
        "--build-arg",
        f"USERNAME={username}",
        "--build-arg",
        f"USER_UID={os.getuid()}",
        "--build-arg",
        f"USER_GID={os.getgid()}",
    ]
    if force_rebuild:
        build_args += ["--build-arg", f"CACHE_BUST={int(time.time())}"]
    run_command(
        [
            "docker",
            "build",
            *build_args,
            "-t",
            image,
            str(container_dir),
        ],
        stdout=None,
        stderr=None,
    )


def _ensure_container_running(container_name: str, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    status = ""
    while time.monotonic() < deadline:
        status = run_command(
            ["docker", "inspect", "-f", "{{.State.Status}}", container_name],
            raise_error=False,
        ).strip()
        if status == "running":
            LOGGER.debug(f"container {container_name} is running")
            return
        if status in {"exited", "dead"}:
            break
        time.sleep(0.2)
    raise RuntimeError(
        f"container {container_name} not running (last status: {status or 'missing'})"
    )


def create_network(name: str) -> None:
    LOGGER.info(f"creating docker network {name}")
    run_command(["docker", "network", "create", name])


def remove_network(name: str) -> None:
    run_command(["docker", "network", "rm", name], raise_error=False)


def start_mitm_proxy(
    session: Session,
    mitm_dir: Path,
    mitmproxy_image: str,
    port: int,
    rules_bind_source: str,
    network: str | None = None,
) -> None:
    LOGGER.info("starting socat on host")
    socat_proc = run_command_background(
        [
            "socat",
            f"UNIX-LISTEN:{session.socket_path},fork,mode=600",
            f"TCP:127.0.0.1:{port}",
        ]
    )
    session.processes.append(socat_proc)

    container_name = f"agent-uplink-mitm-{session.id}"
    session.containers.append(container_name)
    LOGGER.info("starting mitmproxy container")
    network_args = ["--network", network] if network else []
    proc = run_command_background(
        [
            "docker",
            "run",
            "--name",
            container_name,
            *DOCKER_RUN_FLAGS,
            "--memory=0.5g",
            *network_args,
            "--entrypoint",
            "/bin/sh",
            "-u",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{mitm_dir}:/tmp/.mitmproxy",
            "-v",
            f"{ADDON_DIR}:/mnt/addon:ro",
            "-v",
            f"{rules_bind_source}:/mnt/rules.json:ro",
            "-p",
            f"{port}:8080",
            mitmproxy_image,
            "-c",
            "exec mitmdump --set confdir=/tmp/.mitmproxy "
            "-s /mnt/addon/filter.py --set rules_file=/mnt/rules.json",
        ]
    )
    session.processes.append(proc)
    _ensure_container_running(container_name)


def start_sigv4_proxy(
    session: Session,
    image: str,
    container_name: str,
    network: str,
    profile: str,
    creds_bind_source: str,
) -> None:
    session.containers.append(container_name)
    LOGGER.info(f"starting sigv4-proxy sidecar {container_name}")
    # Run as the host user so the bind-mounted, host-owned 0600 creds file is
    # readable (--cap-drop=ALL strips CAP_DAC_OVERRIDE, so root-in-container
    # cannot bypass the permission check).
    proc = run_command_background(
        [
            "docker",
            "run",
            "--name",
            container_name,
            *DOCKER_RUN_FLAGS,
            "--memory=128m",
            "--network",
            network,
            "-u",
            f"{os.getuid()}:{os.getgid()}",
            "-v",
            f"{creds_bind_source}:/aws/credentials:ro",
            "-e",
            "AWS_SHARED_CREDENTIALS_FILE=/aws/credentials",
            "-e",
            f"AWS_PROFILE={profile}",
            image,
            "--log-failed-requests",
            "--log-signing-process",
            "-v",
        ]
    )
    session.processes.append(proc)
    _ensure_container_running(container_name)


def start_agent_container(
    session: Session,
    agent_name: str,
    image: str,
    mounts: list[str],
    env: dict[str, str],
    runtime: str,
    memory: str,
) -> None:
    container_name = f"agent-uplink-{agent_name}-{session.id}"
    session.containers.append(container_name)
    LOGGER.info(f"starting {agent_name} container")
    env_args: list[str] = []
    for key, value in env.items():
        env_args.extend(["-e", f"{key}={value}"])
    run_command(
        [
            "docker",
            "run",
            "--name",
            container_name,
            *DOCKER_RUN_FLAGS,
            f"--memory={memory}",
            f"--runtime={runtime}",
            "--network",
            "none",
            "-it",
            *env_args,
            *mounts,
            image,
        ],
        stdout=None,
        stderr=None,
        raise_error=False,
    )
