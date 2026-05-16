import logging
import os
import shutil
import time
from pathlib import Path

from .config import HOST_CLAUDE_DIR
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
    "--memory=0.5g",
    "--pids-limit",
    "100",
    "--read-only",
    "--rm",
    "--init",
    "--security-opt",
    "no-new-privileges",
]


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


def check_claude_image_exists(claude_image: str) -> bool:
    return (
        run_command(["docker", "image", "inspect", claude_image], raise_error=False)
        != ""
    )


def build_claude_image(
    claude_image: str, username: str, mitm_dir: Path, force_rebuild: bool = False
) -> None:
    LOGGER.info("(re)building claude container")
    container_dir = Path(__file__).resolve().parent / "claude_container"
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
            claude_image,
            str(container_dir),
        ],
        stdout=None,
        stderr=None,
    )


def build_claude_mounts(
    username: str,
    settings_path: Path,
    aws_creds_path: Path | None,
    socket_path: Path,
    mitm_dir: Path,
    cwd: Path,
) -> list[str]:
    project_id = str(Path.cwd()).replace("/", "-")
    host_project_dir = HOST_CLAUDE_DIR / "projects" / project_id
    host_project_dir.mkdir(parents=True, exist_ok=True)

    container_home = get_container_home(username)
    claude_dir = container_home / ".claude"
    uid, gid = os.getuid(), os.getgid()

    mounts: list[str] = [
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=200m",
        "--tmpfs",
        f"{container_home / '.local' / 'share' / 'applications'}:rw,noexec,nosuid,size=200m",
        "--tmpfs",
        f"{claude_dir}:rw,noexec,nosuid,size=200m,uid={uid},gid={gid}",
    ]

    def vol(host: Path, container: str, mode: str | None = None) -> None:
        spec = f"{host}:{container}" if mode is None else f"{host}:{container}:{mode}"
        mounts.extend(["-v", spec])

    vol(settings_path, f"{claude_dir}/settings.json", "ro")
    vol(mitm_dir, "/mnt/certs", "ro")
    vol(host_project_dir, f"{claude_dir}/projects/{project_id}", "rw")
    vol(Path.home() / ".claude.json", f"{container_home}/.claude.json", "rw")
    vol(socket_path, "/mnt/socket/uplink.sock")
    vol(cwd, str(cwd), "rw")

    for name in ["CLAUDE.md", "commands", "skills"]:
        host_path = HOST_CLAUDE_DIR / name
        if host_path.exists():
            vol(host_path, f"{claude_dir}/{name}", "ro")
    for name in [".credentials.json", "history.jsonl"]:
        host_path = HOST_CLAUDE_DIR / name
        if host_path.exists():
            vol(host_path, f"{claude_dir}/{name}", "rw")

    if aws_creds_path is not None:
        vol(aws_creds_path, str(container_home / ".aws"), "ro")

    return mounts


def _ensure_container_running(container_name: str) -> None:
    time.sleep(1)
    status = run_command(
        ["docker", "inspect", "-f", "{{.State.Status}}", container_name],
        raise_error=False,
    ).strip()
    if status != "running":
        raise RuntimeError(f"container {container_name} not running")
    LOGGER.debug(f"container {container_name} is running")


def start_mitm_proxy(
    session: Session,
    mitm_dir: Path,
    mitmproxy_image: str,
    port: int,
    rules_bind_source: str,
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
    proc = run_command_background(
        [
            "docker",
            "run",
            "--name",
            container_name,
            *DOCKER_RUN_FLAGS,
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


def start_claude_container(
    session: Session,
    claude_image: str,
    cwd: Path,
    claude_mounts: list[str],
) -> None:
    container_name = f"agent-uplink-claude-{session.id}"
    session.containers.append(container_name)
    LOGGER.info("starting claude container")
    run_command(
        [
            "docker",
            "run",
            "--name",
            container_name,
            *DOCKER_RUN_FLAGS,
            "--network",
            "none",
            "-it",
            "-e",
            f"WORKDIR={cwd}",
            *claude_mounts,
            claude_image,
        ],
        stdout=None,
        stderr=None,
        raise_error=False,
    )
