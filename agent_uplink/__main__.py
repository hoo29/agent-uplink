import argparse
import logging
import signal
import json
import os
import uuid


from pathlib import Path

from .utils import SESSION_DIRS, create_aws_profile_file_contents, get_free_port, run_command, run_command_background, shutdown_handler


LOGGER = logging.getLogger("agent-uplink")


def get_bedrock_aws_profile_name() -> str:
    with open(f"{Path.home()}/.claude/settings.json", "r", encoding="utf8") as f:
        settings = json.loads(f.read())
        name = settings.get("env", {}).get("AWS_PROFILE")
        if not name:
            raise RuntimeError("AWS_PROFILE not found in claude settings env")
        return name


def _main(socket_dir, mitm_dir):
    parser = argparse.ArgumentParser(
        description="Trust is a weakness", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-a", "--aws-profiles", type=str, nargs="*",
                        action="extend", default=[],
                        help="AWS profiles to provide credentials for")
    parser.add_argument("-m", "--mitmproxy-image", type=str,
                        default="mitmproxy/mitmproxy")
    parser.add_argument("-c", "--claude-image", type=str,
                        default="why")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG, format="%(message)s")
    LOGGER.info("hi")

    bedrock_aws_profile_name = get_bedrock_aws_profile_name()
    aws_profile_names = args.aws_profiles
    aws_profile_names.append(bedrock_aws_profile_name)
    aws_profile_file_contents = create_aws_profile_file_contents(
        aws_profile_names)

    free_port = get_free_port()

    socket_path = socket_dir / "uplink.sock"
    run_command_background(
        f"socat UNIX-LISTEN:{socket_path},fork,mode=666 TCP:127.0.0.1:{free_port}")

    mitmproxy_image = args.mitmproxy_image
    mitm_container_command = " ".join([
        "docker run",
        "--cap-add=DAC_OVERRIDE",
        "--cap-add=SETGID",
        "--cap-add=SETUID",
        "--cap-drop=ALL",
        "--cpus 1",
        "--ipc private",
        "--memory=0.5g",
        "--pids-limit 100",
        "--read-only",
        "--rm",
        "--security-opt no-new-privileges",
        f"-v {mitm_dir}:/home/mitmproxy/.mitmproxy",
        f"-p {free_port}:8080",
        mitmproxy_image,
        "mitmdump",
    ])
    run_command_background(mitm_container_command)

    claude_image = args.claude_image
    claude_container_command = " ".join([
        "docker run",
        "--cap-drop=ALL",
        "--cpus 1",
        "--ipc private",
        "--memory=0.5g",
        "--network none",
        "--pids-limit 100",
        "--read-only",
        "--rm",
        "--security-opt no-new-privileges",
        "--tmpfs /tmp:rw,noexec,nosuid,size=200m",
        "-it",
        f"-v {socket_path}:/mounts/socket/uplink.sock",
        f"-v {mitm_dir}:/mounts/certs:ro",
        claude_image,
    ])
    run_command(claude_container_command, interactive=True)

    idk = 1


def main():
    script_dir = Path.home() / ".agent_uplink" / uuid.uuid4().hex
    SESSION_DIRS.append(script_dir)
    socket_dir = script_dir / "sockets"
    mitm_dir = script_dir / "mitm"
    for dir in [socket_dir, mitm_dir]:
        os.makedirs(dir, exist_ok=True)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)
    try:
        _main(socket_dir, mitm_dir)
    except Exception:
        LOGGER.fatal("oh no", exc_info=True)
    finally:
        shutdown_handler(None, None)


if __name__ == "__main__":
    main()
