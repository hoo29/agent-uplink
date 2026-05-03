import logging
import socketserver
import subprocess

LOGGER = logging.getLogger("agent-uplink")


def run_command(
    command: list[str],
    *,
    stdout: int | None = subprocess.PIPE,
    stderr: int | None = subprocess.PIPE,
    raise_error: bool = True,
) -> str:
    LOGGER.debug(f"running {command}")
    res = subprocess.run(
        command,
        stdout=stdout,
        stderr=stderr,
        check=False,
    )
    stderr_d = res.stderr.decode("utf8") if res.stderr is not None else ""
    stdout_d = res.stdout.decode("utf8") if res.stdout is not None else ""
    if res.returncode != 0:
        if raise_error:
            raise OSError(
                f"command failed with exit code {res.returncode}. Stderr: {stderr_d}"
            )
        return ""
    return stdout_d


def run_command_background(command: list[str]) -> subprocess.Popen:
    LOGGER.debug(f"running {command} (background)")
    return subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def get_free_port() -> int:
    with socketserver.TCPServer(("localhost", 0), None) as s:  # type: ignore
        # something else could nab this port before we use it but see how we go
        return s.server_address[1]
