import logging
import subprocess

LOGGER = logging.getLogger("agent-uplink")


def run_command(
    command: list[str],
    *,
    stdin: bytes | None = None,
    stdout: int | None = subprocess.PIPE,
    stderr: int | None = subprocess.PIPE,
    raise_error: bool = True,
) -> str:
    LOGGER.debug(f"running {command}")
    res = subprocess.run(
        command,
        input=stdin,
        stdout=stdout,
        stderr=stderr,
        check=False,
    )
    stderr_d = res.stderr.decode("utf8") if res.stderr is not None else ""
    stdout_d = res.stdout.decode("utf8") if res.stdout is not None else ""
    if res.returncode != 0:
        if raise_error:
            raise RuntimeError(
                f"command failed ({command[0]} exit={res.returncode}). stderr: {stderr_d}"
            )
        return ""
    return stdout_d


def run_interactive(command: list[str]) -> int:
    """Run a command attached to the parent's stdio (no piping). Returns exit code."""
    LOGGER.debug(f"running interactive {command}")
    res = subprocess.run(command, check=False)
    return res.returncode
