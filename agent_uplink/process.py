import logging
import subprocess
from dataclasses import dataclass

LOGGER = logging.getLogger("agent-uplink")


@dataclass
class CommandResult:
    """Outcome of a subprocess run. Keeps returncode, stdout and stderr distinct
    so callers can tell a successful empty-output command from a failed one (a
    bare stdout string cannot)."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(
    command: list[str],
    *,
    stdin: bytes | None = None,
    stdout: int | None = subprocess.PIPE,
    stderr: int | None = subprocess.PIPE,
) -> CommandResult:
    """Run a command and return its full result. Never raises on a non-zero exit
    (inspect `.ok`/`.returncode`); use `run_command` for the raise-or-string
    convenience wrapper."""
    LOGGER.debug(f"running {command}")
    res = subprocess.run(
        command,
        input=stdin,
        stdout=stdout,
        stderr=stderr,
        check=False,
    )
    # errors="replace": tool output is only logged/parsed leniently here, and a
    # stray non-UTF-8 byte must not turn into a UnicodeDecodeError mid-run.
    out = res.stdout.decode("utf-8", errors="replace") if res.stdout is not None else ""
    err = res.stderr.decode("utf-8", errors="replace") if res.stderr is not None else ""
    return CommandResult(res.returncode, out, err)


def run_command(
    command: list[str],
    *,
    stdin: bytes | None = None,
    stdout: int | None = subprocess.PIPE,
    stderr: int | None = subprocess.PIPE,
    raise_error: bool = True,
) -> str:
    """Run a command and return its stdout.

    On a non-zero exit: raise RuntimeError when `raise_error` (default), else log
    stderr at warning and return "". The tolerated-failure path logs rather than
    swallowing stderr so a failure isn't silently indistinguishable from empty
    output; callers that must branch on the exit code should use `run` instead.
    """
    res = run(command, stdin=stdin, stdout=stdout, stderr=stderr)
    if not res.ok:
        if raise_error:
            raise RuntimeError(
                f"command failed ({command[0]} exit={res.returncode}). "
                f"stderr: {res.stderr.strip()}"
            )
        if res.stderr.strip():
            LOGGER.warning(
                "command %s exited %d (tolerated): %s",
                command[0],
                res.returncode,
                res.stderr.strip(),
            )
        return ""
    return res.stdout


def run_interactive(command: list[str]) -> int:
    """Run a command attached to the parent's stdio (no piping). Returns exit code."""
    LOGGER.debug(f"running interactive {command}")
    res = subprocess.run(command, check=False)
    return res.returncode
