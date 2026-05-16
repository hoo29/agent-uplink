from __future__ import annotations

import logging
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .process import run_command
from .secret import LockedSecret

LOGGER = logging.getLogger("agent-uplink")


@dataclass
class Session:
    session_dir: Path
    socket_dir: Path
    aws_dir: Path
    containers: list[str] = field(default_factory=list)
    processes: list[subprocess.Popen] = field(default_factory=list)
    secrets: list[LockedSecret] = field(default_factory=list)
    network: str | None = None
    _cleaned_up: bool = field(default=False, init=False, repr=False)

    @classmethod
    def create(cls, state_dir: Path) -> Session:
        session_dir = state_dir / "sessions" / uuid.uuid4().hex
        socket_dir = session_dir / "sockets"
        socket_dir.mkdir(parents=True, exist_ok=True)
        aws_dir = session_dir / "aws_credentials"
        aws_dir.mkdir(parents=True, exist_ok=True)
        return cls(session_dir=session_dir, socket_dir=socket_dir, aws_dir=aws_dir)

    @property
    def id(self) -> str:
        return self.session_dir.name

    @property
    def socket_path(self) -> Path:
        return self.socket_dir / "uplink.sock"

    def cleanup(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True
        for name in self.containers:
            run_command(["docker", "stop", name, "-t", "3"], raise_error=False)
        for p in self.processes:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                LOGGER.warning(
                    f"process {p.pid} didn't respond to SIGTERM, SIGKILL'ing")
                p.kill()
        # Containers and host processes that bind-mounted any secret are gone,
        # so the only refs left are ours — close() now zeros pages before free.
        for s in self.secrets:
            s.close()
        self.secrets.clear()
        if self.network is not None:
            run_command(
                ["docker", "network", "rm", self.network], raise_error=False
            )
            self.network = None
        shutil.rmtree(self.session_dir, ignore_errors=True)


def handle_signal(session: Session, signum: int, _frame) -> None:
    session.cleanup()
    sys.exit(128 + signum)
