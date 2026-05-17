from __future__ import annotations

import logging
import shutil
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .k8s import delete_namespace

LOGGER = logging.getLogger("agent-uplink")


@dataclass
class Session:
    """Single run of an agent. Owns one K8s namespace and a host-side scratch
    directory for transient files (e.g. a fake credentials.json an agent
    writes before it gets uploaded as a Secret)."""

    session_dir: Path
    namespace: str
    _cleaned_up: bool = field(default=False, init=False, repr=False)

    @classmethod
    def create(cls, state_dir: Path) -> Session:
        session_id = uuid.uuid4().hex[:12]
        session_dir = state_dir / "sessions" / session_id
        session_dir.mkdir(parents=True, exist_ok=True)
        namespace = f"agent-uplink-{session_id}"
        return cls(session_dir=session_dir, namespace=namespace)

    @property
    def id(self) -> str:
        return self.session_dir.name

    def cleanup(self) -> None:
        if self._cleaned_up:
            return
        self._cleaned_up = True
        LOGGER.info(f"deleting namespace {self.namespace} (background)")
        delete_namespace(self.namespace, wait=False)
        shutil.rmtree(self.session_dir, ignore_errors=True)


def handle_signal(session: Session, signum: int, _frame) -> None:
    session.cleanup()
    sys.exit(128 + signum)
