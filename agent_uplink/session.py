from __future__ import annotations

import logging
import shutil
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .k8s import delete_namespace

LOGGER = logging.getLogger("agent-uplink")

# A session held this long is almost certainly an orphan from a crashed or
# kill -9'd run rather than active work; each one pins a microVM and its pods.
STALE_SESSION_SECONDS = 24 * 3600


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
        warn_if_stale_sessions(self.namespace)


def warn_if_stale_sessions(exclude_namespace: str) -> None:
    """Warn about other session namespaces alive for over 24h.

    Teardown only deletes this run's namespace; a crashed or kill -9'd run leaks
    its own. The background-delete line above is the moment the user is looking,
    so we list the rest here and flag any older than 24h — each still holds a
    microVM and pods. Best-effort: a failed lookup (e.g. cluster unreachable
    during shutdown) must never block teardown."""
    try:
        from . import reaper

        stale = [
            s
            for s in reaper.list_sessions()
            if s.namespace != exclude_namespace
            and s.age_seconds >= STALE_SESSION_SECONDS
        ]
        if not stale:
            return
        LOGGER.warning(f"{len(stale)} potential orphaned sessions:")
        for s in stale:
            LOGGER.warning(
                f"  {s.id} (age {reaper.format_age(s.age_seconds)}, {s.phase})"
            )
        LOGGER.warning("remove with `agent-uplink clean --older-than 24h`")
    except Exception as exc:
        LOGGER.debug(f"stale-session check skipped: {exc}")


def handle_signal(session: Session, signum: int, _frame) -> None:
    session.cleanup()
    sys.exit(128 + signum)
