"""Session reaper: list and delete the per-run `agent-uplink-<id>` namespaces.

Teardown normally rides on the run's signal handlers, so a `kill -9`, a host
crash, or a closed lid leaks a namespace (and its pods/microVM). The `list` and
`clean` subcommands find those by the `managed-by=agent-uplink` label and delete
them. The long-lived registry namespace carries no such label, and is excluded
by name as well, so it is never a target.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .bootstrap import REGISTRY_NAMESPACE
from .k8s import delete_namespace, list_namespaces

LOGGER = logging.getLogger("agent-uplink")

LABEL_SELECTOR = "managed-by=agent-uplink"
NAMESPACE_PREFIX = "agent-uplink-"

_DURATION_RE = re.compile(r"(\d+)\s*([smhd])")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


@dataclass(frozen=True)
class SessionNamespace:
    namespace: str
    phase: str
    age_seconds: float

    @property
    def id(self) -> str:
        return self.namespace.removeprefix(NAMESPACE_PREFIX)


def parse_duration(text: str) -> float:
    """Parse a duration like '90s', '30m', '2h', '1d' into seconds."""
    match = _DURATION_RE.fullmatch(text.strip())
    if not match:
        raise ValueError(f"invalid duration {text!r}; use forms like 30m, 2h, 1d")
    return int(match.group(1)) * _UNIT_SECONDS[match.group(2)]


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # k8s emits RFC3339 with a trailing Z; fromisoformat wants an offset.
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def format_age(seconds: float) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h{(s % 3600) // 60}m"
    return f"{s // 86400}d{(s % 86400) // 3600}h"


def list_sessions(now: datetime | None = None) -> list[SessionNamespace]:
    """All session namespaces, oldest first so likely orphans surface at the top."""
    now = now or datetime.now(timezone.utc)
    sessions: list[SessionNamespace] = []
    for item in list_namespaces(LABEL_SELECTOR):
        meta = item.get("metadata", {})
        name = meta.get("name", "")
        if not name or name == REGISTRY_NAMESPACE:
            continue
        created = _parse_timestamp(meta.get("creationTimestamp"))
        age = (now - created).total_seconds() if created else 0.0
        phase = item.get("status", {}).get("phase", "Unknown")
        sessions.append(SessionNamespace(name, phase, age))
    return sorted(sessions, key=lambda s: s.age_seconds, reverse=True)


def select_for_clean(
    sessions: list[SessionNamespace],
    *,
    ids: list[str],
    all_sessions: bool,
    older_than_seconds: float | None,
) -> list[SessionNamespace]:
    """Pick which sessions to delete. Exactly one selector applies, in priority
    order all > older-than > ids. Raises ValueError if none is given (so `clean`
    with no arguments can't wipe everything by accident)."""
    if all_sessions:
        return list(sessions)
    if older_than_seconds is not None:
        return [s for s in sessions if s.age_seconds >= older_than_seconds]
    if ids:
        wanted = set(ids)
        return [s for s in sessions if s.namespace in wanted or s.id in wanted]
    raise ValueError("clean needs SESSION id(s), --all, or --older-than")


def cmd_list() -> int:
    sessions = list_sessions()
    if not sessions:
        LOGGER.info("no active agent-uplink sessions")
        return 0
    print(f"{'SESSION':<14}{'STATUS':<13}{'AGE':<9}NAMESPACE")
    for s in sessions:
        print(f"{s.id:<14}{s.phase:<13}{format_age(s.age_seconds):<9}{s.namespace}")
    return 0


def _confirm(count: int) -> bool:
    try:
        reply = input(f"delete {count} namespace(s)? [y/N] ")
    except EOFError:
        return False
    return reply.strip().lower() in ("y", "yes")


def cmd_clean(
    *,
    ids: list[str],
    all_sessions: bool,
    older_than: str | None,
    assume_yes: bool,
    wait: bool,
) -> int:
    older_than_seconds = parse_duration(older_than) if older_than else None
    sessions = list_sessions()
    try:
        targets = select_for_clean(
            sessions,
            ids=ids,
            all_sessions=all_sessions,
            older_than_seconds=older_than_seconds,
        )
    except ValueError as exc:
        LOGGER.error(str(exc))
        return 2

    if ids:
        known = {s.namespace for s in sessions} | {s.id for s in sessions}
        for token in ids:
            if token not in known:
                LOGGER.warning(f"no session matches {token!r}")

    if not targets:
        LOGGER.info("nothing to delete")
        return 0

    LOGGER.info("will delete:")
    for s in targets:
        LOGGER.info(f"  {s.namespace} (age {format_age(s.age_seconds)}, {s.phase})")

    if not assume_yes and not _confirm(len(targets)):
        LOGGER.info("aborted")
        return 1

    for s in targets:
        LOGGER.info(f"deleting {s.namespace}")
        delete_namespace(s.namespace, wait=wait)
    return 0
