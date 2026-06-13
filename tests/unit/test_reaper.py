"""Unit tests for the session reaper: duration parsing, the listing query (age
derivation, oldest-first ordering, registry-namespace exclusion), the
clean-target selection (the no-selector guard that stops `clean` wiping
everything by accident), and the clean command's confirm/skip paths. No cluster."""

from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from agent_uplink import reaper
from agent_uplink.reaper import SessionNamespace, parse_duration, select_for_clean

NOW = datetime(2026, 6, 13, 12, 0, 0, tzinfo=timezone.utc)


def _ns(name: str, created: str, phase: str = "Active") -> dict:
    return {
        "metadata": {"name": name, "creationTimestamp": created},
        "status": {"phase": phase},
    }


# --------------------------------------------------------------------------- #
# parse_duration
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text,seconds",
    [("90s", 90), ("30m", 1800), ("2h", 7200), ("1d", 86400)],
)
def test_parse_duration_units(text, seconds):
    assert parse_duration(text) == seconds


@pytest.mark.parametrize("text", ["", "5", "10x", "h", "1.5h", "-5m"])
def test_parse_duration_rejects_garbage(text):
    with pytest.raises(ValueError):
        parse_duration(text)


# --------------------------------------------------------------------------- #
# list_sessions
# --------------------------------------------------------------------------- #


def test_list_sessions_derives_age_and_orders_oldest_first(monkeypatch):
    monkeypatch.setattr(
        reaper,
        "list_namespaces",
        lambda _sel: [
            _ns("agent-uplink-aaa", "2026-06-13T11:00:00Z"),  # 1h old
            _ns("agent-uplink-bbb", "2026-06-13T10:00:00Z"),  # 2h old
        ],
    )
    sessions = reaper.list_sessions(now=NOW)
    assert [s.id for s in sessions] == ["bbb", "aaa"]  # oldest first
    assert sessions[0].age_seconds == 7200
    assert sessions[1].age_seconds == 3600


def test_list_sessions_excludes_registry_namespace(monkeypatch):
    # The long-lived registry must never be a reaper target, even if it somehow
    # carries the managed-by label.
    monkeypatch.setattr(
        reaper,
        "list_namespaces",
        lambda _sel: [
            _ns(reaper.REGISTRY_NAMESPACE, "2026-06-13T09:00:00Z"),
            _ns("agent-uplink-aaa", "2026-06-13T11:00:00Z"),
        ],
    )
    sessions = reaper.list_sessions(now=NOW)
    assert [s.namespace for s in sessions] == ["agent-uplink-aaa"]


def test_list_sessions_tolerates_missing_timestamp_and_phase(monkeypatch):
    monkeypatch.setattr(
        reaper,
        "list_namespaces",
        lambda _sel: [{"metadata": {"name": "agent-uplink-aaa"}}],
    )
    (session,) = reaper.list_sessions(now=NOW)
    assert session.age_seconds == 0.0
    assert session.phase == "Unknown"


# --------------------------------------------------------------------------- #
# select_for_clean
# --------------------------------------------------------------------------- #


SESSIONS = [
    SessionNamespace("agent-uplink-old", "Active", 7200),
    SessionNamespace("agent-uplink-new", "Active", 600),
]


def test_select_all_returns_everything():
    got = select_for_clean(
        SESSIONS, ids=[], all_sessions=True, older_than_seconds=None
    )
    assert got == SESSIONS


def test_select_older_than_filters_by_age():
    got = select_for_clean(
        SESSIONS, ids=[], all_sessions=False, older_than_seconds=3600
    )
    assert [s.id for s in got] == ["old"]


def test_select_by_id_or_namespace():
    by_id = select_for_clean(
        SESSIONS, ids=["new"], all_sessions=False, older_than_seconds=None
    )
    by_ns = select_for_clean(
        SESSIONS,
        ids=["agent-uplink-old"],
        all_sessions=False,
        older_than_seconds=None,
    )
    assert [s.id for s in by_id] == ["new"]
    assert [s.id for s in by_ns] == ["old"]


def test_select_with_no_selector_raises():
    # The guard that stops a bare `clean` from selecting (and deleting) all.
    with pytest.raises(ValueError):
        select_for_clean(
            SESSIONS, ids=[], all_sessions=False, older_than_seconds=None
        )


# --------------------------------------------------------------------------- #
# cmd_clean
# --------------------------------------------------------------------------- #


def test_cmd_clean_no_selector_returns_error_without_deleting(monkeypatch):
    monkeypatch.setattr(reaper, "list_sessions", lambda: SESSIONS)
    delete = Mock()
    monkeypatch.setattr(reaper, "delete_namespace", delete)

    rc = reaper.cmd_clean(
        ids=[], all_sessions=False, older_than=None, assume_yes=True, wait=False
    )

    assert rc == 2
    delete.assert_not_called()


def test_cmd_clean_all_with_yes_deletes_each(monkeypatch):
    monkeypatch.setattr(reaper, "list_sessions", lambda: SESSIONS)
    delete = Mock()
    monkeypatch.setattr(reaper, "delete_namespace", delete)

    rc = reaper.cmd_clean(
        ids=[], all_sessions=True, older_than=None, assume_yes=True, wait=True
    )

    assert rc == 0
    assert delete.call_count == 2
    delete.assert_any_call("agent-uplink-old", wait=True)
    delete.assert_any_call("agent-uplink-new", wait=True)


def test_cmd_clean_declined_prompt_deletes_nothing(monkeypatch):
    monkeypatch.setattr(reaper, "list_sessions", lambda: SESSIONS)
    delete = Mock()
    monkeypatch.setattr(reaper, "delete_namespace", delete)
    monkeypatch.setattr("builtins.input", lambda _prompt: "n")

    rc = reaper.cmd_clean(
        ids=[], all_sessions=True, older_than=None, assume_yes=False, wait=False
    )

    assert rc == 1
    delete.assert_not_called()


def test_cmd_clean_older_than_returns_zero_when_nothing_matches(monkeypatch):
    monkeypatch.setattr(reaper, "list_sessions", lambda: SESSIONS)
    delete = Mock()
    monkeypatch.setattr(reaper, "delete_namespace", delete)

    rc = reaper.cmd_clean(
        ids=[], all_sessions=False, older_than="10h", assume_yes=True, wait=False
    )

    assert rc == 0
    delete.assert_not_called()
