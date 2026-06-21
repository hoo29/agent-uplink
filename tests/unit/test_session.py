"""Unit tests for the session lifecycle: the per-run namespace + scratch dir, the
idempotent teardown, and the signal handler. The idempotency guard matters
because cleanup() runs from both the normal `finally` and the SIGINT/SIGTERM
handler — a double-fire must not double-delete or crash."""

import signal
from pathlib import Path
from unittest.mock import Mock

import pytest

from agent_uplink import reaper as reaper_mod
from agent_uplink import session as session_mod
from agent_uplink.reaper import SessionNamespace
from agent_uplink.session import Session, handle_signal


@pytest.fixture(autouse=True)
def _no_stale_sessions(monkeypatch):
    """Default: the post-teardown stale-session scan finds nothing, so the
    cleanup tests don't reach for a real cluster. Tests that exercise the
    warning override list_sessions themselves."""
    monkeypatch.setattr(reaper_mod, "list_sessions", lambda: [])


def test_create_derives_hex_id_dir_and_namespace(tmp_path):
    s = Session.create(tmp_path)
    assert len(s.id) == 12
    assert all(c in "0123456789abcdef" for c in s.id)
    assert s.session_dir == tmp_path / "sessions" / s.id
    assert s.session_dir.is_dir()
    # The namespace is deterministically derived from the id, so cleanup can
    # target it without extra bookkeeping.
    assert s.namespace == f"agent-uplink-{s.id}"


def test_id_property_is_the_session_dir_name():
    s = Session(session_dir=Path("/tmp/s/abc123def456"), namespace="x")
    assert s.id == "abc123def456"


def test_cleanup_deletes_namespace_async_and_removes_dir(tmp_path, monkeypatch):
    s = Session.create(tmp_path)
    (s.session_dir / "scratch").write_text("transient")
    delete = Mock()
    monkeypatch.setattr(session_mod, "delete_namespace", delete)

    s.cleanup()

    delete.assert_called_once_with(s.namespace, wait=False)
    assert not s.session_dir.exists()


def test_cleanup_is_idempotent(tmp_path, monkeypatch):
    s = Session.create(tmp_path)
    delete = Mock()
    monkeypatch.setattr(session_mod, "delete_namespace", delete)

    s.cleanup()
    s.cleanup()  # second fire (e.g. signal during normal shutdown)

    # Only the first call does anything; the guard prevents a double delete.
    assert delete.call_count == 1


def test_cleanup_warns_about_other_sessions_over_24h(tmp_path, monkeypatch, caplog):
    s = Session.create(tmp_path)
    monkeypatch.setattr(session_mod, "delete_namespace", Mock())
    monkeypatch.setattr(
        reaper_mod,
        "list_sessions",
        lambda: [
            # The session being torn down: excluded even though it is old.
            SessionNamespace(s.namespace, "Running", 30 * 3600),
            # A fresh leftover: under the threshold, so not flagged.
            SessionNamespace("agent-uplink-young", "Running", 3600),
            # An orphan past 24h: the one we want surfaced.
            SessionNamespace("agent-uplink-stale1", "Running", 90000),
        ],
    )

    with caplog.at_level("WARNING"):
        s.cleanup()

    text = caplog.text
    assert "1 potential orphaned sessions" in text
    assert "stale1" in text
    assert "agent-uplink clean --older-than 24h" in text
    # The current namespace and the young one are not reported as stale.
    assert s.id not in text
    assert "young" not in text


def test_cleanup_warning_failure_does_not_break_teardown(tmp_path, monkeypatch):
    s = Session.create(tmp_path)
    monkeypatch.setattr(session_mod, "delete_namespace", Mock())

    def boom():
        raise RuntimeError("cluster unreachable")

    monkeypatch.setattr(reaper_mod, "list_sessions", boom)

    # A failed stale-session lookup is swallowed; teardown still completes.
    s.cleanup()
    assert not s.session_dir.exists()


def test_handle_signal_cleans_up_then_exits_128_plus_signum(tmp_path, monkeypatch):
    s = Session.create(tmp_path)
    cleanup = Mock()
    monkeypatch.setattr(s, "cleanup", cleanup)

    with pytest.raises(SystemExit) as exc:
        handle_signal(s, signal.SIGTERM, None)

    cleanup.assert_called_once_with()
    # Unix convention: a signal exit code is 128 + signum (SIGTERM=15 -> 143).
    assert exc.value.code == 128 + signal.SIGTERM
