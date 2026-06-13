"""Unit tests for the session lifecycle: the per-run namespace + scratch dir, the
idempotent teardown, and the signal handler. The idempotency guard matters
because cleanup() runs from both the normal `finally` and the SIGINT/SIGTERM
handler — a double-fire must not double-delete or crash."""

import signal
from pathlib import Path
from unittest.mock import Mock

import pytest

from agent_uplink import session as session_mod
from agent_uplink.session import Session, handle_signal


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


def test_handle_signal_cleans_up_then_exits_128_plus_signum(tmp_path, monkeypatch):
    s = Session.create(tmp_path)
    cleanup = Mock()
    monkeypatch.setattr(s, "cleanup", cleanup)

    with pytest.raises(SystemExit) as exc:
        handle_signal(s, signal.SIGTERM, None)

    cleanup.assert_called_once_with()
    # Unix convention: a signal exit code is 128 + signum (SIGTERM=15 -> 143).
    assert exc.value.code == 128 + signal.SIGTERM
