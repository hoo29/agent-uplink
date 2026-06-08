"""Unit tests for the subprocess wrappers. The contract that matters: a failed
command is distinguishable from a successful empty-output one, and a tolerated
failure surfaces stderr (via a log) rather than swallowing it silently."""

import logging

import pytest

from agent_uplink.process import CommandResult, run, run_command


def test_run_reports_returncode_and_streams():
    res = run(["sh", "-c", "printf out; printf err >&2; exit 3"])
    assert isinstance(res, CommandResult)
    assert res.returncode == 3
    assert res.ok is False
    assert res.stdout == "out"
    assert res.stderr == "err"


def test_run_distinguishes_empty_success_from_failure():
    ok = run(["sh", "-c", "exit 0"])  # empty stdout, succeeded
    bad = run(["sh", "-c", "exit 1"])  # empty stdout, failed
    assert ok.stdout == bad.stdout == ""
    assert ok.ok and not bad.ok  # the returncode tells them apart


def test_run_command_returns_stdout_on_success():
    assert run_command(["sh", "-c", "printf hello"]) == "hello"


def test_run_command_raises_with_stderr_on_failure():
    with pytest.raises(RuntimeError, match="boom"):
        run_command(["sh", "-c", "printf boom >&2; exit 1"])


def test_run_command_tolerated_failure_logs_stderr(caplog):
    with caplog.at_level(logging.WARNING, logger="agent-uplink"):
        out = run_command(["sh", "-c", "printf boom >&2; exit 1"], raise_error=False)
    assert out == ""
    assert "boom" in caplog.text  # stderr surfaced, not swallowed
