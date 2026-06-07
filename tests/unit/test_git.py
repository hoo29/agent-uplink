"""Unit tests for the runtime git config overlay (agent_uplink/git.py)."""

import pytest

from agent_uplink import git as git_mod


def _fake_git_config(values):
    """Return a run_command stand-in answering `git config --global --get <key>`
    from `values` (key -> string). Missing keys return '' like the real CLI with
    raise_error=False."""

    def fake(command, *, raise_error=True):
        key = command[-1]
        return values.get(key, "")

    return fake


def _overlay(monkeypatch, extra_hosts, include_identity, values=None):
    monkeypatch.setattr(
        git_mod, "run_command", _fake_git_config(values or {})
    )
    out = git_mod.build_overlay(extra_hosts, include_identity=include_identity)
    return out.decode() if out is not None else None


def _overlay_text(monkeypatch, extra_hosts, include_identity, values=None):
    out = _overlay(monkeypatch, extra_hosts, include_identity, values)
    assert out is not None
    return out


def test_empty_overlay_returns_none(monkeypatch):
    assert _overlay(monkeypatch, [], include_identity=False) is None


def test_identity_enabled_but_unset_returns_none(monkeypatch):
    assert _overlay(monkeypatch, [], include_identity=True, values={}) is None


def test_identity_surfaced_when_present(monkeypatch):
    out = _overlay_text(
        monkeypatch, [], include_identity=True,
        values={"user.name": "Ada Lovelace", "user.email": "ada@example.com"},
    )
    assert "[user]" in out
    assert 'name = "Ada Lovelace"' in out
    assert 'email = "ada@example.com"' in out


def test_no_git_identity_omits_user(monkeypatch):
    out = _overlay_text(
        monkeypatch, ["git.example.com"], include_identity=False,
        values={"user.name": "Ada", "user.email": "ada@example.com"},
    )
    assert "[user]" not in out


def test_extra_host_rewrites_both_ssh_forms(monkeypatch):
    out = _overlay_text(monkeypatch, ["git.example.com"], include_identity=False)
    assert '[url "https://git.example.com/"]' in out
    assert "insteadOf = git@git.example.com:" in out
    assert "insteadOf = ssh://git@git.example.com/" in out


def test_partial_identity_only_emits_present_field(monkeypatch):
    out = _overlay_text(
        monkeypatch, [], include_identity=True,
        values={"user.email": "ada@example.com"},
    )
    assert "name =" not in out
    assert 'email = "ada@example.com"' in out


def test_value_with_comment_char_is_quoted(monkeypatch):
    # '#' would start a comment if unquoted; quoting preserves it.
    out = _overlay_text(
        monkeypatch, [], include_identity=True,
        values={"user.name": "A # B", "user.email": "a@b.c"},
    )
    assert 'name = "A # B"' in out


def test_git_absent_skips_identity(monkeypatch):
    def boom(command, *, raise_error=True):
        raise FileNotFoundError("git")

    monkeypatch.setattr(git_mod, "run_command", boom)
    # No identity available and no extra hosts -> nothing to ship.
    assert git_mod.build_overlay([], include_identity=True) is None


def test_invalid_host_raises(monkeypatch):
    monkeypatch.setattr(git_mod, "run_command", _fake_git_config({}))
    with pytest.raises(ValueError):
        git_mod.build_overlay(["bad host/with spaces"], include_identity=False)
