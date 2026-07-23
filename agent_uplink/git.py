"""Runtime git config overlay for the agent pod.

The agent image bakes /etc/gitconfig with SSH->HTTPS `insteadOf` rewrites for the
default hosts and an `include.path` to this overlay, mounted when non-empty:

  - extra SSH->HTTPS rewrites for `--git-https-rewrite` hosts (insteadOf is a
    multivar, so these add to the baked defaults), and
  - the host's git identity (user.name / user.email) unless disabled.

The overlay carries no secrets (git auth is injected by mitm), so its Secret is
safe to mount into the agent pod."""

from __future__ import annotations

import logging
import re

from .process import run

LOGGER = logging.getLogger("agent-uplink")

# Hostname (optionally :port) — guards against config-breaking characters in
# values that come from --git-https-rewrite.
_HOST_RE = re.compile(r"[A-Za-z0-9.\-]+(?::[0-9]+)?")


def _quote(value: str) -> str:
    """Double-quote a git config value so spaces and comment chars (# ;) are
    preserved literally."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _git_global(key: str) -> str | None:
    """Return a host global git config value, or None if git is absent or the
    key is unset."""
    try:
        res = run(["git", "config", "--global", "--get", key])
    except FileNotFoundError:
        LOGGER.warning("git not found on host; skipping git identity")
        return None
    # `git config --get` exits 1 with empty output for an unset key; treat it as
    # empty, not an error.
    return res.stdout.strip() or None


def _rewrite_block(host: str) -> str:
    base = f"https://{host}/"
    return (
        f'[url {_quote(base)}]\n'
        f"\tinsteadOf = git@{host}:\n"
        f"\tinsteadOf = ssh://git@{host}/\n"
    )


def build_overlay(extra_hosts: list[str], include_identity: bool) -> bytes | None:
    """The gitconfig overlay bytes, or None when empty. Raises ValueError for a
    malformed --git-https-rewrite host."""
    sections: list[str] = []

    if include_identity:
        name = _git_global("user.name")
        email = _git_global("user.email")
        identity = "".join(
            f"\t{field} = {_quote(value)}\n"
            for field, value in (("name", name), ("email", email))
            if value
        )
        if identity:
            sections.append(f"[user]\n{identity}")
        else:
            LOGGER.warning(
                "no host git identity (user.name/user.email) found; agent commits "
                "will be unattributed unless set in-repo"
            )

    for host in extra_hosts:
        if not _HOST_RE.fullmatch(host):
            raise ValueError(f"invalid --git-https-rewrite host: {host!r}")
        sections.append(_rewrite_block(host))

    if not sections:
        return None
    return "\n".join(sections).encode("utf-8")
