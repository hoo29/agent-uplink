"""Runtime git config overlay for the agent pod.

The agent image bakes /etc/gitconfig with SSH->HTTPS `insteadOf` rewrites for the
default hosts (github.com, gitlab.com, bitbucket.org) and an `include.path` to a
runtime overlay file. This module builds that overlay, which the orchestrator
mounts at the included path when non-empty:

  - extra SSH->HTTPS rewrites for `--git-https-rewrite` hosts (e.g. self-hosted
    GitLab), accumulated with the baked defaults (insteadOf is a multivar), and
  - the host's git identity (user.name / user.email) unless disabled, so the
    agent's commits are attributed correctly.

The overlay carries no secrets — git auth is injected host-side by mitm via the
rules engine — so the Secret it ships in is safe to mount into the agent pod.
"""

from __future__ import annotations

import logging
import re

from .process import run_command

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
        value = run_command(
            ["git", "config", "--global", "--get", key], raise_error=False
        ).strip()
    except FileNotFoundError:
        LOGGER.warning("git not found on host; skipping git identity")
        return None
    return value or None


def _rewrite_block(host: str) -> str:
    base = f"https://{host}/"
    return (
        f'[url {_quote(base)}]\n'
        f"\tinsteadOf = git@{host}:\n"
        f"\tinsteadOf = ssh://git@{host}/\n"
    )


def build_overlay(extra_hosts: list[str], include_identity: bool) -> bytes | None:
    """Build the runtime gitconfig overlay, or None when it would be empty.

    Raises ValueError for a malformed --git-https-rewrite host.
    """
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
