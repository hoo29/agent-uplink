from __future__ import annotations

import argparse
import inspect
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

import yaml

from ..session import Session


class Agent(ABC):
    """Base class for an agent that runs inside agent-uplink's container sandbox.

    A concrete Agent owns:
      - The container image (Dockerfile + entrypoint + default rules) under its
        own package directory.
      - Per-mode auth resolution and the host-side credential dance.
      - The set of host files bind-mounted into its container.
      - Any auth rules that need to be injected at the mitmproxy layer.

    Generic concerns (mitmproxy cert generation, AWS sigv4 sidecars, locked
    secret allocation, the docker network, session lifecycle) live outside
    subclasses and are wired together by `agent_uplink.cli`.

    Lifecycle (called by the CLI in order):
      1. add_cli_args(parser)              — classmethod, registers subparser flags
      2. __init__(args)                    — capture parsed args
      3. discover_aws_profiles()           — extra AWS profiles to spin sidecars for
      4. resolve_auth(session)             — host-side auth (refresh OAuth, read keyring)
      5. write_session_files(session, ...) — settings.json / dummy creds into session dir
      6. auth_rules()                      — mitmproxy rules for this agent's API
      7. build_mounts(...)                 — list of `-v` / `--tmpfs` flags
      8. container_env(...)                — `-e` env vars
    """

    name: ClassVar[str]

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args

    @classmethod
    @abstractmethod
    def add_cli_args(cls, parser: argparse.ArgumentParser) -> None:
        """Register agent-specific CLI flags on the agent's subparser."""

    @classmethod
    def container_dir(cls) -> Path:
        """Directory containing Dockerfile, entrypoint.sh, default_rules.yaml,
        and any cert directory the agent's image build needs."""
        return Path(inspect.getfile(cls)).resolve().parent

    @classmethod
    def default_image(cls) -> str:
        return f"agent-uplink-{cls.name}"

    @property
    def image(self) -> str:
        """Image name; subclasses can override via an `--image` flag whose
        parsed value lives at `args.image`."""
        return getattr(self.args, "image", None) or self.default_image()

    @classmethod
    def default_rules(cls) -> list[dict]:
        """Agent-specific allow-list rules, loaded from default_rules.yaml in
        the agent's package directory. Returns [] if the file is absent."""
        path = cls.container_dir() / "default_rules.yaml"
        if not path.exists():
            return []
        data = yaml.safe_load(path.read_text(encoding="utf8")) or {}
        return list(data.get("rules") or [])

    def memory(self) -> str:
        """Memory limit for the agent container (docker --memory value)."""
        return "1g"

    @abstractmethod
    def discover_aws_profiles(self) -> list[str]:
        """AWS profiles the agent needs in addition to `--aws-profiles`.

        Typically derived from the agent's own config (e.g. Claude reads
        `env.AWS_PROFILE` from ~/.claude/settings.json in bedrock mode). Return
        [] if none."""

    @abstractmethod
    def resolve_auth(self, session: Session) -> None:
        """Host-side auth: refresh tokens, read keyring, write any fake
        credential files into `session.session_dir`. State produced here should
        be stashed on `self` for the later hooks to consume."""

    @abstractmethod
    def write_session_files(
        self,
        session: Session,
        aws_profile_names: list[str],
    ) -> None:
        """Write per-session config files (e.g. settings.json) into
        `session.session_dir`. Called after `resolve_auth` and after AWS
        profiles have been finalised, so settings can reference them."""

    @abstractmethod
    def auth_rules(self) -> list[dict]:
        """mitmproxy rules that inject this agent's auth header(s). Typically
        a single header-injection rule per provider endpoint."""

    @abstractmethod
    def build_mounts(
        self,
        session: Session,
        cwd: Path,
        username: str,
        aws_creds_dir: Path | None,
        mitm_dir: Path,
        debug_host_dir: Path | None,
    ) -> list[str]:
        """`-v ...` / `--tmpfs ...` flags for the agent container."""

    @abstractmethod
    def container_env(self, cwd: Path, debug: bool) -> dict[str, str]:
        """Env vars to inject via `docker run -e KEY=VALUE`."""
