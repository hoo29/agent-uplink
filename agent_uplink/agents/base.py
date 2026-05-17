from __future__ import annotations

import argparse
import inspect
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

import yaml

from ..session import Session


class Agent(ABC):
    """Base class for an agent that runs inside agent-uplink's microVM sandbox.

    A concrete Agent owns:
      - The container image (Dockerfile + default rules) under its own
        package directory.
      - Per-mode auth resolution and the host-side credential dance.
      - The set of K8s Secrets, volumes, and volumeMounts the agent pod needs.
      - Any auth rules the mitmproxy layer must inject.

    Generic concerns (mitmproxy lifecycle, aws-sigv4-proxy sidecars, registry
    bootstrap, namespace lifecycle, NetworkPolicy) live outside subclasses and
    are wired together by `agent_uplink.cli`.

    Lifecycle (called by the CLI in order):
      1. add_cli_args(parser)         — classmethod, registers subparser flags
      2. __init__(args)               — capture parsed args
      3. discover_aws_profiles()      — extra AWS profiles to spin sidecars for
      4. prepare(session, profiles)   — host-side auth + in-memory config bytes
      5. auth_rules()                 — mitm rules for this agent's API
      6. secret_payloads()            — per-agent K8s Secrets {name: {file: bytes}}
      7. volumes_and_mounts(...)      — pod volumes + volumeMounts
      8. container_env(...)           — agent-specific env vars
      9. container_command(debug)     — argv for `kubectl exec`
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
        """Directory containing Dockerfile, default_rules.yaml, etc."""
        return Path(inspect.getfile(cls)).resolve().parent

    @classmethod
    def default_image_repo(cls) -> str:
        """Image *repo* (not the full localhost:5000/... ref). The orchestrator
        prepends the registry endpoint and appends the tag."""
        return f"agent-uplink-{cls.name}"

    @property
    def image_repo(self) -> str:
        return getattr(self.args, "image", None) or self.default_image_repo()

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
        return "1Gi"

    @abstractmethod
    def discover_aws_profiles(self) -> list[str]:
        """AWS profiles the agent needs in addition to `--aws-profiles`."""

    @abstractmethod
    def prepare(self, session: Session, aws_profile_names: list[str]) -> None:
        """Host-side prep: refresh OAuth, read keyring, produce in-memory
        bytes for settings/credentials. Stash anything later methods need
        on `self`."""

    @abstractmethod
    def auth_rules(self) -> list[dict]:
        """mitm rules injecting this agent's auth header(s)."""

    @abstractmethod
    def secret_payloads(self) -> dict[str, dict[str, bytes]]:
        """K8s Secrets this agent needs, keyed by secret name. Values are
        maps of filename → contents. The orchestrator creates these in the
        session namespace before the pod starts."""

    @abstractmethod
    def volumes_and_mounts(
        self,
        cwd: Path,
        username: str,
        aws_creds_secret_name: str | None,
        debug_host_dir: Path | None,
    ) -> tuple[list[dict], list[dict]]:
        """Pod-spec `volumes` and the container's `volumeMounts`."""

    def container_env(self, cwd: Path, debug: bool) -> dict[str, str]:
        """Agent-specific env vars. Universal vars (HTTPS_PROXY, WORKDIR,
        USERNAME) are set by the orchestrator."""
        return {}

    def container_command(self, debug: bool) -> list[str]:
        """Argv for `kubectl exec -it agent -- ...`. Override to launch your
        CLI directly; default drops into an interactive bash."""
        return ["bash", "-l"]
