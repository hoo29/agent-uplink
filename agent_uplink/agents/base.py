from __future__ import annotations

import argparse
import inspect
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

import yaml

from ..k8s import hardened_container_security_context
from ..session import Session


@dataclass
class PodBuildContext:
    """Inputs the orchestrator hands an agent to build its pod contribution."""

    cwd: Path
    username: str
    uid: int
    gid: int
    # The mitm proxy the pod egresses through, for tooling that needs explicit
    # proxy config beyond the orchestrator's HTTP(S)_PROXY env.
    proxy_host: str
    proxy_port: int
    aws_creds_secret_name: str | None
    debug_host_dir: Path | None
    debug: bool
    # Per-run host scratch dir, for transient files the agent writes then mounts
    # (e.g. a sanitized ~/.claude.json).
    session_dir: Path


@dataclass
class PodContribution:
    """Agent-specific pieces the orchestrator merges into the agent pod spec.
    Universal concerns (proxy env, namespace, NetworkPolicy) are added by the
    orchestrator, not here."""

    env: dict[str, str] = field(default_factory=dict)
    volumes: list[dict] = field(default_factory=list)
    mounts: list[dict] = field(default_factory=list)
    security_context: dict | None = None
    init_command: list[str] | None = None  # argv for the pod's PID 1
    command: list[str] | None = None  # argv for `kubectl exec -it`
    memory: str = "1Gi"


@dataclass
class PreparedAgent:
    """Host-side products of prepare(). Real secrets live only in `auth_rules`
    (injected inside the mitm pod) and `secret_payloads` (K8s Secrets); neither
    reaches the agent container in its real form."""

    auth_rules: list[dict] = field(default_factory=list)
    secret_payloads: dict[str, dict[str, bytes]] = field(default_factory=dict)


class Agent(ABC):
    """Base class for an agent running in agent-uplink's microVM sandbox. A
    concrete Agent owns its image, auth resolution, Secrets/volumes/mounts, and
    any auth rules mitm must inject; generic concerns (mitm, SigV4, bootstrap,
    NetworkPolicy) are wired by `agent_uplink.cli`.

    Lifecycle, called by the CLI in order:
      1. add_cli_args(parser)       — classmethod, registers subparser flags
      2. __init__(args)
      3. discover_aws_profiles()    — extra AWS profiles to spin sidecars for
      4. prepare(session, profiles) — host-side auth -> PreparedAgent
      5. pod_contribution(context)  — env, volumes, mounts, securityContext, ..."""

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

    def default_rules(self) -> list[dict]:
        """Agent-specific allow-list rules from default_rules.yaml, or [] if
        absent. An instance method so a subclass can derive rules from state."""
        path = self.container_dir() / "default_rules.yaml"
        if not path.exists():
            return []
        data = yaml.safe_load(path.read_text(encoding="utf8")) or {}
        return list(data.get("rules") or [])

    @abstractmethod
    def discover_aws_profiles(self) -> list[str]:
        """AWS profiles the agent needs in addition to `--aws-profiles`."""

    @abstractmethod
    def prepare(self, session: Session, aws_profile_names: list[str]) -> PreparedAgent:
        """Host-side prep: refresh OAuth, read keyring, build settings/credential
        bytes, and return auth rules + Secret payloads. Real secrets stay on the
        host / inside mitm."""

    def pod_contribution(self, ctx: PodBuildContext) -> PodContribution:
        """Agent-specific pod pieces. Default: interactive bash, hardened, no
        extra volumes. Override to add volumes/mounts/env or relax hardening."""
        return PodContribution(
            security_context=hardened_container_security_context(
                uid=ctx.uid, gid=ctx.gid
            ),
            init_command=["sleep", "infinity"],
            command=["bash", "-l"],
        )
