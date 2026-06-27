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
    """Inputs the orchestrator hands an agent to build its pod contribution.
    Everything an agent needs to assemble its volumes/env/commands lives here,
    so the agent exposes a single build hook instead of many fine-grained ones."""

    cwd: Path
    username: str
    uid: int
    gid: int
    aws_creds_secret_name: str | None
    debug_host_dir: Path | None
    debug: bool
    # Per-run host scratch dir (Session.session_dir); for transient files the
    # agent writes host-side and then mounts (e.g. a sanitized ~/.claude.json).
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
    """Host-side products of prepare(). Returned (not stashed on the agent) so
    there is no ordering landmine and no per-method 'prepare() not called' guard.

    Real secrets live only in `auth_rules` (injected inside the mitm pod) and in
    `secret_payloads` (K8s Secrets); neither ever reaches the agent container in
    its real form."""

    auth_rules: list[dict] = field(default_factory=list)
    secret_payloads: dict[str, dict[str, bytes]] = field(default_factory=dict)


class Agent(ABC):
    """Base class for an agent that runs inside agent-uplink's microVM sandbox.

    A concrete Agent owns:
      - The container image (Dockerfile + default rules) under its own
        package directory.
      - Per-mode auth resolution and the host-side credential dance.
      - The set of K8s Secrets, volumes, and volumeMounts the agent pod needs.
      - Any auth rules the mitmproxy layer must inject.

    Generic concerns (mitmproxy lifecycle, AWS SigV4 re-signing, registry
    bootstrap, namespace lifecycle, NetworkPolicy) live outside subclasses and
    are wired together by `agent_uplink.cli`.

    Lifecycle (called by the CLI in order):
      1. add_cli_args(parser)              — classmethod, registers subparser flags
      2. __init__(args)                    — capture parsed args
      3. discover_aws_profiles()           — extra AWS profiles to spin sidecars for
      4. prepare(session, profiles)        — host-side auth → PreparedAgent
                                             (auth_rules + secret_payloads)
      5. pod_contribution(context)         — PodContribution: env, volumes, mounts,
                                             securityContext, init/exec commands, memory
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

    def default_rules(self) -> list[dict]:
        """Agent-specific allow-list rules, loaded from default_rules.yaml in
        the agent's package directory. Returns [] if the file is absent.

        An instance method (not a classmethod) so a subclass can derive rules
        from instance state; the resolver always calls it on an instance."""
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
        """Host-side prep: refresh OAuth, read keyring, produce in-memory bytes
        for settings/credentials, and return the agent's auth rules + Secret
        payloads. Real secrets stay on the host / inside mitm."""

    def pod_contribution(self, ctx: PodBuildContext) -> PodContribution:
        """Agent-specific pod pieces. Default: drop into an interactive bash with
        the full hardened security context and no extra volumes. Override to add
        volumes/mounts/env, run a different PID 1, or relax hardening (e.g. to
        run an in-pod dockerd)."""
        return PodContribution(
            security_context=hardened_container_security_context(
                uid=ctx.uid, gid=ctx.gid
            ),
            init_command=["sleep", "infinity"],
            command=["bash", "-l"],
        )
