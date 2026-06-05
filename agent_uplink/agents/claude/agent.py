from __future__ import annotations

import argparse
from pathlib import Path
from typing import ClassVar

import keyring

from ...k8s import hostpath_volume, secret_volume, tmpfs_volume
from ...session import Session
from ..base import Agent, PodBuildContext, PodContribution, PreparedAgent
from .config import (
    HOST_CLAUDE_DIR,
    claude_md_bytes,
    claude_settings_bytes,
    fake_oauth_credentials_bytes,
    get_bedrock_aws_profile_name,
    load_claude_config,
    read_anthropic_oauth_credentials,
    refresh_anthropic_oauth_if_expiring,
)

# Settings.json env injected per auth mode. anthropic mode steers the CLI via
# a fake .credentials.json instead, so it has no entry here. Real credentials
# are added by mitm header injection (see prepare()) and never enter the
# container.
_AUTH_MODE_ENV: dict[str, dict[str, str]] = {
    "bedrock": {"AWS_BEARER_TOKEN_BEDROCK": "placeholder"},
}

_SETTINGS_SECRET = "claude-settings"
_FAKE_CREDS_SECRET = "claude-fake-creds"
_CLAUDE_MD_SECRET = "claude-md"


class ClaudeAgent(Agent):
    """Agent implementation for the Claude Code CLI.

    Supports two auth modes:
      --anthropic: real OAuth bearer is read from the host's
                   ~/.claude/.credentials.json and injected by mitm;
                   the container sees a fake credentials.json.
      --bedrock:   bearer is read from the host keyring (`bedrock`/`key`) and
                   injected by mitm on bedrock-runtime.<region>.amazonaws.com;
                   the container sees AWS_BEARER_TOKEN_BEDROCK=placeholder.
    """

    name: ClassVar[str] = "claude"

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__(args)
        self._auth_mode: str = args.auth_mode
        self._claude_config: dict | None = None

    @classmethod
    def add_cli_args(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-i",
            "--image",
            type=str,
            default=cls.default_image_repo(),
            help="Claude image repo (registry endpoint + :tag added by orchestrator)",
        )
        mode_group = parser.add_mutually_exclusive_group(required=True)
        mode_group.add_argument(
            "--anthropic",
            dest="auth_mode",
            action="store_const",
            const="anthropic",
            help="Configure container for anthropic OAuth auth",
        )
        mode_group.add_argument(
            "--bedrock",
            dest="auth_mode",
            action="store_const",
            const="bedrock",
            help="Configure container for AWS Bedrock bearer-token auth",
        )

    def _config(self) -> dict:
        if self._claude_config is None:
            self._claude_config = load_claude_config()
        return self._claude_config

    def discover_aws_profiles(self) -> list[str]:
        if self._auth_mode != "bedrock":
            return []
        profile = get_bedrock_aws_profile_name(self._config())
        return [profile] if profile else []

    def prepare(self, session: Session, aws_profile_names: list[str]) -> PreparedAgent:
        auth_rules: list[dict] = []
        secret_payloads: dict[str, dict[str, bytes]] = {}

        if self._auth_mode == "anthropic":
            refresh_anthropic_oauth_if_expiring()
            fake_creds, oauth_token = fake_oauth_credentials_bytes(
                read_anthropic_oauth_credentials()
            )
            secret_payloads[_FAKE_CREDS_SECRET] = {".credentials.json": fake_creds}
            auth_rules.append(
                {
                    "name": "anthropic-auth",
                    "host": r"api\.anthropic\.com",
                    "inject": {"headers": {"Authorization": f"Bearer {oauth_token}"}},
                }
            )
        elif self._auth_mode == "bedrock":
            token = keyring.get_password("bedrock", "key")
            if token is None:
                raise RuntimeError(
                    "bedrock bearer token not found in keyring; "
                    "run: keyring set bedrock key"
                )
            auth_rules.append(
                {
                    "name": "bedrock-auth",
                    "host": r"bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com",
                    "inject": {"headers": {"Authorization": f"Bearer {token}"}},
                }
            )

        auth_env = dict(_AUTH_MODE_ENV.get(self._auth_mode, {}))
        settings = claude_settings_bytes(self._config(), auth_env)
        secret_payloads[_SETTINGS_SECRET] = {"settings.json": settings}

        # CLAUDE.md = host's copy + appended sandbox guidance, shipped via Secret
        # so the host file is left untouched (see _volumes_and_mounts).
        secret_payloads[_CLAUDE_MD_SECRET] = {"CLAUDE.md": claude_md_bytes()}

        return PreparedAgent(auth_rules=auth_rules, secret_payloads=secret_payloads)

    def pod_contribution(self, ctx: PodBuildContext) -> PodContribution:
        volumes, mounts = self._volumes_and_mounts(ctx)
        return PodContribution(
            env=self._container_env(ctx.cwd),
            volumes=volumes,
            mounts=mounts,
            security_context=self._container_security_context(),
            init_command=["/usr/local/bin/dockerd-entrypoint.sh"],
            command=self._container_command(ctx.username, ctx.debug),
            # tmpfs /var/lib/docker counts against this; default 1Gi can't hold
            # even a small image alongside the agent process.
            memory="4Gi",
        )

    def _volumes_and_mounts(
        self, ctx: PodBuildContext
    ) -> tuple[list[dict], list[dict]]:
        cwd, username = ctx.cwd, ctx.username
        project_id = str(cwd).replace("/", "-")
        host_project_dir = HOST_CLAUDE_DIR / "projects" / project_id
        host_project_dir.mkdir(parents=True, exist_ok=True)

        container_home = f"/home/{username}"
        claude_dir = f"{container_home}/.claude"

        volumes: list[dict] = [
            tmpfs_volume("tmp", "200Mi"),
            tmpfs_volume("xdg-apps", "16Mi"),
            tmpfs_volume("claude-home", "200Mi"),
            secret_volume("settings", _SETTINGS_SECRET),
            hostpath_volume("workdir", str(cwd)),
            hostpath_volume(
                "claude-projects", str(host_project_dir), hp_type="DirectoryOrCreate"
            ),
            hostpath_volume(
                "claude-json-host",
                str(Path.home() / ".claude.json"),
                hp_type="FileOrCreate",
            ),
        ]

        mounts: list[dict] = [
            {"name": "tmp", "mountPath": "/tmp"},
            {
                "name": "xdg-apps",
                "mountPath": f"{container_home}/.local/share/applications",
            },
            {"name": "claude-home", "mountPath": claude_dir},
            {
                "name": "settings",
                "mountPath": f"{claude_dir}/settings.json",
                "subPath": "settings.json",
                "readOnly": True,
            },
            {"name": "workdir", "mountPath": str(cwd)},
            {
                "name": "claude-projects",
                "mountPath": f"{claude_dir}/projects/{project_id}",
            },
            {"name": "claude-json-host", "mountPath": f"{container_home}/.claude.json"},
        ]

        # anthropic mode ships a fake .credentials.json (see prepare()); mount it.
        if self._auth_mode == "anthropic":
            volumes.append(secret_volume("fake-creds", _FAKE_CREDS_SECRET))
            mounts.append(
                {
                    "name": "fake-creds",
                    "mountPath": f"{claude_dir}/.credentials.json",
                    "subPath": ".credentials.json",
                    "readOnly": True,
                }
            )

        if ctx.aws_creds_secret_name is not None:
            volumes.append(secret_volume("aws-creds", ctx.aws_creds_secret_name))
            mounts.append(
                {
                    "name": "aws-creds",
                    "mountPath": f"{container_home}/.aws/credentials",
                    "subPath": "credentials",
                    "readOnly": True,
                }
            )

        # CLAUDE.md is shipped via Secret (host copy + sandbox guidance), not
        # mounted from the host (see prepare()).
        volumes.append(secret_volume("claude-md", _CLAUDE_MD_SECRET))
        mounts.append(
            {
                "name": "claude-md",
                "mountPath": f"{claude_dir}/CLAUDE.md",
                "subPath": "CLAUDE.md",
                "readOnly": True,
            }
        )

        for name in ["commands", "skills", "plugins", "history.jsonl"]:
            host_path = HOST_CLAUDE_DIR / name
            if not host_path.exists():
                continue
            vol_name = f"claude-{name.replace('.', '-').lower()}"
            hp_type = "Directory" if host_path.is_dir() else "File"
            volumes.append(hostpath_volume(vol_name, str(host_path), hp_type=hp_type))
            mounts.append(
                {
                    "name": vol_name,
                    "mountPath": f"{claude_dir}/{name}",
                    "readOnly": name != "history.jsonl",
                }
            )

        # Maven: settings.xml read-only, the local repository read-write so the
        # agent writes downloaded artifacts straight into the host's real repo.
        # Gated on the host paths existing, so non-Java sessions are unaffected.
        m2_dir = Path.home() / ".m2"
        m2_settings = m2_dir / "settings.xml"
        if m2_settings.exists():
            volumes.append(
                hostpath_volume("m2-settings", str(m2_settings), hp_type="File")
            )
            mounts.append(
                {
                    "name": "m2-settings",
                    "mountPath": f"{container_home}/.m2/settings.xml",
                    "readOnly": True,
                }
            )
        if m2_dir.is_dir():
            volumes.append(
                hostpath_volume(
                    "m2-repo",
                    str(m2_dir / "repository"),
                    hp_type="DirectoryOrCreate",
                )
            )
            mounts.append(
                {"name": "m2-repo", "mountPath": f"{container_home}/.m2/repository"}
            )

        # Private registry auth (ECR, etc.) is handled by mitm rules injecting
        # the Authorization header on registry hosts, so ~/.docker/config.json
        # is deliberately not mounted — no registry credentials enter the pod.

        # /var/lib/docker: tmpfs emptyDir. Disk-backed emptyDir lands on
        # kata's virtio-fs, which the kernel won't accept as an overlayfs
        # upperdir (EINVAL). tmpfs supports overlay natively. Cost: image
        # layers + container rootfs are held in pod memory (see memory()).
        # /run: tmpfs for the docker socket + pidfile. RoFS stays on; these
        # are the only writable paths dockerd touches.
        volumes.append(tmpfs_volume("docker-lib", "2Gi"))
        volumes.append(tmpfs_volume("run", "64Mi"))
        mounts.append({"name": "docker-lib", "mountPath": "/var/lib/docker"})
        mounts.append({"name": "run", "mountPath": "/run"})

        if ctx.debug_host_dir is not None:
            volumes.append(
                hostpath_volume(
                    "claude-debug",
                    str(ctx.debug_host_dir),
                    hp_type="DirectoryOrCreate",
                )
            )
            mounts.append({"name": "claude-debug", "mountPath": f"{claude_dir}/debug"})

        return volumes, mounts

    def _container_env(self, cwd: Path) -> dict[str, str]:
        # Only relevant when the host has a Maven setup; otherwise no-op.
        if not (Path.home() / ".m2").is_dir():
            return {}
        # The Maven JVM does not read HTTPS_PROXY (unlike dockerd), and the pod
        # can egress only to mitm. Point Maven's HTTP client at mitm explicitly.
        # Host mitm:8080 mirrors cli.PROXY_PORT.
        return {
            "MAVEN_OPTS": (
                "-Dhttp.proxyHost=mitm -Dhttp.proxyPort=8080 "
                "-Dhttps.proxyHost=mitm -Dhttps.proxyPort=8080 "
                "-Dhttp.nonProxyHosts=localhost|127.0.0.1"
            ),
            # Lets ${env.CODEARTIFACT_AUTH_TOKEN} in settings.xml expand cleanly;
            # the value is irrelevant — mitm overwrites the Authorization header.
            "CODEARTIFACT_AUTH_TOKEN": "placeholder",
        }

    def _container_security_context(self) -> dict:
        # dockerd needs to manage iptables, cgroups, namespaces, mounts —
        # privileged + root + unconfined seccomp is the minimum. PID 1 runs
        # as root (image has no USER directive); the entrypoint launches
        # dockerd then drops to ${USERNAME}. RoFS is preserved; everything
        # dockerd writes to lives under emptyDir mounts added by
        # _volumes_and_mounts(). The grant is bounded by the Kata guest
        # kernel — the host kernel is unaffected.
        return {
            "privileged": True,
            "readOnlyRootFilesystem": True,
            "allowPrivilegeEscalation": True,
            "seccompProfile": {"type": "Unconfined"},
        }

    def _container_command(self, username: str, debug: bool) -> list[str]:
        flag = (
            "-d --dangerously-skip-permissions"
            if debug
            else "--dangerously-skip-permissions"
        )
        # PID 1 runs as root so it can start dockerd; drop to the agent user
        # for the interactive session. runuser re-initialises HOME/USER/groups
        # to the target user (including the `docker` group, so the socket is
        # usable) without needing PAM.
        return [
            "runuser",
            "-u",
            username,
            "--",
            "bash",
            "-lc",
            f'cd "$WORKDIR" && exec claude {flag}',
        ]
