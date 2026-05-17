from __future__ import annotations

import argparse
from pathlib import Path
from typing import ClassVar

import keyring

from ...k8s import hostpath_volume, secret_volume, tmpfs_volume
from ...session import Session
from ..base import Agent
from .config import (
    HOST_CLAUDE_DIR,
    claude_settings_bytes,
    fake_oauth_credentials_bytes,
    get_bedrock_aws_profile_name,
    load_claude_config,
    read_anthropic_oauth_credentials,
    refresh_anthropic_oauth_if_expiring,
)

# Settings.json env injected per auth mode. anthropic mode steers the CLI via
# a fake .credentials.json instead, so it has no entry here. Real credentials
# are added by mitm header injection (see auth_rules) and never enter the
# container.
_AUTH_MODE_ENV: dict[str, dict[str, str]] = {
    "bedrock": {"AWS_BEARER_TOKEN_BEDROCK": "placeholder"},
}

_SETTINGS_SECRET = "claude-settings"
_FAKE_CREDS_SECRET = "claude-fake-creds"


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
        self._oauth_token: str | None = None
        self._bedrock_token: str | None = None
        self._fake_creds: bytes | None = None
        self._settings: bytes | None = None

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

    def prepare(self, session: Session, aws_profile_names: list[str]) -> None:
        if self._auth_mode == "anthropic":
            refresh_anthropic_oauth_if_expiring()
            self._fake_creds, self._oauth_token = fake_oauth_credentials_bytes(
                read_anthropic_oauth_credentials()
            )
        elif self._auth_mode == "bedrock":
            token = keyring.get_password("bedrock", "key")
            if token is None:
                raise RuntimeError(
                    "bedrock bearer token not found in keyring; "
                    "run: keyring set bedrock key"
                )
            self._bedrock_token = token

        auth_env = dict(_AUTH_MODE_ENV.get(self._auth_mode, {}))
        self._settings = claude_settings_bytes(self._config(), auth_env)

    def auth_rules(self) -> list[dict]:
        if self._auth_mode == "anthropic":
            if self._oauth_token is None:
                raise RuntimeError("prepare() was not called")
            return [
                {
                    "name": "anthropic-auth",
                    "host": r"api\.anthropic\.com",
                    "inject": {
                        "headers": {"Authorization": f"Bearer {self._oauth_token}"}
                    },
                }
            ]
        if self._auth_mode == "bedrock":
            if self._bedrock_token is None:
                raise RuntimeError("prepare() was not called")
            return [
                {
                    "name": "bedrock-auth",
                    "host": r"bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com",
                    "inject": {
                        "headers": {"Authorization": f"Bearer {self._bedrock_token}"}
                    },
                }
            ]
        return []

    def secret_payloads(self) -> dict[str, dict[str, bytes]]:
        if self._settings is None:
            raise RuntimeError("prepare() was not called")
        payloads: dict[str, dict[str, bytes]] = {
            _SETTINGS_SECRET: {"settings.json": self._settings},
        }
        if self._fake_creds is not None:
            payloads[_FAKE_CREDS_SECRET] = {".credentials.json": self._fake_creds}
        return payloads

    def volumes_and_mounts(
        self,
        cwd: Path,
        username: str,
        aws_creds_secret_name: str | None,
        debug_host_dir: Path | None,
    ) -> tuple[list[dict], list[dict]]:
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

        if self._fake_creds is not None:
            volumes.append(secret_volume("fake-creds", _FAKE_CREDS_SECRET))
            mounts.append(
                {
                    "name": "fake-creds",
                    "mountPath": f"{claude_dir}/.credentials.json",
                    "subPath": ".credentials.json",
                    "readOnly": True,
                }
            )

        if aws_creds_secret_name is not None:
            volumes.append(secret_volume("aws-creds", aws_creds_secret_name))
            mounts.append(
                {
                    "name": "aws-creds",
                    "mountPath": f"{container_home}/.aws/credentials",
                    "subPath": "credentials",
                    "readOnly": True,
                }
            )

        for name in ["CLAUDE.md", "commands", "skills", "history.jsonl"]:
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

        if debug_host_dir is not None:
            volumes.append(
                hostpath_volume(
                    "claude-debug", str(debug_host_dir), hp_type="DirectoryOrCreate"
                )
            )
            mounts.append({"name": "claude-debug", "mountPath": f"{claude_dir}/debug"})

        return volumes, mounts

    def memory(self) -> str:
        # tmpfs /var/lib/docker counts against this; default 1Gi can't hold
        # even a small image alongside the agent process.
        return "4Gi"

    def container_security_context(self, uid: int, gid: int) -> dict:
        # dockerd needs to manage iptables, cgroups, namespaces, mounts —
        # privileged + root + unconfined seccomp is the minimum. PID 1 runs
        # as root (image has no USER directive); the entrypoint launches
        # dockerd then drops to ${USERNAME}. RoFS is preserved; everything
        # dockerd writes to lives under emptyDir mounts added by
        # volumes_and_mounts(). The grant is bounded by the Kata guest
        # kernel — the host kernel is unaffected.
        return {
            "privileged": True,
            "readOnlyRootFilesystem": True,
            "allowPrivilegeEscalation": True,
            "seccompProfile": {"type": "Unconfined"},
        }

    def container_init_command(self) -> list[str]:
        return ["/usr/local/bin/dockerd-entrypoint.sh"]

    def container_command(self, username: str, debug: bool) -> list[str]:
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
