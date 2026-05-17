from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import ClassVar

import keyring

from ...session import Session
from ..base import Agent
from .config import (
    HOST_CLAUDE_DIR,
    get_bedrock_aws_profile_name,
    load_claude_config,
    read_anthropic_oauth_credentials,
    refresh_anthropic_oauth_if_expiring,
    write_claude_settings,
    write_fake_oauth_credentials,
)

# Settings.json env injected per auth mode. anthropic mode steers the CLI via
# a fake .credentials.json instead, so it has no entry here. Real credentials
# are added by mitmproxy header injection (see auth_rules) and never enter
# the container.
_AUTH_MODE_ENV: dict[str, dict[str, str]] = {
    "bedrock": {"AWS_BEARER_TOKEN_BEDROCK": "placeholder"},
}


class ClaudeAgent(Agent):
    """Agent implementation for the Claude Code CLI.

    Supports two auth modes:
      --anthropic: real OAuth bearer is read from the host's
                   ~/.claude/.credentials.json and injected by mitmproxy;
                   the container sees a fake credentials.json.
      --bedrock:   bearer is read from the host keyring (`bedrock`/`key`) and
                   injected by mitmproxy on bedrock-runtime.<region>.amazonaws.com;
                   the container sees AWS_BEARER_TOKEN_BEDROCK=placeholder.
    """

    name: ClassVar[str] = "claude"

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__(args)
        self._auth_mode: str = args.auth_mode
        self._claude_config: dict | None = None
        self._oauth_token: str | None = None
        self._bedrock_token: str | None = None
        self._fake_creds_path: Path | None = None
        self._settings_path: Path | None = None

    @classmethod
    def add_cli_args(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "-i",
            "--image",
            type=str,
            default=cls.default_image(),
            help="Claude container image name",
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

    def resolve_auth(self, session: Session) -> None:
        if self._auth_mode == "anthropic":
            refresh_anthropic_oauth_if_expiring()
            real_creds = read_anthropic_oauth_credentials()
            self._fake_creds_path, self._oauth_token = write_fake_oauth_credentials(
                real_creds, session.session_dir
            )
        elif self._auth_mode == "bedrock":
            token = keyring.get_password("bedrock", "key")
            if token is None:
                raise RuntimeError(
                    "bedrock bearer token not found in keyring; "
                    "run: keyring set bedrock key"
                )
            self._bedrock_token = token

    def write_session_files(
        self, session: Session, aws_profile_names: list[str]
    ) -> None:
        auth_env = dict(_AUTH_MODE_ENV.get(self._auth_mode, {}))
        self._settings_path = write_claude_settings(
            self._config(), session.session_dir, auth_env
        )

    def auth_rules(self) -> list[dict]:
        if self._auth_mode == "anthropic":
            if self._oauth_token is None:
                raise RuntimeError("resolve_auth() was not called")
            return [
                {
                    "name": "anthropic-auth",
                    "host": r"api\.anthropic\.com",
                    "inject": {
                        "headers": {"Authorization": f"Bearer {self._oauth_token}"},
                    },
                }
            ]
        if self._auth_mode == "bedrock":
            if self._bedrock_token is None:
                raise RuntimeError("resolve_auth() was not called")
            return [
                {
                    "name": "bedrock-auth",
                    "host": r"bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com",
                    "inject": {
                        "headers": {"Authorization": f"Bearer {self._bedrock_token}"},
                    },
                }
            ]
        return []

    def build_mounts(
        self,
        session: Session,
        cwd: Path,
        username: str,
        aws_creds_dir: Path | None,
        mitm_dir: Path,
        debug_host_dir: Path | None,
    ) -> list[str]:
        if self._settings_path is None:
            raise RuntimeError("write_session_files() was not called")

        project_id = str(cwd).replace("/", "-")
        host_project_dir = HOST_CLAUDE_DIR / "projects" / project_id
        host_project_dir.mkdir(parents=True, exist_ok=True)

        container_home = Path("/home") / username
        claude_dir = container_home / ".claude"
        uid, gid = os.getuid(), os.getgid()

        mounts: list[str] = [
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=200m",
            "--tmpfs",
            f"{container_home / '.local' / 'share' / 'applications'}:rw,noexec,nosuid,size=200m",
            "--tmpfs",
            f"{claude_dir}:rw,noexec,nosuid,size=200m,uid={uid},gid={gid}",
        ]

        def vol(host: Path, container: str, mode: str | None = None) -> None:
            spec = f"{host}:{container}" if mode is None else f"{host}:{container}:{mode}"
            mounts.extend(["-v", spec])

        vol(self._settings_path, f"{claude_dir}/settings.json", "ro")
        vol(mitm_dir, "/mnt/certs", "ro")
        vol(host_project_dir, f"{claude_dir}/projects/{project_id}", "rw")
        vol(Path.home() / ".claude.json", f"{container_home}/.claude.json", "rw")
        vol(session.socket_path, "/mnt/socket/uplink.sock")
        vol(cwd, str(cwd), "rw")

        for name in ["CLAUDE.md", "commands", "skills"]:
            host_path = HOST_CLAUDE_DIR / name
            if host_path.exists():
                vol(host_path, f"{claude_dir}/{name}", "ro")
        for name in ["history.jsonl"]:
            host_path = HOST_CLAUDE_DIR / name
            if host_path.exists():
                vol(host_path, f"{claude_dir}/{name}", "rw")

        if aws_creds_dir is not None:
            vol(aws_creds_dir, str(container_home / ".aws"), "ro")

        if self._fake_creds_path is not None:
            vol(self._fake_creds_path, f"{claude_dir}/.credentials.json", "ro")

        if debug_host_dir is not None:
            vol(debug_host_dir, f"{claude_dir}/debug", "rw")

        return mounts

    def container_env(self, cwd: Path, debug: bool) -> dict[str, str]:
        env = {"WORKDIR": str(cwd)}
        if debug:
            env["AGENT_UPLINK_DEBUG"] = "1"
        return env
