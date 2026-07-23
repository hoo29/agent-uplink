from __future__ import annotations

import argparse
import shlex
from pathlib import Path
from typing import ClassVar

import keyring

from ...k8s import hostpath_volume, secret_volume, tmpfs_volume
from ...session import Session
from ..base import Agent, PodBuildContext, PodContribution, PreparedAgent
from .config import (
    HOST_CLAUDE_DIR,
    HOST_CLAUDE_JSON,
    HOST_MANAGED_SETTINGS,
    claude_md_bytes,
    claude_settings_bytes,
    fake_oauth_credentials_bytes,
    get_bedrock_aws_profile_name,
    load_claude_config,
    load_managed_settings,
    managed_settings_bytes,
    read_anthropic_oauth_credentials,
    refresh_anthropic_oauth_if_expiring,
    sanitized_claude_json_bytes,
)

# settings.json env injected per auth mode (placeholders only; real credentials
# come from mitm injection, see prepare()). anthropic steers the CLI via a fake
# .credentials.json and needs no entry. CLAUDE_CODE_ENABLE_AUTO_MODE=1 is
# required for defaultMode "auto" on Bedrock (Opus 4.7/4.8 only; other models
# fall back to the default mode, bypassPermissions still via Shift+Tab).
_AUTH_MODE_ENV: dict[str, dict[str, str]] = {
    "bedrock": {
        "AWS_BEARER_TOKEN_BEDROCK": "placeholder",
        "CLAUDE_CODE_ENABLE_AUTO_MODE": "1",
    },
}

_SETTINGS_SECRET = "claude-settings"
_FAKE_CREDS_SECRET = "claude-fake-creds"
_CLAUDE_MD_SECRET = "claude-md"
_MANAGED_SETTINGS_SECRET = "claude-managed-settings"
# Where the pod mounts managed settings — the path Claude reads them from, so its
# precedence over the user settings applies.
_MANAGED_SETTINGS_PATH = "/etc/claude-code/managed-settings.json"


class ClaudeAgent(Agent):
    """Claude Code CLI agent. Two auth modes, both injecting the real bearer via
    mitm so it never enters the container:
      --anthropic: OAuth bearer from ~/.claude/.credentials.json; container sees
                   a fake credentials.json.
      --bedrock:   bearer from the host keyring (`bedrock`/`key`), injected on
                   bedrock-runtime.<region>.amazonaws.com; container sees
                   AWS_BEARER_TOKEN_BEDROCK=placeholder."""

    name: ClassVar[str] = "claude"

    def __init__(self, args: argparse.Namespace) -> None:
        super().__init__(args)
        # The --anthropic/--bedrock group is not argparse-required so the mode
        # can come from a .agent-uplink.yaml (auth_mode:/anthropic:/bedrock:)
        # instead; enforce that one was supplied by either route here.
        if args.auth_mode is None:
            raise SystemExit(
                "agent-uplink claude: an auth mode is required; pass --anthropic "
                "or --bedrock, or set auth_mode in .agent-uplink.yaml"
            )
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
        # Not argparse-required: the mode may come from .agent-uplink.yaml
        # instead. __init__ enforces exactly one; the group makes the two flags
        # mutually exclusive on the CLI.
        mode_group = parser.add_mutually_exclusive_group(required=False)
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
        parser.add_argument(
            "--maven",
            action="store_true",
            help="Mount the host's ~/.m2 (settings.xml read-only, repository "
            "read-write) and point the in-pod Maven JVM at mitm. Off by default; "
            "equivalent to --mount-ro ~/.m2/settings.xml --mount-rw ~/.m2/repository "
            "plus the proxy env Maven needs.",
        )
        parser.add_argument(
            "claude_args",
            nargs="*",
            metavar="-- ARG",
            help="Extra args passed verbatim to the `claude` CLI in the pod, after "
            "a `--` separator (e.g. `-- --resume <id>`, `-- -p \"prompt\"`). The pod "
            "defaults to permission mode \"auto\"; --allow-dangerously-skip-permissions "
            "is always added so bypassPermissions stays reachable via Shift+Tab. Pass "
            "--permission-mode here to override the default.",
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
                    "hosts": [r"api\.anthropic\.com"],
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
                    "hosts": [r"bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com"],
                    "inject": {"headers": {"Authorization": f"Bearer {token}"}},
                }
            )

        auth_env = dict(_AUTH_MODE_ENV.get(self._auth_mode, {}))
        settings = claude_settings_bytes(self._config(), auth_env)
        secret_payloads[_SETTINGS_SECRET] = {"settings.json": settings}

        # Enterprise managed settings, when the host has them (see
        # _volumes_and_mounts).
        managed = load_managed_settings()
        if managed is not None:
            secret_payloads[_MANAGED_SETTINGS_SECRET] = {
                "managed-settings.json": managed_settings_bytes(managed, auth_env)
            }

        # CLAUDE.md = host copy + sandbox guidance, via Secret (see
        # _volumes_and_mounts).
        secret_payloads[_CLAUDE_MD_SECRET] = {"CLAUDE.md": claude_md_bytes()}

        return PreparedAgent(auth_rules=auth_rules, secret_payloads=secret_payloads)

    def pod_contribution(self, ctx: PodBuildContext) -> PodContribution:
        volumes, mounts = self._volumes_and_mounts(ctx)
        return PodContribution(
            env=self._container_env(ctx),
            volumes=volumes,
            mounts=mounts,
            security_context=self._container_security_context(),
            init_command=["/usr/local/bin/dockerd-entrypoint.sh"],
            command=self._container_command(
                ctx.username, ctx.debug, self.args.claude_args
            ),
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

        # A redacted copy of ~/.claude.json (MCP Authorization headers replaced)
        # mounted read-write from the session dir, so the host file is untouched
        # and the bearer is re-injected via mitm rules. Mode 0600 since env-based
        # stdio-server secrets remain in the copy (see sanitized_claude_json_bytes).
        session_claude_json = ctx.session_dir / ".claude.json"
        session_claude_json.touch(mode=0o600)
        session_claude_json.write_bytes(sanitized_claude_json_bytes(HOST_CLAUDE_JSON))

        volumes: list[dict] = [
            secret_volume("settings", _SETTINGS_SECRET),
            hostpath_volume("workdir", str(cwd)),
            hostpath_volume(
                "claude-projects", str(host_project_dir), hp_type="DirectoryOrCreate"
            ),
            hostpath_volume(
                "claude-json-host", str(session_claude_json), hp_type="File"
            ),
        ]

        mounts: list[dict] = [
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

        # Only when the host has an enterprise policy; prepare() ships the Secret
        # under the same condition.
        if HOST_MANAGED_SETTINGS.is_file():
            volumes.append(
                secret_volume("managed-settings", _MANAGED_SETTINGS_SECRET)
            )
            mounts.append(
                {
                    "name": "managed-settings",
                    "mountPath": _MANAGED_SETTINGS_PATH,
                    "subPath": "managed-settings.json",
                    "readOnly": True,
                }
            )

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

        # --maven: settings.xml read-only, the local repository read-write so
        # downloaded artifacts land in the host's real repo.
        if getattr(self.args, "maven", False):
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

        # Registry auth (ECR, etc.) comes from mitm header injection, so
        # ~/.docker/config.json is not mounted — no registry creds in the pod.

        # Both need tmpfs even with a writable rootfs. /var/lib/docker is the
        # nested dockerd's overlayfs upperdir: kata's virtio-fs is rejected as one
        # (EINVAL), tmpfs supports overlay natively (cost: image layers held in
        # pod memory, see memory()). /run holds the docker socket, unreliable on
        # virtio-fs.
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

    def _container_env(self, ctx: PodBuildContext) -> dict[str, str]:
        # Only relevant with --maven; otherwise no-op.
        if not getattr(self.args, "maven", False):
            return {}
        # The Maven JVM ignores HTTPS_PROXY, so point its HTTP client at mitm.
        host, port = ctx.proxy_host, ctx.proxy_port
        return {
            "MAVEN_OPTS": (
                f"-Dhttp.proxyHost={host} -Dhttp.proxyPort={port} "
                f"-Dhttps.proxyHost={host} -Dhttps.proxyPort={port} "
                "-Dhttp.nonProxyHosts=localhost|127.0.0.1"
            ),
            # Lets ${env.CODEARTIFACT_AUTH_TOKEN} in settings.xml expand; the
            # value is irrelevant, mitm overwrites the Authorization header.
            "CODEARTIFACT_AUTH_TOKEN": "placeholder",
        }

    def _container_security_context(self) -> dict:
        # dockerd needs iptables/cgroups/namespaces/mounts, so privileged + root +
        # unconfined seccomp is the minimum; the grant is bounded by the Kata guest
        # kernel, not the host. readOnlyRootFilesystem is NOT set: with CAP_SYS_ADMIN
        # the agent can remount rw at will, so it would only add friction, and the
        # trust boundary is the guest kernel plus the NetworkPolicy egress lock.
        # The non-root support pods (mitm/sigv4) do keep it.
        return {
            "privileged": True,
            "allowPrivilegeEscalation": True,
            "seccompProfile": {"type": "Unconfined"},
        }

    def _container_command(
        self, username: str, debug: bool, extra_args: list[str]
    ) -> list[str]:
        # --allow-dangerously-skip-permissions adds bypassPermissions to the
        # Shift+Tab cycle without activating it (the session starts in defaultMode
        # "auto"), keeping bypass reachable on models that don't support auto. Args
        # are shell-quoted so values can't break out of the `bash -lc` string.
        argv = (["-d"] if debug else []) + ["--allow-dangerously-skip-permissions"]
        argv += extra_args
        claude_args = " ".join(shlex.quote(a) for a in argv)
        # PID 1 is root (to start dockerd); runuser drops to the agent user and
        # re-inits HOME/USER/groups (incl. `docker`, for the socket) without PAM.
        return [
            "runuser",
            "-u",
            username,
            "--",
            "bash",
            "-lc",
            f'cd "$WORKDIR" && exec claude {claude_args}',
        ]
