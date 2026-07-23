"""SSH agent-forwarding relay.

Private keys live in a dedicated holder pod running `ssh-agent`; the agent pod
reaches it over a socat TCP bridge and only ever obtains signatures. The holder
is a separate pod (not a sidecar) because the privileged agent's CAP_SYS_ADMIN
could read a same-pod process's memory — same trust model as the mitm pod.

Host->key mapping stays client-side: the user's `config` and derived public keys
are mounted into the agent pod's ~/.ssh, so `IdentityFile ~/.ssh/<name>.pub` +
`IdentitiesOnly yes` pins one key to a host. Public keys are derived from the
private half (so they can't drift), which doubles as a passphraseless check."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# A file carrying this PEM marker is always treated as a private key (kept off
# the agent pod), regardless of its name.
_PRIVATE_KEY_MARKER = b"PRIVATE KEY-----"

# Non-key files for the agent pod's ~/.ssh. `known_hosts` is excluded: mounted
# read-only it would block ssh appending host keys (EROFS); ssh makes its own.
_CONFIG_FILES = frozenset({"config"})


@dataclass
class SshAgentPlan:
    """Split of a host key dir: `private_keys` become the holder's Secret;
    `agent_files` (derived public keys + config) go to the agent pod's ~/.ssh."""

    private_keys: dict[str, bytes]
    agent_files: dict[str, bytes]


def _derive_public_key(priv: Path) -> bytes:
    """Public half of a passphraseless private key via `ssh-keygen -y`. An
    encrypted key must fail here, not in the holder: `start_new_session=True`
    detaches the controlling terminal and the env disables askpass, so ssh-keygen
    has no way to prompt and exits non-zero, surfaced as a clear error."""
    env = {**os.environ, "SSH_ASKPASS_REQUIRE": "never", "DISPLAY": ""}
    env.pop("SSH_ASKPASS", None)
    result = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(priv)],
        capture_output=True,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
        env=env,
    )
    if result.returncode != 0:
        raise ValueError(
            f"could not load SSH key {priv.name}: "
            f"{result.stderr.decode(errors='replace').strip()}. The key must be "
            "a valid, passphraseless private key — the holder pod's ssh-agent "
            "loads it non-interactively and cannot unlock an encrypted key."
        )
    return result.stdout


def prepare(key_dir: Path) -> SshAgentPlan | None:
    """Classify the host key dir, or None if it holds no private keys. Private
    keys go to the holder; a derived `<name>.pub`, any `config`, and any OpenSSH
    certificate (`*-cert.pub`, kept because it can't be derived) go to the agent
    pod so a host->key mapping can pin a key."""
    private_keys: dict[str, bytes] = {}
    agent_extra: dict[str, bytes] = {}  # config + certificates -> agent pod ~/.ssh

    for entry in sorted(key_dir.iterdir()):
        if not entry.is_file():
            continue
        name = entry.name
        if name.endswith("-cert.pub"):
            agent_extra[name] = entry.read_bytes()  # certificate; not derivable
            continue
        if name.endswith(".pub"):
            continue  # plain public keys are derived from the private half
        data = entry.read_bytes()
        if _PRIVATE_KEY_MARKER in data:
            private_keys[name] = data  # -> holder only; never the agent pod
        elif name in _CONFIG_FILES:
            agent_extra[name] = data
        # Anything else (stray files) is ignored.

    if not private_keys:
        return None

    dotted = [name for name in private_keys if name.startswith(".")]
    if dotted:
        raise ValueError(
            f"SSH private key filename(s) start with '.': {', '.join(dotted)}. "
            "The holder loads keys with a `/keys/*` glob that skips dotfiles, so "
            "such a key would never be loaded. Rename it without a leading dot."
        )
    if shutil.which("ssh-keygen") is None:
        raise ValueError(
            "ssh-keygen not found on PATH; --ssh-key-dir needs the OpenSSH "
            "client (e.g. apt install openssh-client) to derive public keys."
        )

    pub_keys = {
        f"{name}.pub": _derive_public_key(key_dir / name) for name in private_keys
    }
    return SshAgentPlan(
        private_keys=private_keys,
        agent_files={**pub_keys, **agent_extra},
    )
