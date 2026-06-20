"""SSH agent-forwarding relay.

The private keys live in a dedicated holder pod running `ssh-agent`; the agent
pod reaches that agent over a socat TCP bridge and only ever obtains signatures,
never the private key bytes. This keeps key material off the privileged agent
container, whose `CAP_SYS_ADMIN` would let it read a same-pod sidecar's memory —
hence the holder must be a separate pod, reachable only over the network (the
same trust model as the mitm pod).

Host->key mapping stays client-side: the user's `config` and the matching public
keys (which are not secret) are mounted into the agent pod's ~/.ssh, so a rule
like `IdentityFile ~/.ssh/<name>.pub` + `IdentitiesOnly yes` pins one key to a
host. ssh loads the public half locally and asks the holder's agent to sign. The
public key is always derived from the private one (not read from a shipped
`.pub`) so it cannot drift, and deriving doubles as a passphraseless check — the
holder's `ssh-add` runs non-interactively and can't unlock an encrypted key.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# A private key is identified by this PEM marker; everything else in the dir is
# an ssh client config file or ignored. The marker is authoritative over the
# filename: a file carrying it is always treated as a private key (and so kept
# off the agent pod), even if it is named like a config file.
_PRIVATE_KEY_MARKER = b"PRIVATE KEY-----"

# Non-key support files that belong in the agent pod's ~/.ssh, not the holder.
# `known_hosts` is deliberately excluded: it would be mounted read-only, which
# blocks ssh from appending newly accepted host keys (EROFS). ssh creates its
# own writable known_hosts in the agent pod's ~/.ssh instead.
_CONFIG_FILES = frozenset({"config"})


@dataclass
class SshAgentPlan:
    """Split of a host key dir into the two pods.

    `private_keys` (filename -> bytes) become the holder's `ssh-agent-keys`
    Secret; `agent_files` (derived public keys + config) become the agent pod's
    `ssh-pub` Secret, dropped file-by-file into ~/.ssh.
    """

    private_keys: dict[str, bytes]
    agent_files: dict[str, bytes]


def _derive_public_key(priv: Path) -> bytes:
    """Public half of a passphraseless private key via `ssh-keygen -y`.

    An encrypted key must fail here, not in the holder. ssh-keygen reads a
    passphrase from the controlling terminal or an askpass helper, not stdin, so
    closing stdin alone is not enough: `start_new_session=True` detaches the
    controlling terminal (no /dev/tty to prompt on) and the environment disables
    askpass. With both, an encrypted key has no way to be unlocked and exits
    non-zero, which we surface as a clear host-side error."""
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
    """Classify the host key dir; return None if it holds no private keys.

    Private keys go to the holder; a freshly derived `<name>.pub`, any `config`,
    and any OpenSSH certificate (`*-cert.pub`) go to the agent pod so a host->key
    mapping can pin a key. Certificates are kept because they cannot be derived
    from the private key and the holder still signs with the private half.
    """
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
