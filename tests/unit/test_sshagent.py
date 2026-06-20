"""Unit tests for the SSH key dir split: private keys -> holder, derived public
keys + config -> agent pod. No cluster required, but ssh-keygen must be present
(the public half is always derived from the private key)."""

import shutil
import subprocess

import pytest

from agent_uplink import sshagent

pytestmark = pytest.mark.skipif(
    shutil.which("ssh-keygen") is None, reason="ssh-keygen not on PATH"
)


def _keygen(path, *, passphrase=""):
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", passphrase, "-q", "-f", str(path)],
        check=True,
    )


def test_prepare_splits_private_from_public_and_config(tmp_path):
    _keygen(tmp_path / "id_ed25519")
    (tmp_path / "config").write_bytes(
        b"Host x\n  IdentityFile ~/.ssh/id_ed25519.pub\n"
    )

    plan = sshagent.prepare(tmp_path)

    assert plan is not None
    # Only the private key reaches the holder.
    assert set(plan.private_keys) == {"id_ed25519"}
    assert b"PRIVATE KEY" in plan.private_keys["id_ed25519"]
    # Derived public key + config reach the agent pod; the private key never does.
    assert set(plan.agent_files) == {"id_ed25519.pub", "config"}
    assert plan.agent_files["id_ed25519.pub"].startswith(b"ssh-ed25519 ")
    assert "id_ed25519" not in plan.agent_files


def test_prepare_derives_public_key_ignoring_shipped_pub(tmp_path):
    _keygen(tmp_path / "deploy")
    # A stale/mismatched shipped .pub must be ignored in favour of the derived one.
    (tmp_path / "deploy.pub").write_bytes(b"ssh-ed25519 STALEKEY stale\n")

    plan = sshagent.prepare(tmp_path)

    assert plan is not None
    assert b"STALEKEY" not in plan.agent_files["deploy.pub"]


def test_prepare_returns_none_without_private_keys(tmp_path):
    (tmp_path / "config").write_bytes(b"Host x\n")
    (tmp_path / "known_hosts").write_bytes(b"host ssh-ed25519 AAAA\n")
    assert sshagent.prepare(tmp_path) is None


def test_prepare_rejects_passphrase_protected_key(tmp_path):
    _keygen(tmp_path / "locked", passphrase="hunter2")
    (tmp_path / "locked.pub").unlink()  # force derivation of the encrypted key
    with pytest.raises(ValueError, match="passphraseless"):
        sshagent.prepare(tmp_path)


def test_prepare_keeps_certificate_alongside_derived_pub(tmp_path):
    _keygen(tmp_path / "id_ed25519")
    # An OpenSSH certificate cannot be derived from the private key, so it must be
    # carried to the agent pod rather than dropped with other .pub files.
    (tmp_path / "id_ed25519-cert.pub").write_bytes(b"ssh-ed25519-cert-v01@... cert\n")

    plan = sshagent.prepare(tmp_path)

    assert plan is not None
    assert "id_ed25519-cert.pub" in plan.agent_files
    assert "id_ed25519.pub" in plan.agent_files


def test_prepare_routes_marker_bearing_config_named_file_to_holder(tmp_path):
    _keygen(tmp_path / "id_ed25519")
    # A private key mis-named `config` must go to the holder, never the agent pod,
    # so the confidentiality guarantee holds regardless of filename. Copy it with
    # 0600 perms, as a real private key would have (ssh-keygen -y refuses 0644).
    misnamed = tmp_path / "config"
    misnamed.write_bytes((tmp_path / "id_ed25519").read_bytes())
    misnamed.chmod(0o600)

    plan = sshagent.prepare(tmp_path)

    assert plan is not None
    assert "config" in plan.private_keys
    assert "config" not in plan.agent_files


def test_prepare_rejects_dot_prefixed_private_key(tmp_path):
    _keygen(tmp_path / ".hidden")
    (tmp_path / ".hidden.pub").unlink()
    with pytest.raises(ValueError, match="leading dot"):
        sshagent.prepare(tmp_path)
