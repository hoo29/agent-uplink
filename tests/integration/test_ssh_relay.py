"""Live-cluster test of the SSH agent-forwarding relay.

An ephemeral keypair is split by the production `sshagent.prepare`: the private
half goes to the holder pod's ssh-agent, the public half to the agent pod. A
dummy sshd authorises that public key. The agent must be able to authenticate to
sshd (signing happens in the holder) while the private key never appears in the
agent pod — that split is the whole point of the design.
"""

import pytest

from tests.integration import harness

pytestmark = pytest.mark.integration


def test_agent_authenticates_to_sshd_via_relay(ssh_relay_session):
    # The session fixture already gated on this in warmup; re-run to assert it as
    # a first-class behaviour (signing is delegated to the holder over the bridge).
    rc, out, err = ssh_relay_session.agent(
        ssh_relay_session.extra["ssh_cmd"], timeout=30
    )
    assert "RELAY_OK" in out, f"relay auth failed: rc={rc} out={out!r} err={err!r}"


def test_agent_can_list_holder_keys_over_the_bridge(ssh_relay_session):
    # SSH_AUTH_SOCK resolves through the sidecar -> holder, so the agent sees the
    # loaded identity even though it holds no private key itself.
    rc, out, _ = ssh_relay_session.agent("ssh-add -l", timeout=20)
    assert rc == 0 and "ED25519" in out.upper(), f"agent sees no relayed key: {out!r}"


def test_private_key_absent_from_agent_pod(ssh_relay_session):
    # No private key material anywhere the agent could read it.
    _rc, out, _ = ssh_relay_session.agent(
        "grep -rl 'PRIVATE KEY' /root /home /ssh-agent 2>/dev/null; true", timeout=20
    )
    assert out.strip() == "", f"private key leaked into the agent pod: {out!r}"


def test_only_public_key_present_in_agent_pod(ssh_relay_session):
    pub = ssh_relay_session.extra["pub"]
    rc, out, _ = ssh_relay_session.agent(f"cat /root/.ssh/{pub}", timeout=20)
    assert rc == 0 and out.startswith("ssh-ed25519 "), f"public key missing: {out!r}"


def test_private_key_lives_in_the_holder(ssh_relay_session):
    # Contrast with the agent pod: the holder is exactly where the key is.
    _rc, out, _ = harness.kexec_sh(
        ssh_relay_session.ns,
        "ssh-agent",
        "grep -l 'PRIVATE KEY' /keys/* 2>/dev/null; true",
        container="ssh-agent",
        timeout=20,
    )
    assert out.strip(), "holder is missing the private key it should hold"
