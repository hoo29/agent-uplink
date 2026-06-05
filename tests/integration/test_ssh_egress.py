"""--ssh-cidr opens a controlled TCP-22 path that bypasses mitm. The egress must
be scoped to exactly the given CIDR *and* port 22: a listener on the same target
IP but a different port stays unreachable. (That the agent can reach NO pod IP
without the flag is shown by test_network_policy's bypass test.)"""

import pytest

from tests.integration import harness

pytestmark = pytest.mark.integration


def _nc(session, ip: str, port: int) -> int:
    rc, out, err = session.agent(f"nc -z -w4 {ip} {port}; echo rc=$?", timeout=20)
    line = [l for l in out.splitlines() if l.startswith("rc=")]
    assert line, f"no rc line: {out!r} / {err!r}"
    return int(line[-1].split("=")[1])


def test_ssh_port_reachable_within_cidr(ssh_session):
    target = ssh_session.extra["target_ip"]
    assert _nc(ssh_session, target, 22) == 0


def test_non_ssh_port_blocked_on_same_target(ssh_session):
    # The listener accepts on :80 too, so a failure here is the NetworkPolicy
    # scoping egress to port 22 only — not a missing listener.
    target = ssh_session.extra["target_ip"]
    assert _nc(ssh_session, target, 80) != 0
