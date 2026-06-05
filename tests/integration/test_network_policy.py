"""The agent pod's egress must be confined to mitm + kube-dns. These tests probe
the live NetworkPolicy enforcement (k3s' built-in controller) from inside the
agent pod: it can reach mitm and resolve DNS, but cannot reach the internet
directly nor any in-cluster upstream pod (so it cannot bypass mitm)."""

import pytest

from tests.integration import harness

pytestmark = pytest.mark.integration


def _nc(session, host: str, port: int, *, wait: int = 4) -> int:
    """Return nc's exit code for a TCP connect probe (0 = connected)."""
    rc, out, err = session.agent(
        f"nc -z -w{wait} {host} {port}; echo rc=$?", timeout=wait + 15
    )
    line = [l for l in out.splitlines() if l.startswith("rc=")]
    assert line, f"no rc line in output: {out!r} / {err!r}"
    return int(line[-1].split("=")[1])


def test_agent_can_reach_mitm(core_session):
    assert _nc(core_session, "mitm", 8080) == 0


def test_agent_dns_resolves(core_session):
    # kube-dns egress is allowed, so the mitm Service name must resolve to its
    # actual ClusterIP. Assert on the resolved IP (not just nslookup's boilerplate,
    # which prints a Server/Address line even on NXDOMAIN).
    mitm_ip = harness._run(
        ["kubectl", "get", "svc", "mitm", "-n", core_session.ns,
         "-o", "jsonpath={.spec.clusterIP}"]
    )[1].strip()
    assert mitm_ip, "could not read mitm Service ClusterIP"
    rc, out, err = core_session.agent("getent hosts mitm || nslookup mitm", timeout=20)
    assert mitm_ip in out, f"mitm did not resolve to {mitm_ip}: {out!r}"


def test_agent_cannot_reach_internet_directly(core_session):
    # Egress is restricted to mitm + DNS, so a direct TCP connect to a public
    # address must be dropped (times out -> non-zero).
    assert _nc(core_session, "1.1.1.1", 443) != 0


def test_agent_cannot_bypass_mitm_to_reach_upstream(core_session):
    # The echo upstream is reachable from mitm but must NOT be reachable directly
    # from the agent — otherwise the agent could exfiltrate around the proxy.
    echo_ip = core_session.pod_ip("echo")
    assert _nc(core_session, echo_ip, 8080) != 0
    assert _nc(core_session, echo_ip, 8443) != 0


def test_agent_cannot_reach_kube_apiserver(core_session):
    # Egress is mitm + DNS only, so the agent must not reach the control plane.
    # Probe the resolved ClusterIP directly so a pass means the connect was
    # dropped, not that a name failed to resolve.
    apiserver_ip = harness._run(
        ["kubectl", "get", "svc", "kubernetes", "-n", "default",
         "-o", "jsonpath={.spec.clusterIP}"]
    )[1].strip()
    assert apiserver_ip, "could not read kubernetes Service ClusterIP"
    assert _nc(core_session, apiserver_ip, 443) != 0
