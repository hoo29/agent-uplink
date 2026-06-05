"""In-pod dockerd viability. agent-uplink relies on a dockerd running inside the
agent pod; in production that needs the kata microVM, but the security-relevant
prerequisite the tests pin down is that a privileged pod on the *default* runtime
(no kata) can run dockerd — which is exactly how this suite runs every pod, and
what lets it execute on a bare GitHub runner."""

import pytest

from tests.integration import harness

pytestmark = [pytest.mark.integration, pytest.mark.dockerd]


def test_in_pod_dockerd_is_running(dockerd_session):
    rc, out, err = dockerd_session.exec(
        "dockerd", "docker info --format '{{.ServerVersion}}'", timeout=30
    )
    assert rc == 0, f"docker info failed: {err}"
    assert out.strip(), "empty docker server version"


def test_in_pod_docker_daemon_is_usable(dockerd_session):
    # The daemon responds to a real (if trivial) API call — proving it's not just
    # the socket existing but a functioning engine under privileged + runc.
    rc, out, err = dockerd_session.exec(
        "dockerd", "docker ps --format '{{.ID}}'", timeout=30
    )
    assert rc == 0, f"docker ps failed: {err}"
