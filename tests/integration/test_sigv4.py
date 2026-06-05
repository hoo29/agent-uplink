"""AWS SigV4 rerouting. A request to an allowed *.amazonaws.com host carrying a
dummy-AKIA signature must have its bogus signature headers stripped and be
rerouted (over plaintext, in-namespace) to the matching aws-sigv4-proxy sidecar,
with the original Host preserved so the sidecar can re-sign for the right
service. Crucially the allow-list is checked FIRST: a signature alone grants
nothing. An echo pod (labelled tier=sigv4) stands in for the real sidecar so we
can read back exactly what was forwarded."""

import pytest

from tests.integration import harness

pytestmark = pytest.mark.integration

ALLOWED_HOST = "s3.us-east-1.amazonaws.com"
UNLISTED_HOST = "s3.eu-west-1.amazonaws.com"


def test_signed_request_rerouted_and_signature_stripped(sigv4_session):
    akia = sigv4_session.extra["akia"]
    rc, out, err = sigv4_session.agent(
        harness.aws_signed_curl(ALLOWED_HOST, "/my-bucket/key", akia=akia, method="GET")
    )
    assert rc == 0, err
    data = harness.echo_json(out)  # reaching echo proves it was rerouted to the sidecar
    headers = data["headers"]
    # The bogus signature + amz headers must all be stripped before the sidecar.
    assert "authorization" not in headers
    assert "x-amz-date" not in headers
    assert "x-amz-security-token" not in headers
    assert "x-amz-content-sha256" not in headers
    # The original AWS host must be preserved so the sidecar re-signs correctly.
    assert headers["host"] == ALLOWED_HOST
    assert data["path"] == "/my-bucket/key"


def test_allowlist_is_checked_before_reroute(sigv4_session):
    # A correctly-signed request (known AKIA) to a host NO rule allows must be
    # denied — the SigV4 signature must not be a backdoor around the allow-list.
    akia = sigv4_session.extra["akia"]
    rc, out, err = sigv4_session.agent(
        harness.aws_signed_curl(
            UNLISTED_HOST, "/x", akia=akia, method="POST", code_only=True
        )
    )
    assert rc == 0, err
    assert out.strip() == "403"


def test_agent_cannot_reach_sidecar_directly(sigv4_session):
    # The re-signing sidecar runs with the real profile's IAM scope; the agent
    # must only reach it via mitm, never directly.
    sidecar_ip = sigv4_session.pod_ip("echo")
    rc, out, err = sigv4_session.agent(
        f"nc -z -w4 {sidecar_ip} 8080; echo rc=$?", timeout=20
    )
    assert "rc=0" not in out, out


def test_real_aws_creds_live_in_sidecar_not_agent(sigv4_session):
    # The real AWS secret key is mounted into the sidecar (which re-signs) and
    # must be readable there...
    rc, out, err = sigv4_session.exec("echo", "cat /aws/credentials", timeout=20)
    assert rc == 0, err
    assert harness.REAL_AWS_SENTINEL in out
    # ...but must be absent from the agent pod entirely (env + filesystem).
    rc, env_out, _ = sigv4_session.agent("env", timeout=20)
    assert harness.REAL_AWS_SENTINEL not in env_out
    rc, scan, _ = sigv4_session.agent(
        f"grep -rIl '{harness.REAL_AWS_SENTINEL}' /home /etc /root /tmp /run "
        "2>/dev/null; echo END",
        timeout=30,
    )
    assert scan.strip() == "END", f"real AWS secret found in agent: {scan}"
