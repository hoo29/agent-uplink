"""AWS SigV4 re-signing security properties, on a live cluster.

The agent only ever holds dummy credentials; the real credentials live in the
mitm pod, which re-signs authorised AWS requests in place. Two invariants matter
here and neither needs to reach real AWS:

  * the allow-list is checked FIRST — a valid-looking AWS signature to a host no
    rule permits is denied, so a signature is never a backdoor;
  * the real credentials are readable in the mitm pod but never reachable from
    the agent pod.

The re-sign+forward path itself (canonical request, signature, body hashing,
session tokens) is validated end-to-end against real AWS by the live test
documented in tests/README — that exercises the exact addon shipping here."""

import pytest

from tests.integration import harness

pytestmark = pytest.mark.integration

AWS_HOST = "s3.us-east-1.amazonaws.com"


def test_allowlist_is_checked_before_signing(sigv4_session):
    # A correctly-shaped signature (known dummy AKIA) to a host NO rule allows
    # must be denied. The generic default allows GET everywhere, so use POST.
    akia = sigv4_session.extra["akia"]
    rc, out, err = sigv4_session.agent(
        harness.aws_signed_curl(AWS_HOST, "/x", akia=akia, method="POST", code_only=True)
    )
    assert rc == 0, err
    assert out.strip() == "403"


def test_real_aws_creds_live_in_mitm_not_agent(sigv4_session):
    # The real AWS secret key is mounted into the mitm pod (which re-signs) and
    # must be readable there...
    rc, out, err = sigv4_session.exec(
        "mitm", "cat /aws-creds/creds.json", container="mitm", timeout=20
    )
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
