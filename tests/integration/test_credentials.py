"""The agent pod must never see real secrets. The mitm pod injects a sentinel
bearer on host `echo` (proven to reach the upstream by test_injector); here we
prove that same sentinel — and a stand-in real OAuth token handed to the
production fake-creds builder — appear NOWHERE inside the agent pod's
environment or filesystem, and that the pod only ever holds dummy/fake
credentials. The rules Secret that *does* hold the real value is mounted only
into mitm, never the agent."""

import pytest

from tests.integration import harness

pytestmark = pytest.mark.integration

HOME = "/home/agent"


def test_injected_secret_absent_from_agent_env(core_session):
    rc, out, err = core_session.agent("env", timeout=20)
    assert rc == 0, err
    assert harness.INJECT_SENTINEL not in out
    assert harness.REAL_OAUTH_SENTINEL not in out

# NOTE: the bedrock-placeholder behaviour (AWS_BEARER_TOKEN_BEDROCK=placeholder,
# real token injected only at mitm) is decided by the production ClaudeAgent /
# claude_settings_bytes, which an in-cluster probe can't faithfully reproduce.
# It is covered where it actually lives, in tests/unit/test_claude_config.py.


def test_aws_credentials_in_pod_are_dummy(core_session):
    rc, out, err = core_session.agent(f"cat {HOME}/.aws/credentials")
    assert rc == 0, err
    expected_akia = harness.aws.dummy_akia(harness.TEST_PROFILE)
    assert expected_akia in out
    # The real key id / secret never enter the pod, only the deterministic dummy.
    assert out.strip().startswith(f"[{harness.TEST_PROFILE}]")
    assert harness.INJECT_SENTINEL not in out
    assert "aws_secret_access_key" in out


def test_oauth_credentials_in_pod_are_fake(core_session):
    rc, out, err = core_session.agent(f"cat {HOME}/.claude/.credentials.json")
    assert rc == 0, err
    # The production fake-creds builder swaps the real token for an agent-uplink
    # placeholder; the real token must be gone.
    assert harness.REAL_OAUTH_SENTINEL not in out
    assert "agent-uplink" in out


def test_rules_secret_not_mounted_in_agent_pod(core_session):
    # The resolved rules (which hold the real injected secret) live only in mitm.
    rc, out, err = core_session.agent("ls /rules 2>&1; echo done")
    assert "done" in out
    assert "rules.json" not in out


def test_no_real_secret_anywhere_on_agent_filesystem(core_session):
    # Scan the writable/mounted trees (not /proc, /sys) for either sentinel.
    rc, out, err = core_session.agent(
        f"grep -rIl -e '{harness.INJECT_SENTINEL}' -e '{harness.REAL_OAUTH_SENTINEL}' "
        "/home /etc /root /tmp /run 2>/dev/null; echo END",
        timeout=30,
    )
    # Only the END marker should be printed — no file matched.
    assert out.strip() == "END", f"sentinel found in: {out}"
