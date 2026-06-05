"""Allow-list enforcement + credential injection, exercised through a real mitm
pod running the real addon. Every assertion is made on what the upstream `echo`
server actually received (or on the proxy's status code), so it reflects true
end-to-end behaviour rather than the addon's internal state."""

import pytest

from tests.integration import harness

pytestmark = pytest.mark.integration


def _status(session, script: str) -> str:
    rc, out, err = session.agent(
        f"{script} -s -o /dev/null -w '%{{http_code}}'"
    )
    assert rc == 0, f"curl failed rc={rc}: {err}"
    return out.strip()


def test_allowed_request_reaches_upstream_with_injected_header(core_session):
    rc, out, err = core_session.agent("curl -s http://echo/foo")
    assert rc == 0, err
    data = harness.echo_json(out)
    assert data["headers"]["authorization"] == f"Bearer {harness.INJECT_SENTINEL}"
    assert data["headers"]["x-injected"] == "sentinel"


def test_injection_applies_to_post_too(core_session):
    rc, out, err = core_session.agent("curl -s -X POST -d hi http://echo/p")
    assert rc == 0, err
    data = harness.echo_json(out)
    assert data["method"] == "POST"
    assert data["headers"]["authorization"] == f"Bearer {harness.INJECT_SENTINEL}"


def test_injection_overwrites_client_supplied_header(core_session):
    # The agent sends its own Authorization; the rule must overwrite it.
    rc, out, err = core_session.agent(
        "curl -s -H 'Authorization: Bearer client-value' http://echo/foo"
    )
    assert rc == 0, err
    data = harness.echo_json(out)
    assert data["headers"]["authorization"] == f"Bearer {harness.INJECT_SENTINEL}"


def test_generic_get_allowed_without_injection(core_session):
    # host `plain` has no specific rule, so only the generic GET rule matches:
    # the request reaches echo, but no header is injected.
    rc, out, err = core_session.agent("curl -s http://plain/anything")
    assert rc == 0, err
    data = harness.echo_json(out)
    assert "x-injected" not in data["headers"]
    assert "authorization" not in data["headers"]


def test_post_to_unlisted_host_is_denied(core_session):
    assert _status(core_session, "curl -X POST -d x http://plain/anything") == "403"


def test_denied_request_returns_policy_message(core_session):
    rc, out, err = core_session.agent(
        "curl -s -X POST -d x http://blocked.invalid/whatever"
    )
    assert rc == 0, err
    assert "not permitted by rules" in out


def test_path_rule_allows_matching_path(core_session):
    rc, out, err = core_session.agent("curl -s -X POST -d x http://pathsvc/allowed/thing")
    assert rc == 0, err
    data = harness.echo_json(out)
    assert data["path"] == "/allowed/thing"


def test_path_rule_denies_nonmatching_path(core_session):
    assert _status(core_session, "curl -X POST -d x http://pathsvc/denied/thing") == "403"


def test_path_rule_does_not_block_generic_get(core_session):
    # GET is allowed everywhere by the generic rule regardless of path.
    assert _status(core_session, "curl http://pathsvc/denied/thing") == "200"


def test_https_interception_trusts_mitm_ca_and_injects(core_session):
    # No -k: the probe must trust mitm's baked CA for the TLS interception to
    # validate, and the injected header must survive the re-encrypted leg.
    rc, out, err = core_session.agent("curl -s https://echo/secure")
    assert rc == 0, f"curl https failed rc={rc}: {err}"
    data = harness.echo_json(out)
    assert data["headers"]["authorization"] == f"Bearer {harness.INJECT_SENTINEL}"
