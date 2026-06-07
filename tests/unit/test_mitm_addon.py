"""Unit tests for the mitmproxy addon's pure decision logic — allow-list
matching and SigV4 rerouting — driven with a fake request so no proxy is needed.
The full request()/403/inject path is covered end-to-end by the integration
tests; here we pin the branch behaviour fast."""

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import yaml

pytest.importorskip("mitmproxy.http")

from agent_uplink.mitm_addon import filter as addon  # noqa: E402

EXAMPLE_GIT_RULES = (
    Path(__file__).resolve().parents[2] / "examples" / "rules" / "git.yaml"
)


class Headers:
    """Minimal case-insensitive header map, matching how the addon uses it."""

    def __init__(self, d=None):
        self._d = {}
        for k, v in (d or {}).items():
            self._d[k.lower()] = (k, v)

    def get(self, k, default=None):
        item = self._d.get(k.lower())
        return item[1] if item else default

    def pop(self, k, default=None):
        item = self._d.pop(k.lower(), None)
        return item[1] if item else default

    def __setitem__(self, k, v):
        self._d[k.lower()] = (k, v)

    def __contains__(self, k):
        return k.lower() in self._d

    def __getitem__(self, k):
        return self._d[k.lower()][1]


def req(host, method="GET", path="/", headers=None, scheme="https", port=443):
    return SimpleNamespace(
        host=host, method=method, path=path,
        headers=Headers(headers), scheme=scheme, port=port,
    )


@pytest.fixture
def enforcer(tmp_path, monkeypatch):
    rules = {
        "rules": [
            {"name": "echo", "host": "echo", "methods": ["GET", "POST"],
             "inject": {"headers": {"Authorization": "Bearer X"}}},
            {"name": "paths", "host": "p", "methods": ["POST"],
             "paths": ["/allowed/.*"]},
        ],
        "aws_sigv4_routes": {
            "AKIATEST": {"upstream_host": "sidecar", "upstream_port": 8080}
        },
    }
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules))
    e = addon.RuleEnforcer()
    monkeypatch.setattr(
        addon, "ctx",
        SimpleNamespace(options=SimpleNamespace(rules_file=str(path))),
    )
    e.configure({"rules_file": str(path)})
    return e


# --------------------------------------------------------------------------- #
# allow-list matching
# --------------------------------------------------------------------------- #


def test_match_host_and_method(enforcer):
    matched = enforcer._match_rule(req("echo", "GET", "/foo"))
    assert matched is not None
    name, inject = matched
    assert name == "echo"
    assert inject == {"Authorization": "Bearer X"}


def test_method_not_allowed_does_not_match(enforcer):
    assert enforcer._match_rule(req("echo", "DELETE", "/foo")) is None


def test_host_is_full_match_not_substring(enforcer):
    assert enforcer._match_rule(req("echo.evil.com", "GET", "/")) is None
    assert enforcer._match_rule(req("xechox", "GET", "/")) is None


def test_path_rule_matches_only_allowed_path(enforcer):
    assert enforcer._match_rule(req("p", "POST", "/allowed/x")) is not None
    assert enforcer._match_rule(req("p", "POST", "/denied/x")) is None


def test_unmatched_host_returns_none(enforcer):
    assert enforcer._match_rule(req("nope", "GET", "/")) is None


# --------------------------------------------------------------------------- #
# SigV4 reroute
# --------------------------------------------------------------------------- #


def _sigv4_auth(akia):
    return (
        f"AWS4-HMAC-SHA256 Credential={akia}/20240101/us-east-1/s3/aws4_request, "
        "SignedHeaders=host, Signature=deadbeef"
    )


def test_reroute_strips_signature_and_preserves_host(enforcer):
    r = req(
        "s3.us-east-1.amazonaws.com",
        headers={
            "Authorization": _sigv4_auth("AKIATEST"),
            "X-Amz-Date": "20240101T000000Z",
            "X-Amz-Security-Token": "tok",
            "X-Amz-Content-Sha256": "abc",
        },
    )
    assert enforcer._reroute_sigv4(r, "rule") is True
    assert r.host == "sidecar"
    assert r.port == 8080
    assert r.scheme == "http"
    assert r.headers["Host"] == "s3.us-east-1.amazonaws.com"
    for h in ("Authorization", "X-Amz-Date", "X-Amz-Security-Token",
              "X-Amz-Content-Sha256"):
        assert h not in r.headers


def test_reroute_only_for_amazonaws_hosts(enforcer):
    r = req("not-aws.example.com",
            headers={"Authorization": _sigv4_auth("AKIATEST")})
    assert enforcer._reroute_sigv4(r, "rule") is False
    assert r.host == "not-aws.example.com"  # untouched


def test_reroute_unknown_akia_not_routed(enforcer):
    r = req("s3.us-east-1.amazonaws.com",
            headers={"Authorization": _sigv4_auth("AKIAUNKNOWN")})
    assert enforcer._reroute_sigv4(r, "rule") is False
    assert "Authorization" in r.headers  # left intact to fail at AWS


def test_reroute_ignores_non_sigv4_authorization(enforcer):
    r = req("s3.us-east-1.amazonaws.com",
            headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert enforcer._reroute_sigv4(r, "rule") is False


def test_reroute_noop_without_routes(enforcer):
    enforcer._sigv4_routes = {}
    r = req("s3.us-east-1.amazonaws.com",
            headers={"Authorization": _sigv4_auth("AKIATEST")})
    assert enforcer._reroute_sigv4(r, "rule") is False


def _enforcer_from(tmp_path, monkeypatch, rules):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules))
    e = addon.RuleEnforcer()
    monkeypatch.setattr(
        addon, "ctx", SimpleNamespace(options=SimpleNamespace(rules_file=str(path)))
    )
    e.configure({"rules_file": str(path)})
    return e


def test_request_reroute_skips_header_injection(tmp_path, monkeypatch):
    # inject.headers and SigV4 reroute are mutually exclusive on an amazonaws
    # host: the sidecar re-signs, so an inject header would be discarded. Confirm
    # request() reroutes and does NOT re-apply the rule's injected Authorization.
    e = _enforcer_from(tmp_path, monkeypatch, {
        "rules": [{
            "name": "s3", "host": r"s3\.us-east-1\.amazonaws\.com",
            "inject": {"headers": {"Authorization": "Bearer SHOULD-NOT-APPEAR"}},
        }],
        "aws_sigv4_routes": {
            "AKIATEST": {"upstream_host": "sidecar", "upstream_port": 8080}
        },
    })
    r = req("s3.us-east-1.amazonaws.com",
            headers={"Authorization": _sigv4_auth("AKIATEST")})
    flow = SimpleNamespace(request=r, response=None)
    e.request(cast(Any, flow))
    assert flow.response is None           # allowed
    assert r.host == "sidecar"             # rerouted
    assert r.headers.get("Authorization") is None  # stripped, NOT re-injected


def test_request_denies_unmatched_host(tmp_path, monkeypatch):
    e = _enforcer_from(tmp_path, monkeypatch,
                       {"rules": [{"name": "only", "host": "allowed.example"}]})
    r = req("blocked.example", "POST", "/x")
    flow = SimpleNamespace(request=r, response=None)
    e.request(cast(Any, flow))
    assert flow.response is not None
    assert flow.response.status_code == 403


# --------------------------------------------------------------------------- #
# Shipped git.yaml example matches real git smart-HTTP requests
# --------------------------------------------------------------------------- #


def _git_enforcer(tmp_path, monkeypatch):
    data = yaml.safe_load(EXAMPLE_GIT_RULES.read_text())
    data.setdefault("aws_sigv4_routes", {})
    return _enforcer_from(tmp_path, monkeypatch, data)


@pytest.mark.parametrize(
    "method,path",
    [
        # info/refs carries a query string; req.path is fullmatched WITH it, so
        # the rule must allow the query — else private-repo discovery (which 401s
        # without auth) would miss the auth-injecting rule.
        ("GET", "/hoo29/test-little-timmy-gha.git/info/refs?service=git-upload-pack"),
        ("GET", "/hoo29/test-little-timmy-gha.git/info/refs?service=git-receive-pack"),
        ("POST", "/hoo29/test-little-timmy-gha.git/git-upload-pack"),
        ("POST", "/hoo29/test-little-timmy-gha.git/git-receive-pack"),
    ],
)
def test_git_example_matches_smart_http(tmp_path, monkeypatch, method, path):
    e = _git_enforcer(tmp_path, monkeypatch)
    matched = e._match_rule(cast(Any, req("github.com", method, path)))
    assert matched is not None, (method, path)
    name, inject = matched
    assert name == "github-git-https"
    assert "Authorization" in inject


def test_git_example_does_not_blanket_allow_post(tmp_path, monkeypatch):
    # The rule is scoped to the smart-HTTP paths, not all POSTs to the host.
    e = _git_enforcer(tmp_path, monkeypatch)
    r = cast(Any, req("github.com", "POST", "/hoo29/repo/issues"))
    assert e._match_rule(r) is None
