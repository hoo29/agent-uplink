"""Unit tests for the mitmproxy addon's pure decision logic — allow-list
matching and SigV4 re-signing — driven with a fake request so no proxy is
needed. Cryptographic correctness against real AWS is covered by the live test;
here we pin host parsing, the structural shape of the signature, and the
enforcer's branch behaviour fast."""

import datetime
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

# Real-looking credentials the addon re-signs with (AWS's documented example key).
CREDS = {
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
}
CREDS_WITH_TOKEN = {**CREDS, "session_token": "FwoGZXIvYXdzEXAMPLETOKEN"}
DUMMY_AKIA = "AKIATEST"


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


def req(host, method="GET", path="/", headers=None, scheme="https", port=443,
        raw_content=b""):
    return SimpleNamespace(
        host=host, method=method, path=path,
        headers=Headers(headers), scheme=scheme, port=port,
        raw_content=raw_content, stream=None,
    )


def flow_for(r):
    return SimpleNamespace(request=r, response=None, metadata={})


def _enforcer(tmp_path, monkeypatch, rules, creds=None):
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(json.dumps(rules))
    opts = SimpleNamespace(rules_file=str(rules_path), aws_creds_file="")
    updates = {"rules_file": str(rules_path)}
    if creds is not None:
        creds_path = tmp_path / "creds.json"
        creds_path.write_text(json.dumps(creds))
        opts.aws_creds_file = str(creds_path)
        updates["aws_creds_file"] = str(creds_path)
    e = addon.RuleEnforcer()
    monkeypatch.setattr(addon, "ctx", SimpleNamespace(options=opts))
    e.configure(updates)
    return e


@pytest.fixture
def enforcer(tmp_path, monkeypatch):
    rules = {
        "rules": [
            {"name": "echo", "host": "echo", "methods": ["GET", "POST"],
             "inject": {"headers": {"Authorization": "Bearer X"}}},
            {"name": "paths", "host": "p", "methods": ["POST"],
             "paths": ["/allowed/.*"]},
        ],
    }
    return _enforcer(tmp_path, monkeypatch, rules)


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
# host -> (service, region) parsing
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host,expected",
    [
        ("sts.eu-west-2.amazonaws.com", ("sts", "eu-west-2")),
        ("ssm.eu-west-1.amazonaws.com", ("ssm", "eu-west-1")),
        ("s3.eu-west-2.amazonaws.com", ("s3", "eu-west-2")),
        ("my-bucket.s3.eu-west-2.amazonaws.com", ("s3", "eu-west-2")),
        ("id123.execute-api.us-east-1.amazonaws.com", ("execute-api", "us-east-1")),
        ("ec2.us-gov-west-1.amazonaws.com", ("ec2", "us-gov-west-1")),
        # Global / region-less endpoints sign as us-east-1.
        ("sts.amazonaws.com", ("sts", "us-east-1")),
        ("iam.amazonaws.com", ("iam", "us-east-1")),
        ("s3.amazonaws.com", ("s3", "us-east-1")),
        # Signing-name overrides.
        ("bedrock-runtime.us-east-1.amazonaws.com", ("bedrock", "us-east-1")),
    ],
)
def test_parse_aws_host(host, expected):
    assert addon.parse_aws_host(host) == expected


# --------------------------------------------------------------------------- #
# sigv4_sign — structural correctness (crypto validated live against AWS)
# --------------------------------------------------------------------------- #


def _freeze_time(monkeypatch):
    fixed = datetime.datetime(2024, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc)
    monkeypatch.setattr(addon, "_now", lambda: fixed)
    return fixed


def test_sigv4_sign_sets_authorization_with_real_key(monkeypatch):
    _freeze_time(monkeypatch)
    r = req("ssm.eu-west-2.amazonaws.com", "POST", "/",
            headers={"Authorization": "dummy", "X-Amz-Date": "old"})
    addon.sigv4_sign(cast(Any, r), CREDS, "ssm", "eu-west-2", "abc123")
    auth = r.headers["Authorization"]
    assert auth.startswith("AWS4-HMAC-SHA256 ")
    assert f"Credential={CREDS['access_key_id']}/20240102/eu-west-2/ssm/aws4_request" in auth
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in auth
    # 64-hex signature.
    signature = auth.split("Signature=")[1]
    assert len(signature) == 64 and all(c in "0123456789abcdef" for c in signature)
    assert r.headers["X-Amz-Date"] == "20240102T030405Z"
    assert r.headers["X-Amz-Content-Sha256"] == "abc123"


def test_sigv4_sign_includes_session_token_in_signed_headers(monkeypatch):
    _freeze_time(monkeypatch)
    r = req("sts.eu-west-2.amazonaws.com", "POST", "/")
    addon.sigv4_sign(cast(Any, r), CREDS_WITH_TOKEN, "sts", "eu-west-2", "h")
    assert r.headers["X-Amz-Security-Token"] == CREDS_WITH_TOKEN["session_token"]
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token" \
        in r.headers["Authorization"]


def test_sigv4_sign_is_deterministic_for_fixed_time(monkeypatch):
    _freeze_time(monkeypatch)
    a = req("sts.eu-west-2.amazonaws.com", "POST", "/")
    b = req("sts.eu-west-2.amazonaws.com", "POST", "/")
    addon.sigv4_sign(cast(Any, a), CREDS, "sts", "eu-west-2", "h")
    addon.sigv4_sign(cast(Any, b), CREDS, "sts", "eu-west-2", "h")
    assert a.headers["Authorization"] == b.headers["Authorization"]


def test_canonical_query_is_sorted_and_encoded():
    # Keys sorted; reserved chars in values percent-encoded.
    assert addon._canonical_query("list-type=2&prefix=a/b") == \
        "list-type=2&prefix=a%2Fb"
    assert addon._canonical_query("b=2&a=1") == "a=1&b=2"
    assert addon._canonical_query("") == ""


# --------------------------------------------------------------------------- #
# enforcer re-signing flow
# --------------------------------------------------------------------------- #


def _aws_dummy_auth(akia=DUMMY_AKIA):
    return (
        f"AWS4-HMAC-SHA256 Credential={akia}/20240101/us-east-1/s3/aws4_request, "
        "SignedHeaders=host, Signature=deadbeef"
    )


def _sigv4_enforcer(tmp_path, monkeypatch, host_regex, creds=None):
    rules = {"rules": [{"name": "aws", "host": host_regex}]}
    return _enforcer(tmp_path, monkeypatch, rules, creds={DUMMY_AKIA: CREDS, **(creds or {})})


def test_s3_request_signed_in_place_at_headers_time(tmp_path, monkeypatch):
    _freeze_time(monkeypatch)
    e = _sigv4_enforcer(tmp_path, monkeypatch, r"s3\.us-east-1\.amazonaws\.com")
    r = req("s3.us-east-1.amazonaws.com", "GET", "/bucket/key",
            headers={"Authorization": _aws_dummy_auth(),
                     "X-Amz-Date": "old", "X-Amz-Security-Token": "dummytok"})
    flow = flow_for(r)
    e.requestheaders(cast(Any, flow))
    assert flow.response is None
    # Re-signed in place with the real key and S3's unsigned payload.
    auth = r.headers["Authorization"]
    assert f"Credential={CREDS['access_key_id']}/20240102/us-east-1/s3/" in auth
    assert r.headers["X-Amz-Content-Sha256"] == "UNSIGNED-PAYLOAD"
    # The dummy session token was stripped (these creds carry none).
    assert "X-Amz-Security-Token" not in r.headers
    assert "aws_sign" not in flow.metadata  # signed now, nothing deferred


def test_non_s3_request_deferred_then_signed_with_body_hash(tmp_path, monkeypatch):
    _freeze_time(monkeypatch)
    e = _sigv4_enforcer(tmp_path, monkeypatch, r"ssm\.eu-west-2\.amazonaws\.com")
    body = b'{"MaxResults": 1}'
    r = req("ssm.eu-west-2.amazonaws.com", "POST", "/", raw_content=body,
            headers={"Authorization": _aws_dummy_auth(), "X-Amz-Date": "old"})
    flow = flow_for(r)
    e.requestheaders(cast(Any, flow))
    # Deferred: body buffered, dummy signature stripped, nothing signed yet.
    assert flow.response is None
    assert r.stream is False
    assert flow.metadata["aws_sign"]["service"] == "ssm"
    assert r.headers.get("Authorization") is None

    e.request(cast(Any, flow))
    import hashlib
    auth = r.headers["Authorization"]
    assert f"Credential={CREDS['access_key_id']}/20240102/eu-west-2/ssm/" in auth
    # Payload hash is the SHA256 of the real body.
    assert r.headers["X-Amz-Content-Sha256"] == hashlib.sha256(body).hexdigest()


def test_request_hook_noop_without_marker(tmp_path, monkeypatch):
    e = _sigv4_enforcer(tmp_path, monkeypatch, r"ssm\.eu-west-2\.amazonaws\.com")
    r = req("ssm.eu-west-2.amazonaws.com", "POST", "/")
    flow = flow_for(r)  # no aws_sign metadata
    e.request(cast(Any, flow))
    assert r.headers.get("Authorization") is None


def test_unknown_akia_not_signed_but_allowed(tmp_path, monkeypatch):
    e = _sigv4_enforcer(tmp_path, monkeypatch, r"s3\.us-east-1\.amazonaws\.com")
    original = _aws_dummy_auth("AKIAUNKNOWN")
    r = req("s3.us-east-1.amazonaws.com", "GET", "/",
            headers={"Authorization": original})
    flow = flow_for(r)
    e.requestheaders(cast(Any, flow))
    # Allowed by the rule, but left untouched (will fail at AWS with dummy sig).
    assert flow.response is None
    assert r.headers["Authorization"] == original


def test_non_aws_host_with_sigv4_auth_not_signed(tmp_path, monkeypatch):
    e = _enforcer(
        tmp_path, monkeypatch,
        {"rules": [{"name": "ex", "host": "not-aws.example.com"}]},
        creds={DUMMY_AKIA: CREDS},
    )
    r = req("not-aws.example.com", "GET", "/",
            headers={"Authorization": _aws_dummy_auth()})
    flow = flow_for(r)
    e.requestheaders(cast(Any, flow))
    assert flow.response is None
    assert r.headers["Authorization"] == _aws_dummy_auth()  # untouched


def test_aws_request_skips_header_injection(tmp_path, monkeypatch):
    # inject.headers and re-signing are mutually exclusive on an AWS host: the
    # signer overwrites Authorization, so the injected header must not appear.
    _freeze_time(monkeypatch)
    e = _enforcer(
        tmp_path, monkeypatch,
        {"rules": [{
            "name": "s3", "host": r"s3\.us-east-1\.amazonaws\.com",
            "inject": {"headers": {"Authorization": "Bearer SHOULD-NOT-APPEAR"}},
        }]},
        creds={DUMMY_AKIA: CREDS},
    )
    r = req("s3.us-east-1.amazonaws.com", "GET", "/",
            headers={"Authorization": _aws_dummy_auth()})
    flow = flow_for(r)
    e.requestheaders(cast(Any, flow))
    assert "SHOULD-NOT-APPEAR" not in r.headers["Authorization"]
    assert r.headers["Authorization"].startswith("AWS4-HMAC-SHA256 ")


def test_request_denies_unmatched_host(tmp_path, monkeypatch):
    e = _enforcer(tmp_path, monkeypatch,
                  {"rules": [{"name": "only", "host": "allowed.example"}]})
    r = req("blocked.example", "POST", "/x")
    flow = flow_for(r)
    e.requestheaders(cast(Any, flow))
    assert flow.response is not None
    assert flow.response.status_code == 403


# --------------------------------------------------------------------------- #
# Shipped git.yaml example matches real git smart-HTTP requests
# --------------------------------------------------------------------------- #


def _git_enforcer(tmp_path, monkeypatch):
    data = yaml.safe_load(EXAMPLE_GIT_RULES.read_text())
    return _enforcer(tmp_path, monkeypatch, data)


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
