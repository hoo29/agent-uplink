"""Unit tests for kube.resolve. No cluster required — kubectl is monkey-patched."""

import base64
import json
from unittest import mock

import pytest
import yaml

from agent_uplink import kube


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_CA_PEM = b"-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n"
_FAKE_CA_B64 = base64.b64encode(_FAKE_CA_PEM).decode("ascii")

_FAKE_MITM_CA = b"-----BEGIN CERTIFICATE-----\nMITMCA\n-----END CERTIFICATE-----\n"
_FAKE_MITM_CA_B64 = base64.b64encode(_FAKE_MITM_CA).decode("ascii")

_FAKE_CERT_PEM = b"-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----\n"
_FAKE_KEY_PEM = b"-----BEGIN RSA PRIVATE KEY-----\nFAKEKEY\n-----END RSA PRIVATE KEY-----\n"
_FAKE_CERT_B64 = base64.b64encode(_FAKE_CERT_PEM).decode("ascii")
_FAKE_KEY_B64 = base64.b64encode(_FAKE_KEY_PEM).decode("ascii")


def _kubectl_view_bearer(context: str = "my-ctx") -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": context,
        "clusters": [{"name": "my-cluster", "cluster": {
            "server": "https://api.example.com:6443",
            "certificate-authority-data": _FAKE_CA_B64,
        }}],
        "users": [{"name": "my-user", "user": {"token": "real-token-abc"}}],
        "contexts": [{"name": context, "context": {
            "cluster": "my-cluster", "user": "my-user",
        }}],
    }


def _kubectl_view_client_cert(context: str = "cert-ctx") -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": context,
        "clusters": [{"name": "cert-cluster", "cluster": {
            "server": "https://192.168.1.100:6443",
            "certificate-authority-data": _FAKE_CA_B64,
        }}],
        "users": [{"name": "cert-user", "user": {
            "client-certificate-data": _FAKE_CERT_B64,
            "client-key-data": _FAKE_KEY_B64,
        }}],
        "contexts": [{"name": context, "context": {
            "cluster": "cert-cluster", "user": "cert-user",
        }}],
    }


def _run_resolve(context_names, side_effects):
    """Call kube.resolve with kubectl monkey-patched."""
    with mock.patch("agent_uplink.kube.run_command") as m:
        m.side_effect = [json.dumps(d) for d in side_effects]
        return kube.resolve(None, context_names, _FAKE_MITM_CA)


# ---------------------------------------------------------------------------
# Bearer token
# ---------------------------------------------------------------------------


def test_bearer_rule_injects_real_token():
    plan = _run_resolve(["my-ctx"], [_kubectl_view_bearer()])
    assert len(plan.rules) == 1
    rule = plan.rules[0]
    assert rule["name"] == "kube-my-ctx"
    assert rule["inject"]["headers"]["Authorization"] == "Bearer real-token-abc"


def test_bearer_host_regex_escapes_dots():
    plan = _run_resolve(["my-ctx"], [_kubectl_view_bearer()])
    # api.example.com -> re.escape -> api\.example\.com
    assert plan.rules[0]["host"] == r"api\.example\.com"


def test_bearer_pod_kubeconfig_strips_real_token():
    plan = _run_resolve(["my-ctx"], [_kubectl_view_bearer()])
    kc = yaml.safe_load(plan.pod_kubeconfig)
    user = kc["users"][0]["user"]
    assert user["token"] == kube._BEARER_PLACEHOLDER
    assert "real-token-abc" not in plan.pod_kubeconfig.decode()


def test_bearer_pod_kubeconfig_trusts_mitm_ca():
    plan = _run_resolve(["my-ctx"], [_kubectl_view_bearer()])
    kc = yaml.safe_load(plan.pod_kubeconfig)
    ca_data = kc["clusters"][0]["cluster"]["certificate-authority-data"]
    assert base64.b64decode(ca_data) == _FAKE_MITM_CA


def test_bearer_no_client_certs():
    plan = _run_resolve(["my-ctx"], [_kubectl_view_bearer()])
    assert plan.client_certs == {}


def test_bearer_upstream_ca_bundle():
    plan = _run_resolve(["my-ctx"], [_kubectl_view_bearer()])
    assert _FAKE_CA_PEM in plan.upstream_ca_bundle


# ---------------------------------------------------------------------------
# Client certificate
# ---------------------------------------------------------------------------


def test_client_cert_rule_has_no_inject_headers():
    plan = _run_resolve(["cert-ctx"], [_kubectl_view_client_cert()])
    rule = plan.rules[0]
    assert rule["name"] == "kube-cert-ctx"
    assert "inject" not in rule


def test_client_cert_stored_for_mitm():
    plan = _run_resolve(["cert-ctx"], [_kubectl_view_client_cert()])
    assert "192.168.1.100.pem" in plan.client_certs
    pem = plan.client_certs["192.168.1.100.pem"]
    assert _FAKE_CERT_PEM in pem
    assert _FAKE_KEY_PEM in pem


def test_client_cert_pod_kubeconfig_strips_key():
    plan = _run_resolve(["cert-ctx"], [_kubectl_view_client_cert()])
    kc = yaml.safe_load(plan.pod_kubeconfig)
    user = kc["users"][0]["user"]
    assert "client-key-data" not in user
    assert "client-certificate-data" not in user


def test_client_cert_pod_kubeconfig_trusts_mitm_ca():
    plan = _run_resolve(["cert-ctx"], [_kubectl_view_client_cert()])
    kc = yaml.safe_load(plan.pod_kubeconfig)
    ca_data = kc["clusters"][0]["cluster"]["certificate-authority-data"]
    assert base64.b64decode(ca_data) == _FAKE_MITM_CA


# ---------------------------------------------------------------------------
# Pod kubeconfig structure
# ---------------------------------------------------------------------------


def test_pod_kubeconfig_server_url_unchanged():
    plan = _run_resolve(["my-ctx"], [_kubectl_view_bearer()])
    kc = yaml.safe_load(plan.pod_kubeconfig)
    assert kc["clusters"][0]["cluster"]["server"] == "https://api.example.com:6443"


def test_pod_kubeconfig_current_context_is_first():
    views = [_kubectl_view_bearer("ctx-a"), _kubectl_view_client_cert("ctx-b")]
    # Patch bearer view to use a different server so hosts don't clash
    views[1]["clusters"][0]["cluster"]["server"] = "https://other.example.com:6443"
    plan = _run_resolve(["ctx-a", "ctx-b"], views)
    kc = yaml.safe_load(plan.pod_kubeconfig)
    assert kc["current-context"] == "ctx-a"


def test_empty_context_list_returns_empty_plan():
    plan = kube.resolve(None, [], _FAKE_MITM_CA)
    assert plan.rules == []
    assert plan.client_certs == {}
    assert plan.upstream_ca_bundle == b""
    assert plan.pod_kubeconfig == b""


# ---------------------------------------------------------------------------
# Multiple contexts / upstream CA bundle
# ---------------------------------------------------------------------------


def test_two_contexts_ca_bundle_contains_both():
    view_a = _kubectl_view_bearer("ctx-a")
    ca_a = b"-----BEGIN CERTIFICATE-----\nCA-A\n-----END CERTIFICATE-----\n"
    view_a["clusters"][0]["cluster"]["certificate-authority-data"] = (
        base64.b64encode(ca_a).decode()
    )

    view_b = _kubectl_view_client_cert("ctx-b")
    view_b["clusters"][0]["cluster"]["server"] = "https://other.example.com:6443"
    ca_b = b"-----BEGIN CERTIFICATE-----\nCA-B\n-----END CERTIFICATE-----\n"
    view_b["clusters"][0]["cluster"]["certificate-authority-data"] = (
        base64.b64encode(ca_b).decode()
    )

    plan = _run_resolve(["ctx-a", "ctx-b"], [view_a, view_b])
    assert ca_a in plan.upstream_ca_bundle
    assert ca_b in plan.upstream_ca_bundle


# ---------------------------------------------------------------------------
# Error cases
# ---------------------------------------------------------------------------


def test_insecure_skip_tls_verify_raises():
    data = _kubectl_view_bearer()
    data["clusters"][0]["cluster"]["insecure-skip-tls-verify"] = True
    del data["clusters"][0]["cluster"]["certificate-authority-data"]
    with pytest.raises(ValueError, match="insecure-skip-tls-verify"):
        _run_resolve(["my-ctx"], [data])


def test_missing_cluster_ca_raises():
    data = _kubectl_view_bearer()
    del data["clusters"][0]["cluster"]["certificate-authority-data"]
    with pytest.raises(ValueError, match="certificate-authority-data"):
        _run_resolve(["my-ctx"], [data])


def test_exec_credentials_raise():
    data = _kubectl_view_bearer()
    data["users"][0]["user"] = {"exec": {"command": "aws"}}
    with pytest.raises(ValueError, match="exec"):
        _run_resolve(["my-ctx"], [data])


def test_auth_provider_raises():
    data = _kubectl_view_bearer()
    data["users"][0]["user"] = {"auth-provider": {"name": "gcp"}}
    with pytest.raises(ValueError, match="exec and auth-provider"):
        _run_resolve(["my-ctx"], [data])


def test_username_password_raises():
    data = _kubectl_view_bearer()
    data["users"][0]["user"] = {"username": "admin", "password": "s3cr3t"}
    with pytest.raises(ValueError, match="username/password"):
        _run_resolve(["my-ctx"], [data])


def test_no_credentials_raises():
    data = _kubectl_view_bearer()
    data["users"][0]["user"] = {}
    with pytest.raises(ValueError, match="no supported credentials"):
        _run_resolve(["my-ctx"], [data])


def test_duplicate_host_raises():
    view_a = _kubectl_view_bearer("ctx-a")
    view_b = _kubectl_view_bearer("ctx-b")  # same server host
    with pytest.raises(ValueError, match="both resolve to API server host"):
        _run_resolve(["ctx-a", "ctx-b"], [view_a, view_b])


def test_no_cluster_in_view_raises():
    data = _kubectl_view_bearer()
    data["clusters"] = []
    with pytest.raises(ValueError, match="no cluster found"):
        _run_resolve(["my-ctx"], [data])


def test_no_user_in_view_raises():
    data = _kubectl_view_bearer()
    data["users"] = []
    with pytest.raises(ValueError, match="no user found"):
        _run_resolve(["my-ctx"], [data])


# ---------------------------------------------------------------------------
# tokenFile path
# ---------------------------------------------------------------------------


def test_token_file_is_read(tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("file-token-xyz\n")

    data = _kubectl_view_bearer()
    data["users"][0]["user"] = {"tokenFile": str(token_file)}

    plan = _run_resolve(["my-ctx"], [data])
    assert plan.rules[0]["inject"]["headers"]["Authorization"] == "Bearer file-token-xyz"
    assert "file-token-xyz" not in yaml.safe_load(plan.pod_kubeconfig)["users"][0]["user"].get("token", "")
