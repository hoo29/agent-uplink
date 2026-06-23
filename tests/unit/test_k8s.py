"""Unit tests for k8s.py manifest-builder branch logic that the cli/bootstrap
tests don't pin directly: resource request defaulting (the QoS contract every
pod relies on), NetworkPolicy policyTypes derivation (which directions a policy
actually restricts), and the wait_for_pod_succeeded failure/timeout paths."""

import itertools

import pytest

from agent_uplink import k8s
from agent_uplink.k8s import Resources, container_spec, network_policy_manifest


# --------------------------------------------------------------------------- #
# Resources -> requests/limits
# --------------------------------------------------------------------------- #


def test_requests_default_to_limits_when_unset():
    # No *_request given: requests mirror limits (matches Kubernetes' own default
    # when requests is omitted), so a caller that only sets a cap is unchanged.
    c = container_spec(image="x", resources=Resources(memory="512Mi", cpu="500m"))
    assert c["resources"]["limits"] == {"memory": "512Mi", "cpu": "500m"}
    assert c["resources"]["requests"] == {"memory": "512Mi", "cpu": "500m"}


def test_requests_below_limits_give_burstable():
    c = container_spec(
        image="x",
        resources=Resources(
            memory="1Gi", cpu="1", memory_request="256Mi", cpu_request="100m"
        ),
    )
    assert c["resources"]["limits"] == {"memory": "1Gi", "cpu": "1"}
    assert c["resources"]["requests"] == {"memory": "256Mi", "cpu": "100m"}


def test_cpu_none_omits_cpu_limit():
    # cpu=None means no CPU limit (uncapped burst) while still reserving the
    # request — Kubernetes leaves a container with no CPU limit uncapped.
    c = container_spec(
        image="x",
        resources=Resources(memory="512Mi", cpu=None, cpu_request="500m"),
    )
    assert c["resources"]["limits"] == {"memory": "512Mi"}
    assert c["resources"]["requests"] == {"memory": "512Mi", "cpu": "500m"}


# --------------------------------------------------------------------------- #
# network_policy_manifest policyTypes derivation
# --------------------------------------------------------------------------- #


def test_ingress_only_policy_omits_egress():
    p = network_policy_manifest("n", "ns", pod_selector={}, ingress=[{}])
    assert p["spec"]["policyTypes"] == ["Ingress"]
    assert "egress" not in p["spec"]


def test_egress_only_policy_omits_ingress():
    # The real agent-egress policy is egress-only; a wrong derivation here would
    # silently leave ingress (or egress) unrestricted.
    p = network_policy_manifest("n", "ns", pod_selector={}, egress=[{}])
    assert p["spec"]["policyTypes"] == ["Egress"]
    assert "ingress" not in p["spec"]


def test_both_directions_policy():
    p = network_policy_manifest("n", "ns", pod_selector={}, ingress=[], egress=[])
    assert p["spec"]["policyTypes"] == ["Ingress", "Egress"]
    assert p["spec"]["ingress"] == []
    assert p["spec"]["egress"] == []


# --------------------------------------------------------------------------- #
# wait_for_pod_succeeded
# --------------------------------------------------------------------------- #


def test_wait_for_pod_succeeded_raises_with_logs_on_failure(monkeypatch):
    # First kubectl returns the phase, second returns the logs included in the
    # error so a failure is diagnosable without re-querying.
    calls = iter(["Failed", "container crashed: boom"])
    monkeypatch.setattr(k8s, "kubectl", lambda *a, **k: next(calls))
    monkeypatch.setattr(k8s.time, "monotonic", lambda: 0.0)
    with pytest.raises(RuntimeError, match="pod pod failed") as exc:
        k8s.wait_for_pod_succeeded("ns", "pod", timeout=120)
    assert "container crashed: boom" in str(exc.value)


def test_wait_for_pod_succeeded_times_out_with_last_phase(monkeypatch):
    clock = itertools.chain([1000.0, 1000.5], itertools.repeat(2000.0))
    monkeypatch.setattr(k8s.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(k8s.time, "sleep", lambda s: None)
    monkeypatch.setattr(k8s, "kubectl", lambda *a, **k: "Pending")
    # The last observed phase is surfaced in the timeout message for debugging.
    with pytest.raises(TimeoutError, match="Pending"):
        k8s.wait_for_pod_succeeded("ns", "pod", timeout=1)


# --------------------------------------------------------------------------- #
# list_namespaces
# --------------------------------------------------------------------------- #


def test_list_namespaces_parses_items(monkeypatch):
    monkeypatch.setattr(
        k8s, "kubectl", lambda *a, **k: '{"items": [{"metadata": {"name": "a"}}]}'
    )
    items = k8s.list_namespaces("managed-by=agent-uplink")
    assert items == [{"metadata": {"name": "a"}}]


def test_list_namespaces_empty_output_returns_empty_list(monkeypatch):
    # No matches: kubectl prints nothing (raise_error=False), not valid JSON.
    monkeypatch.setattr(k8s, "kubectl", lambda *a, **k: "")
    assert k8s.list_namespaces("managed-by=agent-uplink") == []


def test_list_namespaces_malformed_json_returns_empty_list(monkeypatch):
    monkeypatch.setattr(k8s, "kubectl", lambda *a, **k: "not json")
    assert k8s.list_namespaces("managed-by=agent-uplink") == []
