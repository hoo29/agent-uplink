"""Shared fixtures for the agent-uplink test suite.

Unit tests (tests/unit) need nothing here. Integration tests (tests/integration)
depend on the `cluster` fixture, which skips the whole integration suite when no
usable kubectl/cluster is present, so `pytest` stays green on a bare checkout.
"""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from tests.integration import harness

HOST_MITM_CERTS = Path.home() / ".agent_uplink" / "mitm"
_REQUIRED_CERT_FILES = (
    "mitmproxy-ca.pem",
    "mitmproxy-ca-cert.pem",
    "mitmproxy-dhparam.pem",
)


# --------------------------------------------------------------------------- #
# Session handle
# --------------------------------------------------------------------------- #


@dataclass
class Session:
    """A deployed test namespace plus convenience exec helpers."""

    ns: str
    extra: dict = field(default_factory=dict)

    def agent(self, script: str, **kw):
        return harness.kexec_sh(self.ns, "agent", script, **kw)

    def exec(self, pod: str, script: str, **kw):
        return harness.kexec_sh(self.ns, pod, script, **kw)

    def pod_ip(self, pod: str) -> str:
        return harness.get_pod_ip(self.ns, pod)


def _new_ns() -> str:
    return f"autest-{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# Cluster / image prerequisites
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def cluster() -> None:
    """Skip the integration suite unless a usable cluster + registry is present."""
    try:
        proc = subprocess.run(
            ["kubectl", "get", "nodes"],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"no usable kubectl/cluster: {exc}")
    if proc.returncode != 0:
        pytest.skip(f"kubectl get nodes failed: {proc.stderr.strip()}")
    # The agent-egress DNS rule selects kube-system pods labelled k8s-app=kube-dns
    # (cli.py). If the cluster's DNS pods aren't labelled that way, the agent
    # couldn't resolve anything and unrelated tests would fail deep in curl/nc —
    # fail fast with a clear message instead.
    dns = subprocess.run(
        ["kubectl", "get", "pods", "-n", "kube-system", "-l", "k8s-app=kube-dns",
         "-o", "name"],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if dns.returncode != 0 or not dns.stdout.strip():
        pytest.skip(
            "no kube-system pod labelled k8s-app=kube-dns; the agent-egress DNS "
            "rule won't match on this cluster"
        )


@pytest.fixture(scope="session")
def mitm_certs_dir(cluster) -> Path:
    """The mitm CA. Reuse the host's copy if a previous agent-uplink run created
    it; otherwise generate it via the same one-shot bootstrap pod the product
    uses, so a fresh runner is self-sufficient."""
    missing = [f for f in _REQUIRED_CERT_FILES if not (HOST_MITM_CERTS / f).exists()]
    if missing:
        from agent_uplink import bootstrap

        try:
            bootstrap.ensure_mitm_certs(HOST_MITM_CERTS, harness.MITM_IMAGE)
        except Exception as exc:  # noqa: BLE001
            pytest.skip(f"could not generate mitm certs: {exc}")
    return HOST_MITM_CERTS


def _registry_serving() -> bool:
    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen("http://localhost:5000/v2/", timeout=4):
            return True
    except urllib.error.HTTPError:
        return True  # 401/etc still means something is answering
    except Exception:
        return False


@pytest.fixture(scope="session")
def test_image(cluster, mitm_certs_dir) -> str:
    """Build + push the probe/echo/dockerd image. Only bootstraps the local registry
    when it isn't already serving — re-applying the Deployment over a running
    registry forces a rollout that deadlocks on the held hostPort 5000."""
    if not _registry_serving():
        from agent_uplink import bootstrap

        try:
            bootstrap.check_registries_yaml()
        except SystemExit as exc:
            pytest.skip(f"local registry not configured for k3s: {exc}")
        bootstrap.ensure_registry()
    return harness.build_test_image(mitm_certs_dir)


# --------------------------------------------------------------------------- #
# Deploy helper
# --------------------------------------------------------------------------- #


def _deploy(ns: str, manifests: list[dict], ready_pods: list[str]) -> None:
    harness.apply([harness.namespace(ns), *manifests])
    for pod in ready_pods:
        harness.wait_ready(ns, pod, timeout=150)


# --------------------------------------------------------------------------- #
# Topology fixtures (one deployed namespace each, session-scoped for speed)
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="session")
def core_session(cluster, test_image, mitm_certs_dir):
    """mitm + echo (echo/plain/pathsvc aliases) + agent probe with dummy AWS and
    fake OAuth creds mounted. Rules inject a sentinel bearer on host `echo`, gate
    a POST path on host `pathsvc`, and otherwise fall through to the generic GET
    allow. Shared by the injector, credentials and network-policy tests."""
    ns = _new_ns()
    rules_yaml = f"""
rules:
  - name: echo-inject
    host: 'echo'
    methods: [GET, POST]
    inject:
      headers:
        Authorization: 'Bearer {harness.INJECT_SENTINEL}'
        X-Injected: 'sentinel'
  - name: pathsvc-rule
    host: 'pathsvc'
    methods: [POST]
    paths:
      - '/allowed/.*'
"""
    rules_bytes = harness.resolve_rules(rules_yaml)
    aws_secret, _akia = harness.dummy_aws_secret(ns, [harness.TEST_PROFILE])
    manifests = [
        *harness.control_plane(ns, mitm_certs_dir, rules_bytes),
        aws_secret,
        harness.fake_creds_secret(ns),
        *harness.network_policies(ns),
        *harness.mitm(ns),
        *harness.echo(ns, ["echo", "plain", "pathsvc"]),
        *harness.agent_probe(
            ns,
            env_extra={"AWS_BEARER_TOKEN_BEDROCK": "placeholder"},
            mount_dummy_creds=True,
            mount_fake_creds=True,
        ),
    ]
    try:
        _deploy(ns, manifests, ["mitm", "echo", "agent"])
        harness.warmup_http(ns, "echo")
        harness.warmup_http(ns, "echo", scheme="https")
        # Negative gate: prove default-deny is actually enforced (not just that
        # the allow path is up) before the network-policy deny tests run.
        harness.warmup_denied(
            ns, harness.get_pod_ip(ns, "echo"), 8080,
            desc="default-deny active (agent cannot reach echo directly)",
        )
        yield Session(ns=ns)
    finally:
        harness.delete_namespace(ns)


@pytest.fixture(scope="session")
def sigv4_session(cluster, test_image, mitm_certs_dir):
    """mitm (with the real per-AKIA creds Secret mounted, carrying a sentinel
    secret) + agent. The rules carry no allowed AWS host, so a signed request to
    an AWS host is denied at the allow-list — proving a signature is not a
    backdoor — and the suite never reaches real AWS. The re-sign+forward crypto
    is validated by the live test (see tests/README); here we pin the allow-list
    gate and the real-creds isolation in the mitm pod."""
    ns = _new_ns()
    akia = harness.aws.dummy_akia(harness.TEST_PROFILE)
    # Generic defaults allow GET everywhere, so the deny probe uses POST.
    rules_bytes = harness.resolve_rules(None)
    creds_secret = harness.real_aws_creds_secret(ns)
    manifests = [
        *harness.control_plane(ns, mitm_certs_dir, rules_bytes),
        *harness.network_policies(ns),
        *harness.mitm(ns, aws_creds_secret=creds_secret["metadata"]["name"]),
        creds_secret,
        *harness.agent_probe(ns),
    ]
    try:
        _deploy(ns, manifests, ["mitm", "agent"])

        def _warm():
            rc, out, _err = harness.kexec_sh(
                ns,
                "agent",
                harness.aws_signed_curl(
                    "s3.us-east-1.amazonaws.com", "/warmup",
                    akia=akia, method="POST", code_only=True,
                ),
                timeout=20,
            )
            return out.strip() == "403", f"rc={rc} code={out.strip()!r}"

        harness.wait_until(_warm, desc="mitm denies unlisted signed AWS request")
        yield Session(ns=ns, extra={"akia": akia})
    finally:
        harness.delete_namespace(ns)


@pytest.fixture(scope="session")
def ssh_session(cluster, test_image, mitm_certs_dir):
    """agent + a TCP listener on :22 and :80. The agent-egress policy is built
    with --ssh-cidr = <listener IP>/32, so :22 must be reachable and :80 must
    not — proving SSH egress is scoped to exactly the CIDR and port."""
    ns = _new_ns()
    try:
        # Stage 1: namespace + listener, so we can read its pod IP before writing
        # the ipBlock the NetworkPolicy needs.
        harness.apply(
            [harness.namespace(ns), *harness.tcp_listener(ns, "ssh-target", [22, 80])]
        )
        harness.wait_ready(ns, "ssh-target", timeout=150)
        target_ip = harness.get_pod_ip(ns, "ssh-target")
        # Stage 2: policies (scoped to the listener IP) + agent. mitm is unused by
        # the SSH tests but is deployed for parity; generic default rules suffice.
        rules_bytes = harness.resolve_rules(None)
        manifests = [
            *harness.control_plane(ns, mitm_certs_dir, rules_bytes),
            *harness.network_policies(ns, ssh_cidrs=[f"{target_ip}/32"]),
            *harness.mitm(ns),
            *harness.agent_probe(ns),
        ]
        harness.apply(manifests)
        harness.wait_ready(ns, "mitm", timeout=150)
        harness.wait_ready(ns, "agent", timeout=150)

        def _warm():
            rc, out, _err = harness.kexec_sh(
                ns, "agent", f"nc -z -w3 {target_ip} 22; echo rc=$?", timeout=20
            )
            return "rc=0" in out, f"rc={rc} out={out.strip()!r}"

        harness.wait_until(_warm, desc="ssh egress to :22 live")
        # Negative gate: :80 to the same target must be denied before we assert it.
        harness.warmup_denied(
            ns, target_ip, 80, desc="ssh egress scoped to :22 only (:80 denied)"
        )
        yield Session(ns=ns, extra={"target_ip": target_ip})
    finally:
        harness.delete_namespace(ns)


@pytest.fixture(scope="session")
def dockerd_session(cluster, test_image):
    """A single privileged pod on the default runtime running its own dockerd."""
    ns = _new_ns()
    try:
        _deploy(ns, harness.dockerd_pod(ns), ["dockerd"])

        def _warm():
            rc, out, _err = harness.kexec_sh(
                ns, "dockerd", "docker info --format '{{.ServerVersion}}'", timeout=20
            )
            return rc == 0 and out.strip() != "", f"rc={rc} out={out.strip()!r}"

        harness.wait_until(_warm, timeout=120, desc="in-pod dockerd ready")
        yield Session(ns=ns)
    finally:
        harness.delete_namespace(ns)
