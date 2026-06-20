"""Test harness for the live-cluster integration tests.

The guiding principle: assemble each session out of the **real** production
manifest builders and rule resolver so the tests exercise the code that ships,
not a parallel reimplementation. Only two things are swapped for testability:

  * the agent image — a lightweight probe image (see testimage/) instead of the
    full Claude image, and the **default runtime with privileged=true** instead
    of `runtimeClassName: kata-*`, so the suite runs on any k3s (incl. GitHub
    runners) without kata installed;
  * the upstreams — an in-cluster `echo` server that reflects the request it
    received, standing in for the real internet/AWS endpoints so we can observe
    exactly what mitm forwarded, injected or stripped.

Everything security-relevant (NetworkPolicies, the mitm addon, rule layering,
dummy-credential derivation, the SigV4 reroute map) comes straight from
`agent_uplink.*`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from agent_uplink import aws, cli, k8s, rules
from agent_uplink.agents.base import Agent, PreparedAgent
from agent_uplink.agents.claude import config

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

TESTIMAGE_DIR = Path(__file__).resolve().parent / "testimage"

TEST_IMAGE_REPO = "agent-uplink-test"
# Overwritten by build_test_image() with a content-addressed tag. Manifest
# builders read this module global at call time (build runs first, via the
# test_image fixture), so a content tag means concurrent runs on a shared
# registry never clobber each other and pulls are immutable.
TEST_IMAGE = f"localhost:5000/{TEST_IMAGE_REPO}:latest"
MITM_IMAGE = cli.DEFAULT_MITM_IMAGE

# A value that lands in the mitm-injected Authorization header. It must reach the
# upstream (proving injection works) but must appear NOWHERE inside the agent pod
# (proving the real secret never enters the sandbox). The same sentinel ties the
# injector test and the credentials test together.
INJECT_SENTINEL = "INJECTED-BEARER-SENTINEL-9f2c7a1e"
# Stand-in for a real OAuth access token handed to the production fake-creds
# builder. The agent pod must only ever see the fake token, never this value.
REAL_OAUTH_SENTINEL = "REAL-OAUTH-TOKEN-DO-NOT-LEAK-abc123def456"
# Stand-in for a real AWS secret key. It must be readable in the mitm pod (which
# re-signs) but never reachable from the agent pod.
REAL_AWS_SENTINEL = "REAL-AWS-SECRET-DO-NOT-LEAK-9988776655"

TEST_PROFILE = "testprofile"

AGENT_CONTAINER = "main"
ECHO_LABEL = {"app": "echo-upstream"}


# --------------------------------------------------------------------------- #
# kubectl / docker helpers
# --------------------------------------------------------------------------- #


def _run(argv: list[str], *, timeout: int | None = None) -> tuple[int, str, str]:
    proc = subprocess.run(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    return proc.returncode, proc.stdout, proc.stderr


def kexec(
    ns: str,
    pod: str,
    argv: list[str],
    *,
    container: str = AGENT_CONTAINER,
    timeout: int = 60,
) -> tuple[int, str, str]:
    """Run argv inside a pod container. Returns (rc, stdout, stderr)."""
    return _run(
        ["kubectl", "exec", "-n", ns, pod, "-c", container, "--", *argv],
        timeout=timeout,
    )


def kexec_sh(ns: str, pod: str, script: str, **kw) -> tuple[int, str, str]:
    return kexec(ns, pod, ["sh", "-c", script], **kw)


def get_pod_ip(ns: str, pod: str) -> str:
    rc, out, err = _run(
        ["kubectl", "get", "pod", pod, "-n", ns, "-o", "jsonpath={.status.podIP}"]
    )
    if rc != 0 or not out.strip():
        raise RuntimeError(f"could not get IP for pod {pod}: {err}")
    return out.strip()


# Every session-scoped fixture keeps its namespace alive for the whole run, so
# all sessions' pods coexist on the single CI node. The production manifests set
# only `limits` (mitm alone is 1 CPU), and Kubernetes defaults `requests` to
# `limits`, so four namespaces' worth would request ~7 CPU and never schedule on
# a GitHub runner (4 vCPU). The suite tests network/credential/SigV4 behaviour,
# not resource enforcement, so collapse every pod to a tiny request with no
# limit: the scheduler can pack them all, and nothing is CPU-throttled or
# OOM-killed during warmup.
_CI_POD_RESOURCES = {"requests": {"cpu": "10m", "memory": "32Mi"}}


def _relax_pod_resources(manifests: list[dict]) -> None:
    for m in manifests:
        if m.get("kind") != "Pod":
            continue
        for container in m.get("spec", {}).get("containers", []):
            container["resources"] = {k: dict(v) for k, v in _CI_POD_RESOURCES.items()}


def apply(manifests: list[dict]) -> None:
    _relax_pod_resources(manifests)
    k8s.apply_manifests(manifests)


def wait_ready(ns: str, pod: str, *, timeout: int = 120) -> None:
    k8s.wait_for_pod_ready(ns, pod, timeout=timeout)


def wait_until(predicate, *, timeout: int = 90, interval: float = 3.0, desc: str = "condition") -> None:
    """Poll `predicate` (returns (ok, info)) until it's truthy or we time out.

    Used to gate tests on the full data path being live: `kubectl wait Ready`
    returns when a pod's container is up, but Service endpoints and the
    NetworkPolicy rules (kube-proxy / kube-router) are programmed a beat later,
    so the first proxied request can race ahead of them and 502."""
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            ok, last = predicate()
        except Exception as exc:  # noqa: BLE001 - surface as the failure info
            ok, last = False, repr(exc)
        if ok:
            return
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {desc}; last={last}")


def warmup_http(ns: str, host: str, *, scheme: str = "http", expect: str = "200") -> None:
    """Block until the agent can reach `scheme://host/` through mitm and get the
    expected status, so the topology is hot before assertions run."""

    def _probe():
        rc, out, err = kexec_sh(
            ns,
            "agent",
            f"curl -s --max-time 8 -o /dev/null -w '%{{http_code}}' {scheme}://{host}/",
            timeout=20,
        )
        return out.strip() == expect, f"rc={rc} code={out.strip()!r} err={err[-200:]}"

    wait_until(_probe, desc=f"agent -> mitm -> {scheme}://{host} = {expect}")


def warmup_denied(ns: str, host: str, port: int, *, desc: str) -> None:
    """Block until a connect from the agent to host:port actually FAILS.

    The positive warmup only proves the allow path is programmed; it's satisfied
    whether the deny policies are live yet or not (a fail-open window). Gating on
    a known-denied probe failing proves default-deny + agent-egress are actually
    enforced before the negative assertions run."""

    def _probe():
        _, out, _ = kexec_sh(
            ns, "agent", f"nc -z -w4 {host} {port}; echo rc=$?", timeout=20
        )
        return "rc=0" not in out, f"out={out.strip()!r}"

    wait_until(_probe, desc=desc)


def delete_namespace(ns: str) -> None:
    k8s.delete_namespace(ns, wait=False)


# --------------------------------------------------------------------------- #
# Test image build
# --------------------------------------------------------------------------- #


def build_test_image(certs_dir: Path) -> str:
    """Build + push the probe/echo/dockerd image to the local registry. The mitm
    public CA cert is baked in so the probe's curl trusts mitm's interception.

    The image is tagged by a hash of its inputs (Dockerfile + echo.py + CA cert)
    and the chosen tag is published to the module global TEST_IMAGE, which the
    manifest builders read."""
    global TEST_IMAGE
    digest = hashlib.sha256()
    for f in ("Dockerfile", "echo.py"):
        digest.update((TESTIMAGE_DIR / f).read_bytes())
    digest.update((certs_dir / "mitmproxy-ca-cert.pem").read_bytes())
    TEST_IMAGE = f"localhost:5000/{TEST_IMAGE_REPO}:{digest.hexdigest()[:16]}"
    with tempfile.TemporaryDirectory(prefix="agent-uplink-testimg-") as td:
        ctx = Path(td)
        shutil.copy2(TESTIMAGE_DIR / "Dockerfile", ctx / "Dockerfile")
        shutil.copy2(TESTIMAGE_DIR / "echo.py", ctx / "echo.py")
        shutil.copy2(certs_dir / "mitmproxy-ca-cert.pem", ctx / "mitm-ca.pem")
        rc, out, err = _run(
            ["docker", "build", "-t", TEST_IMAGE, str(ctx)], timeout=600
        )
        if rc != 0:
            raise RuntimeError(f"docker build failed:\n{out}\n{err}")
    rc, out, err = _run(["docker", "push", TEST_IMAGE], timeout=300)
    if rc != 0:
        raise RuntimeError(f"docker push failed:\n{out}\n{err}")
    return TEST_IMAGE


# --------------------------------------------------------------------------- #
# Rule resolution (reuses the real resolver)
# --------------------------------------------------------------------------- #


class NullAgent(Agent):
    """Minimal Agent so we can drive the real rules.resolve()/layering without a
    concrete agent. Contributes no default rules and no auth."""

    name = "null"

    @classmethod
    def add_cli_args(cls, parser) -> None:  # pragma: no cover - unused
        pass

    def default_rules(self) -> list[dict]:
        return []

    def discover_aws_profiles(self) -> list[str]:
        return []

    def prepare(self, session, aws_profile_names) -> PreparedAgent:
        return PreparedAgent()


def resolve_rules(
    rules_yaml: str | None,
    *,
    no_default_rules: bool = False,
    auth_rules: list[dict] | None = None,
) -> bytes:
    """Run the production rule resolver on an inline YAML string."""
    path = None
    if rules_yaml is not None:
        tmp = tempfile.NamedTemporaryFile(
            "w", suffix=".yaml", delete=False, prefix="agent-uplink-rules-"
        )
        tmp.write(rules_yaml)
        tmp.close()
        path = Path(tmp.name)
    return rules.resolve(
        path,
        no_default_rules,
        NullAgent(args=argparse.Namespace()),
        auth_rules or [],
        allow_exec=False,
    )


# --------------------------------------------------------------------------- #
# Manifest builders
# --------------------------------------------------------------------------- #


def namespace(ns: str) -> dict:
    # PSA enforce=privileged so the privileged probe/dockerd pods are admitted.
    return k8s.namespace_manifest(
        ns,
        labels={
            "managed-by": "agent-uplink-tests",
            "pod-security.kubernetes.io/enforce": "privileged",
        },
    )


def control_plane(ns: str, certs_dir: Path, rules_bytes: bytes) -> list[dict]:
    """The mitm addon ConfigMap, resolved-rules Secret and CA Secret that the
    real `cli._mitm_manifests` mounts (`mitm-addon`, `rules-json`, `mitm-certs`)."""
    return [
        k8s.configmap_manifest(
            "mitm-addon", ns, {"filter.py": cli.ADDON_PATH.read_text("utf-8")}
        ),
        k8s.secret_manifest("rules-json", ns, {"rules.json": rules_bytes}),
        k8s.secret_manifest(
            "mitm-certs",
            ns,
            {
                "mitmproxy-ca.pem": (certs_dir / "mitmproxy-ca.pem").read_bytes(),
                "mitmproxy-ca-cert.pem": (
                    certs_dir / "mitmproxy-ca-cert.pem"
                ).read_bytes(),
                "mitmproxy-dhparam.pem": (
                    certs_dir / "mitmproxy-dhparam.pem"
                ).read_bytes(),
            },
        ),
    ]


def mitm(ns: str, *, ssl_insecure: bool = True, aws_creds_secret: str | None = None) -> list[dict]:
    """Real mitm Pod+Service. `ssl_insecure` appends --ssl-insecure (test-only)
    so mitm doesn't reject the self-signed cert on the *upstream* (echo) leg;
    the agent->mitm leg still validates mitm's real CA, which is what we test.
    `aws_creds_secret` mounts the real per-AKIA creds the addon re-signs with."""
    manifests = cli._mitm_manifests(ns, MITM_IMAGE, "", aws_creds_secret=aws_creds_secret)
    if ssl_insecure:
        pod = next(m for m in manifests if m["kind"] == "Pod")
        pod["spec"]["containers"][0]["args"].append("--ssl-insecure")
    return manifests


def network_policies(
    ns: str, *, ssh_cidrs: list[str] | None = None, ssh_relay: bool = False
) -> list[dict]:
    """The real per-session NetworkPolicies (default-deny, agent-egress,
    mitm-policy, and the ssh-agent holder ingress when ssh_relay)."""
    return cli._network_policies(ns, ssh_cidrs, ssh_relay=ssh_relay)


def real_aws_creds_secret(ns: str, profile: str = TEST_PROFILE) -> dict:
    """The real-AWS-creds Secret the orchestrator mounts into the mitm pod: a
    JSON map from the profile's dummy AKIA to its real credentials, carrying a
    sentinel secret key so a test can confirm it lives in mitm, not the agent."""
    blob = aws.sigv4_credentials_json(
        {
            aws.dummy_akia(profile): {
                "access_key_id": "AKIAREALEXAMPLE",
                "secret_access_key": REAL_AWS_SENTINEL,
            }
        }
    )
    return k8s.secret_manifest("aws-sigv4-creds", ns, {"creds.json": blob})


def echo(
    ns: str,
    services: list[str],
    *,
    labels_extra: dict | None = None,
    allow_ingress_from_mitm: bool = True,
) -> list[dict]:
    """Echo upstream Pod + one Service per alias name. Each Service exposes
    :80->8080 (http) and :443->8443 (https). Optionally adds a NetworkPolicy
    granting it ingress from mitm (echo is an in-cluster stand-in for the
    internet, which the production default-deny would otherwise block)."""
    labels = dict(ECHO_LABEL)
    if labels_extra:
        labels.update(labels_extra)
    container = k8s.container_spec(
        name=AGENT_CONTAINER,
        image=TEST_IMAGE,
        command=["python3", "/echo.py"],
        image_pull_policy="Always",
        ports=[
            {"containerPort": 8080, "protocol": "TCP"},
            {"containerPort": 8443, "protocol": "TCP"},
        ],
        resources=k8s.Resources(memory="128Mi", cpu="500m"),
    )
    # Only register Service endpoints once the server is actually listening, so
    # mitm never connects to a half-started upstream.
    container["readinessProbe"] = {
        "tcpSocket": {"port": 8080},
        "periodSeconds": 1,
        "initialDelaySeconds": 1,
    }
    pod = k8s.pod_manifest(
        "echo",
        ns,
        labels=labels,
        spec=k8s.pod_spec(container=container, restart_policy="Always"),
    )
    manifests: list[dict] = [pod]
    for name in services:
        manifests.append(
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": name, "namespace": ns},
                "spec": {
                    "selector": labels,
                    "ports": [
                        {"name": "http", "port": 80, "targetPort": 8080,
                         "protocol": "TCP"},
                        {"name": "https", "port": 443, "targetPort": 8443,
                         "protocol": "TCP"},
                    ],
                },
            }
        )
    if allow_ingress_from_mitm:
        manifests.append(
            k8s.network_policy_manifest(
                "allow-echo-ingress",
                ns,
                pod_selector={"matchLabels": ECHO_LABEL},
                ingress=[
                    {
                        "from": [
                            {"podSelector": {"matchLabels": {"app": "mitm"}}}
                        ],
                        "ports": [
                            {"protocol": "TCP", "port": 8080},
                            {"protocol": "TCP", "port": 8443},
                        ],
                    }
                ],
            )
        )
    return manifests


def tcp_listener(ns: str, name: str, ports: list[int]) -> list[dict]:
    """A pod that accepts TCP on each given port (used as an SSH-egress target).
    No NetworkPolicy is attached, so reachability is governed purely by the
    agent's egress policy under test."""
    listeners = " & ".join(
        f"socat TCP-LISTEN:{p},fork,reuseaddr SYSTEM:'true'" for p in ports
    )
    container = k8s.container_spec(
        name=AGENT_CONTAINER,
        image=TEST_IMAGE,
        command=["sh", "-c", f"{listeners} & wait"],
        image_pull_policy="Always",
        resources=k8s.Resources(memory="64Mi", cpu="250m"),
    )
    # Gate readiness on ALL ports being up, so a "port N is blocked" test can't
    # pass merely because that listener hadn't started yet.
    probe = " && ".join(f"nc -z localhost {p}" for p in ports)
    container["readinessProbe"] = {
        "exec": {"command": ["sh", "-c", probe]},
        "periodSeconds": 1,
        "initialDelaySeconds": 1,
    }
    pod = k8s.pod_manifest(
        name,
        ns,
        labels={"app": name},
        spec=k8s.pod_spec(container=container, restart_policy="Always"),
    )
    # Allow ingress from the agent so that, where the egress policy permits it,
    # the connection is governed by the egress rule rather than blocked here.
    policy = k8s.network_policy_manifest(
        f"allow-{name}-ingress",
        ns,
        pod_selector={"matchLabels": {"app": name}},
        ingress=[{"from": [{"podSelector": {"matchLabels": {"app": "agent"}}}]}],
    )
    return [pod, policy]


def ssh_holder(ns: str, *, uid: int = 1000, gid: int = 1000) -> list[dict]:
    """The real ssh-agent holder Pod+Service (cli._ssh_agent_manifests), built on
    the probe image (which carries ssh-agent/ssh-add/socat). It mounts the
    `ssh-agent-keys` Secret — the test must apply that alongside."""
    return cli._ssh_agent_manifests(ns, TEST_IMAGE, "", uid=uid, gid=gid)


def ssh_relay_agent(
    ns: str,
    *,
    ssh_pub_secret: str,
    pub_filename: str,
    uid: int = 1000,
    gid: int = 1000,
) -> list[dict]:
    """An agent probe wired for the SSH relay using the *real* sidecar builder
    (cli._ssh_relay_sidecar): the public key is subPath-mounted into /root/.ssh,
    SSH_AUTH_SOCK points at the socket the sidecar bridges to the holder, and the
    private key is nowhere in this pod. Runs as root (the probe image has no
    dedicated user); the hardened sidecar runs as uid:gid and the shared socket
    tmpfs is group-writable via fsGroup."""
    env = cli._agent_env(Path("/root"), "root")
    env["SSH_AUTH_SOCK"] = cli.SSH_AUTH_SOCK_PATH
    container = k8s.container_spec(
        name=AGENT_CONTAINER,
        image=TEST_IMAGE,
        command=["sleep", "infinity"],
        env=env,
        volume_mounts=[
            {
                "name": "ssh-pub",
                "mountPath": f"/root/.ssh/{pub_filename}",
                "subPath": pub_filename,
                "readOnly": True,
            },
            {"name": "ssh-sock", "mountPath": "/ssh-agent"},
        ],
        security_context={"privileged": True},
        image_pull_policy="Always",
        resources=k8s.Resources(memory="256Mi", cpu="500m"),
    )
    pod = k8s.pod_manifest(
        "agent",
        ns,
        labels={"app": "agent", "managed-by": "agent-uplink-tests"},
        spec=k8s.pod_spec(
            container=container,
            volumes=[
                k8s.secret_volume("ssh-pub", ssh_pub_secret),
                k8s.tmpfs_volume("ssh-sock", "8Mi"),
            ],
            pod_security_context={"fsGroup": gid},
            extra_containers=[cli._ssh_relay_sidecar(TEST_IMAGE, uid, gid)],
        ),
    )
    return [pod]


def sshd_host(ns: str, name: str, authorized_key: bytes) -> list[dict]:
    """A real SSH server target (dropbear): accepts pubkey auth for root with the
    given public key as authorized_keys. Reachability is governed by the agent's
    egress policy (the test scopes --ssh-cidr to this pod's IP); an
    ingress-from-agent policy lets the connection through once egress permits it.

    dropbear (not openssh sshd) because the openssh server package clashes with
    the openssh client already pinned in the docker:dind base image."""
    secret = k8s.secret_manifest(
        f"{name}-authkeys", ns, {"authorized_keys": authorized_key}
    )
    # -F foreground, -E log to stderr, -R generate host keys on demand.
    script = (
        "set -e\n"
        "mkdir -p /root/.ssh\n"
        "chmod 700 /root/.ssh\n"
        "cat /authkeys/authorized_keys > /root/.ssh/authorized_keys\n"
        "chmod 600 /root/.ssh/authorized_keys\n"
        "exec dropbear -F -E -R -p 22\n"
    )
    container = k8s.container_spec(
        name=AGENT_CONTAINER,
        image=TEST_IMAGE,
        command=["sh", "-c", script],
        volume_mounts=[{"name": "authkeys", "mountPath": "/authkeys", "readOnly": True}],
        image_pull_policy="Always",
        resources=k8s.Resources(memory="64Mi", cpu="250m"),
    )
    container["readinessProbe"] = {
        "tcpSocket": {"port": 22},
        "periodSeconds": 1,
        "initialDelaySeconds": 1,
    }
    pod = k8s.pod_manifest(
        name,
        ns,
        labels={"app": name},
        spec=k8s.pod_spec(
            container=container,
            volumes=[k8s.secret_volume("authkeys", f"{name}-authkeys")],
            restart_policy="Always",
        ),
    )
    policy = k8s.network_policy_manifest(
        f"allow-{name}-ingress",
        ns,
        pod_selector={"matchLabels": {"app": name}},
        ingress=[{"from": [{"podSelector": {"matchLabels": {"app": "agent"}}}]}],
    )
    return [secret, pod, policy]


def dummy_aws_secret(ns: str, profiles: list[str]) -> tuple[dict, dict[str, str]]:
    ini, profile_to_akia = aws.dummy_aws_credentials_ini(profiles)
    secret = k8s.secret_manifest("agent-aws-creds", ns, {"credentials": ini})
    return secret, profile_to_akia


def fake_creds_secret(ns: str) -> dict:
    synthetic_real = {
        "claudeAiOauth": {
            "accessToken": REAL_OAUTH_SENTINEL,
            "refreshToken": "refresh-" + REAL_OAUTH_SENTINEL,
            "expiresAt": int(time.time() * 1000),
            "scopes": ["user:inference"],
            "subscriptionType": "pro",
        }
    }
    fake_bytes, real_token = config.fake_oauth_credentials_bytes(synthetic_real)
    assert real_token == REAL_OAUTH_SENTINEL
    return k8s.secret_manifest(
        "claude-fake-creds", ns, {".credentials.json": fake_bytes}
    )


def agent_probe(
    ns: str,
    *,
    cwd: str = "/home/agent",
    username: str = "agent",
    env_extra: dict[str, str] | None = None,
    mount_dummy_creds: bool = False,
    mount_fake_creds: bool = False,
) -> list[dict]:
    """The agent stand-in pod: label app=agent (so the real agent-egress policy
    selects it), the real proxy env from cli._agent_env, privileged + default
    runtime (no kata). Optionally mounts the same dummy AWS creds + fake OAuth
    creds the production agent pod gets, so the credentials tests can inspect
    exactly what a real agent would see. It deliberately does NOT mount the
    rules-json Secret (which holds the real injected secrets).

    Security-context delta vs the shipping agent pod (see ClaudeAgent
    ._container_security_context): production runs privileged + seccomp=Unconfined
    under kata with a writable rootfs; the probe runs plain privileged on runc.
    The NetworkPolicy/credential/injection properties under test don't depend on
    that delta — the shipping mount/secret wiring is covered by the unit test
    against cli._agent_pod_manifest(ClaudeAgent.pod_contribution(...))."""
    env = cli._agent_env(Path(cwd), username)
    if env_extra:
        env.update(env_extra)

    home = f"/home/{username}"
    volumes: list[dict] = []
    mounts: list[dict] = []
    if mount_dummy_creds:
        volumes.append(k8s.secret_volume("aws-creds", "agent-aws-creds"))
        mounts.append(
            {
                "name": "aws-creds",
                "mountPath": f"{home}/.aws/credentials",
                "subPath": "credentials",
                "readOnly": True,
            }
        )
    if mount_fake_creds:
        volumes.append(k8s.secret_volume("fake-creds", "claude-fake-creds"))
        mounts.append(
            {
                "name": "fake-creds",
                "mountPath": f"{home}/.claude/.credentials.json",
                "subPath": ".credentials.json",
                "readOnly": True,
            }
        )

    container = k8s.container_spec(
        name=AGENT_CONTAINER,
        image=TEST_IMAGE,
        command=["sleep", "infinity"],
        env=env,
        volume_mounts=mounts or None,
        security_context={"privileged": True},
        image_pull_policy="Always",
        resources=k8s.Resources(memory="256Mi", cpu="500m"),
    )
    pod = k8s.pod_manifest(
        "agent",
        ns,
        labels={"app": "agent", "managed-by": "agent-uplink-tests"},
        spec=k8s.pod_spec(container=container, volumes=volumes or None),
    )
    return [pod]


def dockerd_pod(ns: str) -> list[dict]:
    """Privileged pod running its own dockerd on the default runtime — proves an
    in-pod dockerd works without kata. DOCKER_TLS_CERTDIR='' makes dockerd serve
    the local socket."""
    container = k8s.container_spec(
        name=AGENT_CONTAINER,
        image=TEST_IMAGE,  # FROM docker:dind, so its entrypoint launches dockerd
        env={"DOCKER_TLS_CERTDIR": ""},
        security_context={"privileged": True},
        image_pull_policy="Always",
        resources=k8s.Resources(memory="1Gi", cpu="1"),
    )
    pod = k8s.pod_manifest(
        "dockerd",
        ns,
        labels={"app": "dockerd"},
        spec=k8s.pod_spec(container=container, restart_policy="Always"),
    )
    return [pod]


# --------------------------------------------------------------------------- #
# Small helpers used by tests
# --------------------------------------------------------------------------- #


def echo_json(stdout: str) -> dict:
    """Parse the echo server's reflected-request JSON out of curl stdout."""
    return json.loads(stdout)


def aws_signed_curl(
    host: str,
    path: str = "/",
    *,
    akia: str,
    method: str = "GET",
    code_only: bool = False,
    scheme: str = "http",
) -> str:
    """A curl command carrying a (bogus) SigV4 Authorization header for `akia`,
    plus the X-Amz-* headers the addon is supposed to strip on reroute. The
    signature is never verified by anything in the test — the addon only parses
    the AKIA out of the Credential= field — so no real signing is needed."""
    auth = (
        f"AWS4-HMAC-SHA256 Credential={akia}/20240101/us-east-1/s3/aws4_request, "
        "SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=deadbeefcafe"
    )
    out = "-s -o /dev/null -w '%{http_code}'" if code_only else "-s"
    return (
        f"curl {out} --max-time 10 -X {method} "
        f"-H 'Authorization: {auth}' "
        f"-H 'X-Amz-Date: 20240101T000000Z' "
        f"-H 'X-Amz-Content-Sha256: UNSIGNED-PAYLOAD' "
        f"-H 'X-Amz-Security-Token: dummy-session-token' "
        f"{scheme}://{host}{path}"
    )
