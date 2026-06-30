"""Unit tests for the orchestrator's manifest assembly and validation — the
NetworkPolicy perimeter, the proxy env, the rules-Secret isolation, SSH CIDR
scoping and the cwd guard. These run with no cluster."""

import argparse
import base64
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import Mock

import pytest

from agent_uplink import aws, cli, k8s
from agent_uplink.agents.base import PodContribution
from agent_uplink.kube import KubePlan
from agent_uplink.session import Session


def _by_name(policies):
    return {p["metadata"]["name"]: p for p in policies}


# --------------------------------------------------------------------------- #
# NetworkPolicy perimeter
# --------------------------------------------------------------------------- #


def test_default_deny_blocks_all():
    policies = cli._network_policies("ns")
    deny = _by_name(policies)["default-deny"]
    assert deny["spec"]["podSelector"] == {}
    assert deny["spec"]["ingress"] == []
    assert deny["spec"]["egress"] == []
    assert set(deny["spec"]["policyTypes"]) == {"Ingress", "Egress"}


def test_agent_egress_is_mitm_and_dns_only():
    policies = cli._network_policies("ns")
    egress = _by_name(policies)["agent-egress"]["spec"]["egress"]
    # mitm:8080
    mitm = [e for e in egress if any(
        p.get("port") == cli.PROXY_PORT for p in e.get("ports", []))]
    assert mitm and mitm[0]["to"][0]["podSelector"]["matchLabels"]["app"] == "mitm"
    # kube-dns on 53
    dns = [e for e in egress if any(p.get("port") == 53 for p in e.get("ports", []))]
    assert dns, "kube-dns egress rule missing"
    # No raw ipBlock egress without --ssh-cidr.
    assert not any("ipBlock" in t for e in egress for t in e.get("to", []))


def test_agent_egress_adds_ssh_cidr_on_port_22_only():
    policies = cli._network_policies("ns", ssh_cidrs=["10.0.0.0/24"])
    egress = _by_name(policies)["agent-egress"]["spec"]["egress"]
    ssh = [e for e in egress if any(
        t.get("ipBlock", {}).get("cidr") == "10.0.0.0/24" for t in e.get("to", []))]
    assert ssh, "ssh ipBlock egress rule missing"
    assert ssh[0]["ports"] == [{"protocol": "TCP", "port": 22}]


def test_no_sigv4_policy_signing_happens_in_mitm():
    # AWS re-signing now runs inside mitm, so there is no separate sidecar tier
    # and no sigv4-policy; mitm's unrestricted egress reaches AWS directly.
    names = _by_name(cli._network_policies("ns"))
    assert "sigv4-policy" not in names
    assert set(names) == {"default-deny", "agent-egress", "mitm-policy"}


def test_mitm_policy_ingress_from_agent_only():
    mitm = _by_name(cli._network_policies("ns"))["mitm-policy"]
    ingress = mitm["spec"]["ingress"][0]
    assert ingress["from"][0]["podSelector"]["matchLabels"]["app"] == "agent"
    assert ingress["ports"][0]["port"] == cli.PROXY_PORT
    # Egress unrestricted so mitm can reach the real AWS endpoints it re-signs for.
    assert mitm["spec"]["egress"] == [{}]


# --------------------------------------------------------------------------- #
# SSH agent-forwarding relay (holder pod + sidecar bridge)
# --------------------------------------------------------------------------- #


def test_ssh_relay_adds_egress_to_holder_and_ingress_policy():
    names = _by_name(cli._network_policies("ns", ssh_relay=True))
    assert "ssh-agent-policy" in names
    egress = names["agent-egress"]["spec"]["egress"]
    relay = [e for e in egress if any(
        t.get("podSelector", {}).get("matchLabels", {}).get("app") == "ssh-agent"
        for t in e.get("to", []))]
    assert relay and relay[0]["ports"][0]["port"] == cli.SSH_AGENT_PORT
    # Holder accepts the signing bridge from the agent only, and has no egress.
    holder = names["ssh-agent-policy"]["spec"]
    assert holder["ingress"][0]["from"][0]["podSelector"]["matchLabels"]["app"] == "agent"
    assert "Egress" not in holder["policyTypes"]


def test_ssh_relay_absent_by_default():
    names = _by_name(cli._network_policies("ns"))
    assert "ssh-agent-policy" not in names


def test_ssh_agent_holder_is_hardened_and_mounts_keys_secret():
    pod, svc = cli._ssh_agent_manifests("ns", "img", "", uid=1000, gid=1000)
    container = pod["spec"]["containers"][0]
    sc = container["securityContext"]
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["runAsNonRoot"] is True
    assert sc["capabilities"]["drop"] == ["ALL"]
    # The private keys arrive as a Secret; the socket lives on tmpfs.
    vols = {v["name"]: v for v in pod["spec"]["volumes"]}
    assert vols["keys"]["secret"]["secretName"] == "ssh-agent-keys"
    assert vols["sock"]["emptyDir"]["medium"] == "Memory"
    assert svc["spec"]["ports"][0]["port"] == cli.SSH_AGENT_PORT
    # Keys must be piped via `ssh-add -` (stdin): ssh-add rejects the 0644
    # Secret-mounted key file as "too open", so loading from a file would fail.
    script = container["command"][-1]
    assert "ssh-add - <" in script
    assert 'ssh-add "$k"' not in script
    # A stale socket from a prior in-place restart is cleared before ssh-agent
    # binds, and an empty key dir is a no-op (nullglob), not a literal /keys/*.
    assert "rm -f /run/ssh-agent/agent.sock" in script
    assert "nullglob" in script
    # A per-key load failure is isolated; the pod fails only if no key loads.
    assert "no SSH keys could be loaded" in script
    # Readiness reflects a reachable agent that holds a key (exec probe, so it is
    # not blocked by the holder's ingress NetworkPolicy).
    assert "ssh-add -l" in container["readinessProbe"]["exec"]["command"][-1]


def test_ssh_relay_sidecar_clears_stale_socket_and_gates_on_socket():
    sidecar = cli._ssh_relay_sidecar("img", 1000, 1000)
    script = sidecar["command"][-1]
    # unlink-early clears any socket left by a prior in-place restart.
    assert "unlink-early" in script
    # Readiness gates on the bridged socket existing so the agent never attaches
    # to a not-yet-created SSH_AUTH_SOCK.
    assert cli.SSH_AUTH_SOCK_PATH in sidecar["readinessProbe"]["exec"]["command"][-1]


# --------------------------------------------------------------------------- #
# Proxy env
# --------------------------------------------------------------------------- #


def test_agent_env_forces_everything_through_mitm():
    env = cli._agent_env(Path("/home/u/proj"), "u")
    proxy = f"http://mitm:{cli.PROXY_PORT}"
    for key in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                "DOCKER_HTTP_PROXY", "DOCKER_HTTPS_PROXY"):
        assert env[key] == proxy
    assert "127.0.0.1" in env["NO_PROXY"]


# --------------------------------------------------------------------------- #
# rules-json Secret isolation
# --------------------------------------------------------------------------- #


def _secret_names(pod):
    return [
        v.get("secret", {}).get("secretName")
        for v in pod["spec"].get("volumes", [])
    ]


def test_mitm_pod_mounts_rules_secret():
    pod = next(m for m in cli._mitm_manifests("ns", "mitm:img", "")
               if m["kind"] == "Pod")
    assert "rules-json" in _secret_names(pod)


def test_agent_pod_never_mounts_rules_secret():
    contribution = PodContribution(
        env={"X": "1"},
        volumes=[k8s.secret_volume("creds", "agent-aws-creds")],
        mounts=[{"name": "creds", "mountPath": "/c"}],
        security_context={"privileged": True},
        init_command=["sleep", "infinity"],
        command=["bash"],
        memory="1Gi",
    )
    pod = cli._agent_pod_manifest(
        "ns", "img", contribution, Path("/home/u"), "u", 1000, "", uid=1000
    )
    assert "rules-json" not in _secret_names(pod)
    # The app=agent label (so the agent-egress policy selects the pod) is owned by
    # test_claude_agent.test_agent_pod_is_labelled_for_egress_policy.


# --------------------------------------------------------------------------- #
# Hardened security context (mitm / sigv4 support pods)
# --------------------------------------------------------------------------- #


def test_hardened_security_context_flags():
    sc = k8s.hardened_container_security_context(uid=1000, gid=1000)
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["runAsNonRoot"] is True
    assert sc["seccompProfile"]["type"] == "RuntimeDefault"
    assert sc["runAsUser"] == 1000


# --------------------------------------------------------------------------- #
# SSH arg validation / cwd guard
# --------------------------------------------------------------------------- #


def test_validate_ssh_args_normalises_bare_ip_to_cidr():
    cidrs, key_dir = cli.validate_ssh_args(["203.0.113.7"], None)
    assert cidrs == ["203.0.113.7/32"]
    assert key_dir is None


def test_validate_ssh_args_normalises_to_network_address():
    cidrs, _ = cli.validate_ssh_args(["10.1.2.3/24"], None)
    assert cidrs == ["10.1.2.0/24"]


def test_validate_ssh_args_rejects_bad_cidr():
    with pytest.raises(ValueError, match="not a valid CIDR"):
        cli.validate_ssh_args(["not-an-ip"], None)


def test_validate_cwd_must_be_under_home():
    cli.validate_cwd("alice", Path("/home/alice/project"))  # ok
    cli.validate_cwd("alice", Path("/home/alice"))  # ok
    with pytest.raises(ValueError):
        cli.validate_cwd("alice", Path("/tmp/elsewhere"))
    with pytest.raises(ValueError):
        cli.validate_cwd("alice", Path("/home/bob/project"))


# --------------------------------------------------------------------------- #
# --mount-rw / --mount-ro validation
# --------------------------------------------------------------------------- #


def test_validate_mounts_accepts_siblings(tmp_path, monkeypatch):
    # Siblings of cwd and of each other are all valid.
    base = tmp_path / "home" / "alice"
    cwd = base / "code" / "repo-a"
    d1 = base / "code" / "repo-b"
    d2 = base / "shared"
    for p in (cwd, d1, d2):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    result = cli.validate_mounts("alice", cwd, [d1, d2], [])
    assert result == [cli.HostMount(d1, False), cli.HostMount(d2, False)]


def test_validate_mounts_ro_file_is_read_only(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo"
    cwd.mkdir(parents=True)
    cfg = base / ".ansible.cfg"
    cfg.write_text("[defaults]\n")
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    result = cli.validate_mounts("alice", cwd, [], [cfg])
    assert result == [cli.HostMount(cfg, True)]


def test_validate_mounts_deduplicates(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo-a"
    d = base / "repo-b"
    for p in (cwd, d):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    result = cli.validate_mounts("alice", cwd, [d, d], [])
    assert result == [cli.HostMount(d, False)]


def test_validate_mounts_rejects_rw_ro_conflict(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo-a"
    d = base / "repo-b"
    for p in (cwd, d):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="both read-write and read-only"):
        cli.validate_mounts("alice", cwd, [d], [d])


def test_validate_mounts_rejects_cwd_duplicate(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo-a"
    cwd.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="working directory"):
        cli.validate_mounts("alice", cwd, [cwd], [])


def test_validate_mounts_rejects_descendant_of_cwd(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo"
    child = cwd / "subdir"
    for p in (cwd, child):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="overlap"):
        cli.validate_mounts("alice", cwd, [child], [])


def test_validate_mounts_rejects_ancestor_of_cwd(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    parent = base / "code"
    cwd = parent / "repo"
    for p in (parent, cwd):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="overlap"):
        cli.validate_mounts("alice", cwd, [parent], [])


def test_validate_mounts_rejects_nested_rw_dirs(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "cwd"
    d1 = base / "extra"
    d2 = d1 / "nested"
    for p in (cwd, d1, d2):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="overlap"):
        cli.validate_mounts("alice", cwd, [d1, d2], [])


def test_validate_mounts_allows_ro_file_under_rw_dir(tmp_path, monkeypatch):
    # Only writable directories are checked for overlap; a read-only file inside
    # a read-write dir is allowed.
    base = tmp_path / "home" / "alice"
    cwd = base / "cwd"
    d1 = base / "extra"
    d1.mkdir(parents=True)
    cwd.mkdir(parents=True)
    cfg = d1 / "config"
    cfg.write_text("x\n")
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    result = cli.validate_mounts("alice", cwd, [d1], [cfg])
    assert cli.HostMount(cfg, True) in result


def test_validate_mounts_rejects_outside_home(tmp_path, monkeypatch):
    cwd = tmp_path / "home" / "alice" / "repo"
    outside = tmp_path / "srv" / "data"
    for p in (cwd, outside):
        p.mkdir(parents=True)
    # _under_home returns False for anything outside the alice home subtree.
    monkeypatch.setattr(cli, "_under_home",
                        lambda u, p: str(p).startswith(str(tmp_path / "home" / "alice")))
    with pytest.raises(ValueError, match="must be under /home"):
        cli.validate_mounts("alice", cwd, [outside], [])


def test_validate_mounts_rejects_nonexistent(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo"
    cwd.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="does not exist"):
        cli.validate_mounts("alice", cwd, [base / "ghost"], [])


def test_agent_pod_manifest_extra_mounts_adds_volumes_and_mounts(tmp_path):
    d1 = tmp_path / "home" / "alice" / "repo-b"
    d1.mkdir(parents=True)
    ro_file = tmp_path / "home" / "alice" / ".ansible.cfg"
    ro_file.write_text("[defaults]\n")
    contribution = PodContribution(
        env={},
        volumes=[],
        mounts=[],
        security_context={"privileged": True},
        init_command=["sleep", "infinity"],
        command=["bash"],
        memory="1Gi",
    )
    pod = cli._agent_pod_manifest(
        "ns", "img", contribution, tmp_path / "home" / "alice" / "cwd",
        "alice", 1000, "",
        cli.AgentMounts(
            extra_mounts=[cli.HostMount(d1, False), cli.HostMount(ro_file, True)]
        ),
        uid=1000,
    )
    mounts = pod["spec"]["containers"][0]["volumeMounts"]
    by_name = {m["name"]: m for m in mounts}
    assert by_name["mount-0"]["mountPath"] == str(d1)
    assert by_name["mount-0"]["readOnly"] is False
    assert by_name["mount-1"]["mountPath"] == str(ro_file)
    assert by_name["mount-1"]["readOnly"] is True
    # hostPath type is auto-detected: Directory for the dir, File for the file.
    hp = {v["name"]: v["hostPath"] for v in pod["spec"]["volumes"] if "hostPath" in v}
    assert hp["mount-0"]["path"] == str(d1)
    assert hp["mount-0"]["type"] == "Directory"
    assert hp["mount-1"]["path"] == str(ro_file)
    assert hp["mount-1"]["type"] == "File"


# --------------------------------------------------------------------------- #
# Deploy context selection
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _reset_kube_context():
    """Keep the module-level deploy context from leaking between tests."""
    k8s.set_kube_context(None)
    yield
    k8s.set_kube_context(None)


def test_kubectl_injects_deploy_context(monkeypatch):
    captured = []
    monkeypatch.setattr(k8s, "run_command", lambda cmd, **kw: captured.append(cmd) or "")
    k8s.set_kube_context("local-k8s-admin")
    k8s.kubectl("get", "pods")
    assert captured[0] == ["kubectl", "--context", "local-k8s-admin", "get", "pods"]


def test_kubectl_omits_context_when_unset(monkeypatch):
    captured = []
    monkeypatch.setattr(k8s, "run_command", lambda cmd, **kw: captured.append(cmd) or "")
    k8s.set_kube_context("")  # empty -> current-context, no --context flag
    k8s.kubectl("get", "pods")
    assert captured[0] == ["kubectl", "get", "pods"]


def test_exec_interactive_injects_deploy_context(monkeypatch):
    captured = []
    monkeypatch.setattr(k8s, "run_interactive", lambda cmd: captured.append(cmd) or 0)
    k8s.set_kube_context("dev")
    k8s.exec_interactive("ns", "agent", container="main", command=["bash"])
    assert captured[0][:3] == ["kubectl", "--context", "dev"]
    assert captured[0][3:6] == ["exec", "-it", "agent"]


def test_deploy_context_defaults_to_local_k8s_admin():
    ns = cli._common_arg_parser().parse_args([])
    assert ns.deploy_context == cli.DEFAULT_DEPLOY_CONTEXT == "local-k8s-admin"


# --------------------------------------------------------------------------- #
# Helpers for manifest inspection
# --------------------------------------------------------------------------- #


def _env_dict(container):
    return {e["name"]: e["value"] for e in container.get("env", [])}


def _volume_by_name(pod, name):
    vol = next((v for v in pod["spec"]["volumes"] if v["name"] == name), None)
    assert vol is not None, f"volume {name!r} not found"
    return vol


def _mount_by_name(container, name):
    mount = next((m for m in container.get("volumeMounts", []) if m["name"] == name), None)
    assert mount is not None, f"mount {name!r} not found"
    return mount


def _assert_set_arg(args, value):
    """mitm passes options as a `--set X=Y` pair; assert the value is present and
    immediately preceded by --set."""
    assert value in args, f"{value!r} not in mitm args"
    assert args[args.index(value) - 1] == "--set"


# --------------------------------------------------------------------------- #
# mitm manifest — hardening + AWS creds + kube (mTLS / upstream-CA) wiring
# --------------------------------------------------------------------------- #


def test_mitm_manifest_is_hardened_without_kube():
    pod = next(m for m in cli._mitm_manifests("ns", "img", "") if m["kind"] == "Pod")
    sc = pod["spec"]["containers"][0]["securityContext"]
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["runAsNonRoot"] is True
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert sc["seccompProfile"]["type"] == "RuntimeDefault"


def test_mitm_manifest_no_aws_creds_mount_without_profiles():
    pod = next(m for m in cli._mitm_manifests("ns", "img", "") if m["kind"] == "Pod")
    container = pod["spec"]["containers"][0]
    assert not any(v["name"] == "aws-creds" for v in pod["spec"]["volumes"])
    assert "aws_creds_file=/aws-creds/creds.json" not in container["args"]


def test_mitm_manifest_mounts_aws_creds_when_present():
    pod = next(
        m for m in cli._mitm_manifests("ns", "img", "", aws_creds_secret="aws-sigv4-creds")
        if m["kind"] == "Pod"
    )
    container = pod["spec"]["containers"][0]
    # Real per-AKIA creds map mounted read-only, and the addon pointed at it.
    assert _volume_by_name(pod, "aws-creds")["secret"]["secretName"] == "aws-sigv4-creds"
    mount = _mount_by_name(container, "aws-creds")
    assert mount["mountPath"] == "/aws-creds" and mount["readOnly"] is True
    _assert_set_arg(container["args"], "aws_creds_file=/aws-creds/creds.json")


def test_mitm_manifest_no_debug_logging_by_default():
    pod = next(m for m in cli._mitm_manifests("ns", "img", "") if m["kind"] == "Pod")
    args = pod["spec"]["containers"][0]["args"]
    assert "termlog_verbosity=debug" not in args
    assert "flow_detail=3" not in args


def test_mitm_manifest_enables_verbose_logging_with_debug():
    pod = next(
        m for m in cli._mitm_manifests("ns", "img", "", debug=True) if m["kind"] == "Pod"
    )
    args = pod["spec"]["containers"][0]["args"]
    _assert_set_arg(args, "termlog_verbosity=debug")
    _assert_set_arg(args, "flow_detail=3")


def test_mitm_manifest_kube_client_certs_and_upstream_ca():
    pod = next(
        m for m in cli._mitm_manifests(
            "ns", "img", "",
            kube_client_certs_secret="kube-client-certs",
            kube_upstream_ca_secret="kube-upstream-ca",
        )
        if m["kind"] == "Pod"
    )
    container = pod["spec"]["containers"][0]

    assert _volume_by_name(pod, "kube-client-certs")["secret"]["secretName"] == "kube-client-certs"
    assert _volume_by_name(pod, "kube-upstream-ca")["secret"]["secretName"] == "kube-upstream-ca"

    cc_mount = _mount_by_name(container, "kube-client-certs")
    assert cc_mount["mountPath"] == "/kube-client-certs" and cc_mount["readOnly"] is True
    ca_mount = _mount_by_name(container, "kube-upstream-ca")
    assert ca_mount["mountPath"] == "/kube-upstream-ca" and ca_mount["readOnly"] is True

    args = container["args"]
    # Client cert presentation on the upstream TLS leg + upstream CA verification.
    _assert_set_arg(args, "client_certs=/kube-client-certs")
    # The cluster CAs are concatenated with the image's certifi bundle into the
    # writable /tmp at startup (the option replaces, not augments, the trust
    # store), and mitm trusts that combined file.
    _assert_set_arg(args, "ssl_verify_upstream_trusted_ca=/tmp/upstream-ca-bundle.pem")
    startup = container["command"]
    assert startup[0] == "sh"
    assert "certifi" in startup[2]
    assert "/kube-upstream-ca/bundle.pem" in startup[2]
    assert "/tmp/upstream-ca-bundle.pem" in startup[2]
    assert "exec mitmdump" in startup[2]


def test_mitm_manifest_disables_http2():
    pod = next(m for m in cli._mitm_manifests("ns", "img", "") if m["kind"] == "Pod")
    _assert_set_arg(pod["spec"]["containers"][0]["args"], "http2=false")


def test_mitm_manifest_secure_upstream_by_default():
    pod = next(m for m in cli._mitm_manifests("ns", "img", "") if m["kind"] == "Pod")
    assert "ssl_insecure=true" not in pod["spec"]["containers"][0]["args"]


def test_mitm_manifest_insecure_disables_upstream_verification():
    pod = next(
        m for m in cli._mitm_manifests("ns", "img", "", insecure=True)
        if m["kind"] == "Pod"
    )
    _assert_set_arg(pod["spec"]["containers"][0]["args"], "ssl_insecure=true")


def test_mitm_manifest_custom_ca_added_to_trust_bundle():
    pod = next(
        m for m in cli._mitm_manifests("ns", "img", "", custom_ca_secret="custom-ca")
        if m["kind"] == "Pod"
    )
    container = pod["spec"]["containers"][0]
    assert _volume_by_name(pod, "custom-ca")["secret"]["secretName"] == "custom-ca"
    mount = _mount_by_name(container, "custom-ca")
    assert mount["mountPath"] == "/custom-ca" and mount["readOnly"] is True
    _assert_set_arg(container["args"], "ssl_verify_upstream_trusted_ca=/tmp/upstream-ca-bundle.pem")
    startup = container["command"]
    assert "certifi" in startup[2]
    assert "/custom-ca/bundle.pem" in startup[2]
    assert "exec mitmdump" in startup[2]


def test_mitm_manifest_custom_ca_concatenated_with_kube_ca():
    pod = next(
        m for m in cli._mitm_manifests(
            "ns", "img", "",
            kube_upstream_ca_secret="kube-upstream-ca",
            custom_ca_secret="custom-ca",
        )
        if m["kind"] == "Pod"
    )
    startup = pod["spec"]["containers"][0]["command"][2]
    assert "/kube-upstream-ca/bundle.pem" in startup
    assert "/custom-ca/bundle.pem" in startup


def test_read_custom_ca_none_when_empty():
    assert cli._read_custom_ca([]) is None


def test_read_custom_ca_concatenates_pem_files(tmp_path):
    a = tmp_path / "a.pem"
    b = tmp_path / "b.pem"
    a.write_bytes(b"-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----")
    b.write_bytes(b"-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n")
    out = cli._read_custom_ca([a, b])
    assert out is not None
    assert out.count(b"BEGIN CERTIFICATE") == 2
    assert out.endswith(b"\n")


def test_read_custom_ca_rejects_non_pem(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_bytes(b"not a cert")
    with pytest.raises(ValueError, match="no PEM certificate"):
        cli._read_custom_ca([bad])


# --------------------------------------------------------------------------- #
# Agent pod optional mounts (ssh keys + kubeconfig)
# --------------------------------------------------------------------------- #


def _minimal_contribution():
    return PodContribution(
        env={}, volumes=[], mounts=[], security_context={"privileged": True},
        init_command=["sleep", "infinity"], command=["bash"], memory="1Gi",
    )


def test_agent_pod_ssh_relay_mounts_pub_secret_and_adds_sidecar():
    pod = cli._agent_pod_manifest(
        "ns", "img", _minimal_contribution(), Path("/home/u"), "u", 1000, "",
        cli.AgentMounts(
            ssh_pub_secret="ssh-pub", ssh_pub_files=["id_ed25519.pub", "config"]
        ),
        uid=1000,
    )
    container = pod["spec"]["containers"][0]
    assert _volume_by_name(pod, "ssh-pub")["secret"]["secretName"] == "ssh-pub"
    # Public keys + config land read-only via per-file subPath mounts INTO ~/.ssh,
    # so the directory itself stays writable (ssh creates known_hosts there) and
    # no private key is ever mounted into the agent pod.
    pub_mounts = {
        m["mountPath"]: m for m in container["volumeMounts"] if m["name"] == "ssh-pub"
    }
    assert set(pub_mounts) == {"/home/u/.ssh/id_ed25519.pub", "/home/u/.ssh/config"}
    assert pub_mounts["/home/u/.ssh/config"]["subPath"] == "config"
    assert all(m["readOnly"] for m in pub_mounts.values())
    # The whole ~/.ssh is never a single read-only mount.
    assert not any(m["mountPath"] == "/home/u/.ssh" for m in container["volumeMounts"])
    # SSH_AUTH_SOCK points at the bridged socket.
    assert _env_dict(container)["SSH_AUTH_SOCK"] == cli.SSH_AUTH_SOCK_PATH
    # The relay sidecar bridges the unix socket to the holder over TCP.
    sidecar = {c["name"]: c for c in pod["spec"]["containers"]}["ssh-agent-relay"]
    assert sidecar["securityContext"]["readOnlyRootFilesystem"] is True
    assert any(m["mountPath"] == "/ssh-agent" for m in sidecar["volumeMounts"])


def test_agent_pod_mounts_kubeconfig_outside_home_with_env():
    pod = cli._agent_pod_manifest(
        "ns", "img", _minimal_contribution(), Path("/home/u"), "u", 1000, "",
        cli.AgentMounts(kube_config_secret="kube-config"),
        uid=1000,
    )
    container = pod["spec"]["containers"][0]
    assert _env_dict(container)["KUBECONFIG"] == "/etc/agent-uplink/kube/config"
    assert _volume_by_name(pod, "kube-config")["secret"]["secretName"] == "kube-config"
    mount = _mount_by_name(container, "kube-config")
    # Mounted outside the home dir so readOnlyRootFilesystem semantics don't block
    # it, and read-only since it carries placeholder creds the agent can't change.
    assert mount["mountPath"] == "/etc/agent-uplink/kube"
    assert mount["readOnly"] is True


# --------------------------------------------------------------------------- #
# _build_aws_plan — dummy creds for the agent, real per-AKIA creds for mitm
# --------------------------------------------------------------------------- #


def _decode_secret(manifest, key):
    return base64.b64decode(manifest["data"][key]).decode()


def test_build_aws_plan_dummy_for_agent_real_for_mitm(monkeypatch):
    monkeypatch.setattr(
        cli, "export_aws_profile_env",
        lambda profile: {
            "AWS_ACCESS_KEY_ID": f"AKIAREAL-{profile}",
            "AWS_SECRET_ACCESS_KEY": "realsecret",
            "AWS_SESSION_TOKEN": "realtoken",
        },
    )
    session = Session(session_dir=Path("/tmp/unused"), namespace="test-ns")
    plan = cli._build_aws_plan(session, ["test-profile", "My.Profile"])

    assert plan.dummy_secret_name == "agent-aws-creds"
    assert plan.creds_secret_name == "aws-sigv4-creds"

    by_name = {m["metadata"]["name"]: m for m in plan.secret_manifests}
    # The agent's credentials Secret holds only deterministic dummy values.
    dummy_ini = _decode_secret(by_name["agent-aws-creds"], "credentials")
    assert "[test-profile]" in dummy_ini
    assert "AKIA" in dummy_ini and "DUMMYsecret" in dummy_ini
    assert "realsecret" not in dummy_ini and "realtoken" not in dummy_ini

    # The real creds live only in the mitm pod's Secret, keyed by dummy AKIA.
    creds_map = json.loads(_decode_secret(by_name["aws-sigv4-creds"], "creds.json"))
    assert set(creds_map) == {aws.dummy_akia("test-profile"), aws.dummy_akia("My.Profile")}
    entry = creds_map[aws.dummy_akia("test-profile")]
    assert entry == {
        "access_key_id": "AKIAREAL-test-profile",
        "secret_access_key": "realsecret",
        "session_token": "realtoken",
    }
    # No per-profile sidecar Secrets exist anymore.
    assert not any(n.startswith("aws-creds-") for n in by_name)
    assert by_name["aws-sigv4-creds"]["metadata"]["namespace"] == "test-ns"


def test_build_aws_plan_no_profiles_has_no_secrets():
    session = Session(session_dir=Path("/tmp/unused"), namespace="test-ns")
    plan = cli._build_aws_plan(session, [])
    assert plan.dummy_secret_name is None
    assert plan.creds_secret_name is None
    assert plan.secret_manifests == []


# --------------------------------------------------------------------------- #
# _kube_secrets — conditional Secret assembly
# --------------------------------------------------------------------------- #


def test_kube_secrets_none_plan_is_empty():
    session = Session(session_dir=Path("/tmp/unused"), namespace="ns")
    out = cli._kube_secrets(session, None)
    assert out.config_secret is None
    assert out.manifests == []


def test_kube_secrets_bearer_only_has_config_no_certs():
    session = Session(session_dir=Path("/tmp/unused"), namespace="ns")
    plan = KubePlan(pod_kubeconfig=b"cfg", client_certs={}, upstream_ca_bundle=b"")
    out = cli._kube_secrets(session, plan)
    assert out.config_secret == "kube-config"
    cfg = next(m for m in out.manifests if m["metadata"]["name"] == "kube-config")
    assert _decode_secret(cfg, "config") == "cfg"
    assert out.client_certs_secret is None
    assert out.upstream_ca_secret is None


def test_kube_secrets_full_plan_adds_certs_and_ca():
    session = Session(session_dir=Path("/tmp/unused"), namespace="ns")
    plan = KubePlan(
        pod_kubeconfig=b"cfg",
        client_certs={"host.pem": b"cert+key"},
        upstream_ca_bundle=b"PEM",
    )
    out = cli._kube_secrets(session, plan)
    assert out.client_certs_secret == "kube-client-certs"
    assert out.upstream_ca_secret == "kube-upstream-ca"
    ca = next(m for m in out.manifests if m["metadata"]["name"] == "kube-upstream-ca")
    assert _decode_secret(ca, "bundle.pem") == "PEM"


# --------------------------------------------------------------------------- #
# _resolve_aws_profiles — dedup, order
# --------------------------------------------------------------------------- #


def test_resolve_aws_profiles_deduplicates_preserving_order():
    args = argparse.Namespace(aws_profiles=["prof-b", "prof-c"])
    agent = cast(Any, SimpleNamespace(discover_aws_profiles=lambda: ["prof-a", "prof-b"]))
    # --aws-profiles first, agent-discovered appended, duplicate dropped in order.
    assert cli._resolve_aws_profiles(args, agent) == ["prof-b", "prof-c", "prof-a"]


# --------------------------------------------------------------------------- #
# _ensure_agent_image — rebuild triggers
# --------------------------------------------------------------------------- #


def _ensure_image(monkeypatch, *, certs_generated, force_rebuild, age):
    build = Mock(return_value="rebuilt-image")
    monkeypatch.setattr(cli, "get_image_age_seconds", lambda img: age)
    monkeypatch.setattr(cli, "build_and_push_agent_image", build)
    agent = cast(Any, SimpleNamespace(
        image_repo="agent-uplink-claude", container_dir=lambda: Path("/x")
    ))
    args = argparse.Namespace(force_rebuild=force_rebuild, image=None)
    result = cli._ensure_agent_image(args, agent, "u", Path("/mitm"), certs_generated)
    return build, result


@pytest.mark.parametrize(
    "certs_generated,force_rebuild,age,bust_cache",
    [
        (True, False, 10.0, False),                                  # certs just generated
        (False, True, 10.0, True),                                   # --force-rebuild
        (False, False, None, False),                                 # image missing
        (False, False, cli.AGENT_IMAGE_MAX_AGE_SECONDS + 1, True),   # stale
    ],
)
def test_ensure_agent_image_rebuilds(
    monkeypatch, certs_generated, force_rebuild, age, bust_cache
):
    build, result = _ensure_image(
        monkeypatch, certs_generated=certs_generated, force_rebuild=force_rebuild, age=age
    )
    build.assert_called_once()
    assert result == "rebuilt-image"
    # The cache is busted only when the rebuild exists to refresh upstream
    # content (force or staleness); certs/missing reuse cached layers.
    assert build.call_args.kwargs["bust_cache"] is bust_cache


def test_ensure_agent_image_reuses_fresh_image(monkeypatch):
    build, result = _ensure_image(
        monkeypatch, certs_generated=False, force_rebuild=False, age=10.0
    )
    build.assert_not_called()
    assert result == f"{cli.REGISTRY_PUSH_ENDPOINT}/agent-uplink-claude:latest"
