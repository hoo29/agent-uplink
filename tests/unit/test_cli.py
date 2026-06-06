"""Unit tests for the orchestrator's manifest assembly and validation — the
NetworkPolicy perimeter, the proxy env, the rules-Secret isolation, SSH CIDR
scoping and the cwd guard. These run with no cluster."""

from pathlib import Path

import pytest

from agent_uplink import cli, k8s
from agent_uplink.agents.base import PodContribution


def _by_name(policies):
    return {p["metadata"]["name"]: p for p in policies}


# --------------------------------------------------------------------------- #
# NetworkPolicy perimeter
# --------------------------------------------------------------------------- #


def test_default_deny_blocks_all():
    policies = cli._network_policies("ns", has_sigv4=False)
    deny = _by_name(policies)["default-deny"]
    assert deny["spec"]["podSelector"] == {}
    assert deny["spec"]["ingress"] == []
    assert deny["spec"]["egress"] == []
    assert set(deny["spec"]["policyTypes"]) == {"Ingress", "Egress"}


def test_agent_egress_is_mitm_and_dns_only():
    policies = cli._network_policies("ns", has_sigv4=False)
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
    policies = cli._network_policies("ns", has_sigv4=False, ssh_cidrs=["10.0.0.0/24"])
    egress = _by_name(policies)["agent-egress"]["spec"]["egress"]
    ssh = [e for e in egress if any(
        t.get("ipBlock", {}).get("cidr") == "10.0.0.0/24" for t in e.get("to", []))]
    assert ssh, "ssh ipBlock egress rule missing"
    assert ssh[0]["ports"] == [{"protocol": "TCP", "port": 22}]


def test_sigv4_policy_only_present_with_profiles():
    assert "sigv4-policy" not in _by_name(cli._network_policies("ns", has_sigv4=False))
    sigv4 = _by_name(cli._network_policies("ns", has_sigv4=True))["sigv4-policy"]
    ingress = sigv4["spec"]["ingress"][0]
    assert ingress["from"][0]["podSelector"]["matchLabels"]["app"] == "mitm"
    assert sigv4["spec"]["podSelector"]["matchLabels"]["tier"] == "sigv4"


def test_mitm_policy_ingress_from_agent_only():
    mitm = _by_name(cli._network_policies("ns", has_sigv4=False))["mitm-policy"]
    ingress = mitm["spec"]["ingress"][0]
    assert ingress["from"][0]["podSelector"]["matchLabels"]["app"] == "agent"
    assert ingress["ports"][0]["port"] == cli.PROXY_PORT


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
        "ns", "img", contribution, Path("/home/u"), "u", 1000, ""
    )
    assert "rules-json" not in _secret_names(pod)
    # The agent is labelled app=agent so the agent-egress policy selects it.
    assert pod["metadata"]["labels"]["app"] == "agent"


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
# --add-dir validation
# --------------------------------------------------------------------------- #


def test_validate_extra_dirs_accepts_siblings(tmp_path, monkeypatch):
    # Siblings of cwd and of each other are all valid.
    base = tmp_path / "home" / "alice"
    cwd = base / "code" / "repo-a"
    d1 = base / "code" / "repo-b"
    d2 = base / ".ansible"
    for p in (cwd, d1, d2):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    result = cli.validate_extra_dirs("alice", cwd, [d1, d2])
    assert result == [d1, d2]


def test_validate_extra_dirs_deduplicates(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo-a"
    d = base / "repo-b"
    for p in (cwd, d):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    result = cli.validate_extra_dirs("alice", cwd, [d, d])
    assert result == [d]


def test_validate_extra_dirs_rejects_cwd_duplicate(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo-a"
    cwd.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="working directory"):
        cli.validate_extra_dirs("alice", cwd, [cwd])


def test_validate_extra_dirs_rejects_descendant_of_cwd(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo"
    child = cwd / "subdir"
    for p in (cwd, child):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="overlap"):
        cli.validate_extra_dirs("alice", cwd, [child])


def test_validate_extra_dirs_rejects_ancestor_of_cwd(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    parent = base / "code"
    cwd = parent / "repo"
    for p in (parent, cwd):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="overlap"):
        cli.validate_extra_dirs("alice", cwd, [parent])


def test_validate_extra_dirs_rejects_nested_extras(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "cwd"
    d1 = base / "extra"
    d2 = d1 / "nested"
    for p in (cwd, d1, d2):
        p.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="overlap"):
        cli.validate_extra_dirs("alice", cwd, [d1, d2])


def test_validate_extra_dirs_rejects_outside_home(tmp_path, monkeypatch):
    cwd = tmp_path / "home" / "alice" / "repo"
    outside = tmp_path / "srv" / "data"
    for p in (cwd, outside):
        p.mkdir(parents=True)
    # _under_home returns False for anything outside the alice home subtree.
    monkeypatch.setattr(cli, "_under_home",
                        lambda u, p: str(p).startswith(str(tmp_path / "home" / "alice")))
    with pytest.raises(ValueError, match="must be under /home"):
        cli.validate_extra_dirs("alice", cwd, [outside])


def test_validate_extra_dirs_rejects_nonexistent(tmp_path, monkeypatch):
    base = tmp_path / "home" / "alice"
    cwd = base / "repo"
    cwd.mkdir(parents=True)
    monkeypatch.setattr(cli, "_under_home", lambda u, p: str(p).startswith(str(base)))
    with pytest.raises(ValueError, match="does not exist"):
        cli.validate_extra_dirs("alice", cwd, [base / "ghost"])


def test_agent_pod_manifest_extra_dirs_adds_volumes_and_mounts(tmp_path):
    d1 = tmp_path / "home" / "alice" / "repo-b"
    d2 = tmp_path / "home" / "alice" / ".ansible"
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
        "alice", 1000, "", extra_dirs=[d1, d2],
    )
    vol_names = [v["name"] for v in pod["spec"]["volumes"]]
    mnt_paths = [m["mountPath"] for m in pod["spec"]["containers"][0]["volumeMounts"]]
    assert "add-dir-0" in vol_names
    assert "add-dir-1" in vol_names
    assert str(d1) in mnt_paths
    assert str(d2) in mnt_paths
    # Verify hostPath values.
    hp_map = {
        v["name"]: v["hostPath"]["path"]
        for v in pod["spec"]["volumes"]
        if "hostPath" in v
    }
    assert hp_map["add-dir-0"] == str(d1)
    assert hp_map["add-dir-1"] == str(d2)
    # No readOnly key on extra-dir mounts.
    for m in pod["spec"]["containers"][0]["volumeMounts"]:
        if m["name"].startswith("add-dir-"):
            assert not m.get("readOnly")


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
