"""Unit tests for the orchestrator's manifest assembly and validation — the
NetworkPolicy perimeter, the proxy env, the rules-Secret isolation, SSH CIDR
scoping and the cwd guard. These run with no cluster."""

import argparse
import base64
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
        "alice", 1000, "", cli.AgentMounts(extra_dirs=[d1, d2]),
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
# sigv4 sidecar manifest — credential wiring + hardening
# --------------------------------------------------------------------------- #


def test_sigv4_manifests_wiring_and_hardening():
    pod = next(
        m for m in cli._sigv4_manifests("ns", "profile-name", "my-profile", "img:tag", "")
        if m["kind"] == "Pod"
    )
    assert pod["metadata"]["labels"]["tier"] == "sigv4"
    assert pod["metadata"]["labels"]["managed-by"] == "agent-uplink"

    container = pod["spec"]["containers"][0]
    env = _env_dict(container)
    assert env["AWS_SHARED_CREDENTIALS_FILE"] == "/aws/credentials"
    # AWS_PROFILE is the original profile name; the safe name is only for k8s
    # resource names (the per-profile Secret).
    assert env["AWS_PROFILE"] == "profile-name"
    assert env["AWS_SDK_LOAD_CONFIG"] == "true"

    creds_vol = _volume_by_name(pod, "creds")
    assert creds_vol["secret"]["secretName"] == "aws-creds-my-profile"
    creds_mount = _mount_by_name(container, "creds")
    assert creds_mount["mountPath"] == "/aws"
    assert creds_mount["readOnly"] is True

    # The re-signing sidecar holds the real credentials, so it must stay hardened.
    sc = container["securityContext"]
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["runAsNonRoot"] is True
    assert sc["runAsUser"] == 1000 and sc["runAsGroup"] == 1000
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert sc["seccompProfile"]["type"] == "RuntimeDefault"


# --------------------------------------------------------------------------- #
# mitm manifest — hardening + kube (mTLS / upstream-CA) wiring
# --------------------------------------------------------------------------- #


def test_mitm_manifest_is_hardened_without_kube():
    pod = next(m for m in cli._mitm_manifests("ns", "img", "") if m["kind"] == "Pod")
    sc = pod["spec"]["containers"][0]["securityContext"]
    assert sc["readOnlyRootFilesystem"] is True
    assert sc["allowPrivilegeEscalation"] is False
    assert sc["runAsNonRoot"] is True
    assert sc["capabilities"]["drop"] == ["ALL"]
    assert sc["seccompProfile"]["type"] == "RuntimeDefault"


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
    _assert_set_arg(args, "ssl_verify_upstream_trusted_ca=/kube-upstream-ca/bundle.pem")


# --------------------------------------------------------------------------- #
# Agent pod optional mounts (ssh keys + kubeconfig)
# --------------------------------------------------------------------------- #


def _minimal_contribution():
    return PodContribution(
        env={}, volumes=[], mounts=[], security_context={"privileged": True},
        init_command=["sleep", "infinity"], command=["bash"], memory="1Gi",
    )


def test_agent_pod_mounts_ssh_keys_read_only_outside_dot_ssh():
    pod = cli._agent_pod_manifest(
        "ns", "img", _minimal_contribution(), Path("/home/u"), "u", 1000, "",
        cli.AgentMounts(ssh_key_dir=Path("/host/keys")),
    )
    container = pod["spec"]["containers"][0]
    vol = _volume_by_name(pod, "ssh-keys")
    assert vol["hostPath"]["path"] == "/host/keys"
    assert vol["hostPath"]["type"] == "Directory"
    mount = _mount_by_name(container, "ssh-keys")
    # Keys land in ~/.sshclaude (read-only) so the agent can't tamper with them,
    # and ~/.ssh stays writable for ssh to create known_hosts itself.
    assert mount["mountPath"] == "/home/u/.sshclaude"
    assert mount["readOnly"] is True
    assert not any(
        m["mountPath"] == "/home/u/.ssh" for m in container["volumeMounts"]
    )


def test_agent_pod_mounts_kubeconfig_outside_home_with_env():
    pod = cli._agent_pod_manifest(
        "ns", "img", _minimal_contribution(), Path("/home/u"), "u", 1000, "",
        cli.AgentMounts(kube_config_secret="kube-config"),
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
# _build_aws_plan — dummy creds in the agent, AKIA -> sidecar routes
# --------------------------------------------------------------------------- #


def _decode_secret(manifest, key):
    return base64.b64decode(manifest["data"][key]).decode()


def test_build_aws_plan_dummy_creds_and_sigv4_routes(monkeypatch):
    monkeypatch.setattr(
        cli, "export_aws_profile_env",
        lambda profile: {"AWS_ACCESS_KEY_ID": "AKIAREAL", "AWS_SECRET_ACCESS_KEY": "realsecret"},
    )
    session = Session(session_dir=Path("/tmp/unused"), namespace="test-ns")
    plan = cli._build_aws_plan(session, ["test-profile", "My.Profile"])

    assert plan.profile_safe == {"test-profile": "test-profile", "My.Profile": "my-profile"}
    assert plan.dummy_secret_name == "agent-aws-creds"

    by_name = {m["metadata"]["name"]: m for m in plan.secret_manifests}
    # The agent's credentials Secret holds only deterministic dummy values.
    dummy_ini = _decode_secret(by_name["agent-aws-creds"], "credentials")
    assert "[test-profile]" in dummy_ini
    assert "AKIA" in dummy_ini and "DUMMYsecret" in dummy_ini
    assert "realsecret" not in dummy_ini
    # The real creds live in per-profile sidecar Secrets, never the agent's.
    assert "aws-creds-test-profile" in by_name
    assert "aws-creds-my-profile" in by_name
    assert by_name["agent-aws-creds"]["metadata"]["namespace"] == "test-ns"

    # Each dummy AKIA routes to its profile's sidecar Service.
    assert plan.sigv4_routes[aws.dummy_akia("test-profile")] == {
        "upstream_host": "sigv4-test-profile", "upstream_port": cli.PROXY_PORT,
    }
    assert plan.sigv4_routes[aws.dummy_akia("My.Profile")] == {
        "upstream_host": "sigv4-my-profile", "upstream_port": cli.PROXY_PORT,
    }


def test_build_aws_plan_no_profiles_has_no_dummy_secret_or_routes():
    session = Session(session_dir=Path("/tmp/unused"), namespace="test-ns")
    plan = cli._build_aws_plan(session, [])
    assert plan.dummy_secret_name is None
    assert plan.sigv4_routes == {}
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
    "certs_generated,force_rebuild,age",
    [
        (True, False, 10.0),                                   # certs just generated
        (False, True, 10.0),                                   # --force-rebuild
        (False, False, None),                                  # image missing
        (False, False, cli.AGENT_IMAGE_MAX_AGE_SECONDS + 1),   # stale
    ],
)
def test_ensure_agent_image_rebuilds(monkeypatch, certs_generated, force_rebuild, age):
    build, result = _ensure_image(
        monkeypatch, certs_generated=certs_generated, force_rebuild=force_rebuild, age=age
    )
    build.assert_called_once()
    assert result == "rebuilt-image"


def test_ensure_agent_image_reuses_fresh_image(monkeypatch):
    build, result = _ensure_image(
        monkeypatch, certs_generated=False, force_rebuild=False, age=10.0
    )
    build.assert_not_called()
    assert result == f"{cli.REGISTRY_PUSH_ENDPOINT}/agent-uplink-claude:latest"
