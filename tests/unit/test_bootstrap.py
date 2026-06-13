"""Unit tests for the one-time host/cluster bootstrap. No cluster or docker
needed — the build/push and `docker image inspect` shell-outs are monkey-patched
so the security-relevant logic (what enters the image build context, the
registry-binding posture, the registries.yaml guard, the rebuild-age decision)
is pinned in isolation."""

import datetime as _dt
from pathlib import Path

import pytest

from agent_uplink import bootstrap
from agent_uplink.process import CommandResult


# --------------------------------------------------------------------------- #
# build context: the CA private key must never enter an image layer
# --------------------------------------------------------------------------- #


def _capture_build_context(monkeypatch) -> dict:
    """Monkey-patch the build/push shell-outs and snapshot the build-context
    directory contents at `docker build` time (the tempdir is deleted right
    after, so the snapshot has to happen inside the call)."""
    captured: dict = {}

    def fake_run_command(command, **kwargs):
        if command[:2] == ["docker", "build"]:
            ctx = Path(command[-1])
            captured["files"] = {
                str(p.relative_to(ctx)) for p in ctx.rglob("*") if p.is_file()
            }
        return ""

    monkeypatch.setattr(bootstrap, "run_command", fake_run_command)
    return captured


def test_build_and_push_agent_image_excludes_ca_private_key(tmp_path, monkeypatch):
    # Source container dir: a Dockerfile, some code, plus a stale certs/ dir and
    # a __pycache__ that must NOT be copied into the build context.
    container_dir = tmp_path / "agentimg"
    container_dir.mkdir()
    (container_dir / "Dockerfile").write_text("FROM scratch\n")
    (container_dir / "entrypoint.py").write_text("print('hi')\n")
    (container_dir / "certs").mkdir()
    (container_dir / "certs" / "old-file.pem").write_text("STALE")
    (container_dir / "__pycache__").mkdir()
    (container_dir / "__pycache__" / "m.pyc").write_text("bytecode")

    # mitm dir holds BOTH the public cert and the CA private key right next to
    # each other; only the public cert may be copied in.
    mitm_dir = tmp_path / "mitm"
    mitm_dir.mkdir()
    (mitm_dir / "mitmproxy-ca-cert.pem").write_text("PUBLIC CERT")
    (mitm_dir / "mitmproxy-ca.pem").write_text("PRIVATE KEY + CERT")

    captured = _capture_build_context(monkeypatch)
    bootstrap.build_and_push_agent_image("repo", container_dir, "u", mitm_dir)

    files = captured["files"]
    # The public CA cert is baked in so the agent trusts mitm's interception.
    assert "certs/mitmproxy-ca-cert.pem" in files
    # The CA private key must never reach a build layer or artifact.
    assert "certs/mitmproxy-ca.pem" not in files
    # The source certs/ dir is ignored — only the freshly-copied public cert.
    assert "certs/old-file.pem" not in files
    # No bytecode leaks into the context.
    assert not any(f.endswith(".pyc") or "__pycache__" in f for f in files)
    # The actual image inputs are present.
    assert "Dockerfile" in files
    assert "entrypoint.py" in files


# --------------------------------------------------------------------------- #
# local registry deployment posture
# --------------------------------------------------------------------------- #


def test_registry_manifests_bind_loopback_and_host_network():
    manifests = bootstrap._registry_manifests("registry:2")
    dep = next(m for m in manifests if m["kind"] == "Deployment")
    pod = dep["spec"]["template"]["spec"]
    container = pod["containers"][0]

    env = {e["name"]: e["value"] for e in container["env"]}
    # Bind loopback only: the unauthenticated registry must not be exposed on the
    # node's LAN interfaces, even though hostNetwork is on.
    assert env["REGISTRY_HTTP_ADDR"] == "127.0.0.1:5000"
    assert pod["hostNetwork"] is True
    assert pod["dnsPolicy"] == "ClusterFirstWithHostNet"

    port = container["ports"][0]
    assert port["containerPort"] == 5000
    assert port["hostPort"] == bootstrap.REGISTRY_HOST_PORT == 5000
    assert port["protocol"] == "TCP"


# --------------------------------------------------------------------------- #
# image age (drives the rebuild decision in cli._ensure_agent_image)
# --------------------------------------------------------------------------- #


def test_get_image_age_seconds_missing_image_returns_none(monkeypatch):
    # `docker image inspect` exits non-zero for an absent image.
    monkeypatch.setattr(
        bootstrap, "run", lambda *a, **k: CommandResult(1, "", "No such image")
    )
    assert bootstrap.get_image_age_seconds("img") is None


def test_get_image_age_seconds_empty_output_returns_none(monkeypatch):
    # Defensive: succeeded but printed nothing.
    monkeypatch.setattr(bootstrap, "run", lambda *a, **k: CommandResult(0, "", ""))
    assert bootstrap.get_image_age_seconds("img") is None


def test_get_image_age_seconds_parses_iso_timestamp(monkeypatch):
    class _FrozenDateTime(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return _dt.datetime(2024, 6, 13, 10, 30, 45, tzinfo=tz)

    monkeypatch.setattr(
        bootstrap,
        "run",
        lambda *a, **k: CommandResult(0, "2024-06-12T10:30:45.123456Z\n", ""),
    )
    monkeypatch.setattr(bootstrap, "datetime", _FrozenDateTime)
    # 24h apart; the trailing 'Z' and fractional seconds are stripped before parse.
    assert bootstrap.get_image_age_seconds("img") == 86400.0


# --------------------------------------------------------------------------- #
# registries.yaml guard
# --------------------------------------------------------------------------- #


def test_check_registries_yaml_missing_file_exits(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap, "K3S_REGISTRIES_PATH", tmp_path / "registries.yaml")
    with pytest.raises(SystemExit) as exc:
        bootstrap.check_registries_yaml()
    assert "One-time k3s setup" in str(exc.value)


def test_check_registries_yaml_without_localhost_exits(tmp_path, monkeypatch):
    path = tmp_path / "registries.yaml"
    path.write_text("mirrors: {}\n")
    monkeypatch.setattr(bootstrap, "K3S_REGISTRIES_PATH", path)
    with pytest.raises(SystemExit) as exc:
        bootstrap.check_registries_yaml()
    assert "localhost:5000" in str(exc.value)


def test_check_registries_yaml_configured_passes(tmp_path, monkeypatch):
    path = tmp_path / "registries.yaml"
    path.write_text(bootstrap._REGISTRIES_YAML_SETUP)
    monkeypatch.setattr(bootstrap, "K3S_REGISTRIES_PATH", path)
    bootstrap.check_registries_yaml()  # no raise
