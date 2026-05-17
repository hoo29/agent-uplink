"""kubectl wrappers + manifest builders.

Stays low-level: no agent-uplink domain logic here. Other modules import these
helpers to assemble pods/secrets/etc and apply them via stdin to kubectl.
"""

from __future__ import annotations

import base64
import json
import logging
import time
from typing import Any

import yaml

from .process import run_command, run_interactive

LOGGER = logging.getLogger("agent-uplink")


# ---------------------------------------------------------------------------
# kubectl wrappers
# ---------------------------------------------------------------------------


def kubectl(
    *args: str,
    stdin: bytes | None = None,
    raise_error: bool = True,
) -> str:
    return run_command(["kubectl", *args], stdin=stdin, raise_error=raise_error)


def apply_manifests(manifests: list[dict]) -> None:
    """Apply a list of manifests as a single multi-doc YAML via stdin."""
    docs = [yaml.safe_dump(m, sort_keys=False) for m in manifests]
    payload = ("---\n" + "---\n".join(docs)).encode("utf-8")
    kubectl("apply", "-f", "-", stdin=payload)


def delete_namespace(name: str, *, wait: bool = False) -> None:
    """Best-effort namespace delete. By default returns immediately; the
    cluster finishes the cascade in the background (~10-30s for kata pods)."""
    kubectl(
        "delete",
        "namespace",
        name,
        f"--wait={'true' if wait else 'false'}",
        "--ignore-not-found=true",
        raise_error=False,
    )


def namespace_exists(name: str) -> bool:
    out = kubectl(
        "get",
        "namespace",
        name,
        "--ignore-not-found",
        "-o",
        "name",
        raise_error=False,
    )
    return bool(out.strip())


def wait_for_pod_ready(namespace: str, pod_name: str, *, timeout: int = 180) -> None:
    kubectl(
        "wait",
        "--for=condition=Ready",
        f"pod/{pod_name}",
        "-n",
        namespace,
        f"--timeout={timeout}s",
    )


def wait_for_pod_succeeded(
    namespace: str, pod_name: str, *, timeout: int = 120
) -> None:
    """Block until a Pod with restartPolicy=Never reaches Succeeded.
    Raises if it ends up Failed or doesn't terminate in time."""
    import time

    deadline = time.monotonic() + timeout
    last = "<none>"
    while time.monotonic() < deadline:
        phase = kubectl(
            "get",
            "pod",
            pod_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.status.phase}",
            raise_error=False,
        ).strip()
        last = phase or last
        if phase == "Succeeded":
            return
        if phase == "Failed":
            logs = kubectl("logs", pod_name, "-n", namespace, raise_error=False)
            raise RuntimeError(f"pod {pod_name} failed; logs:\n{logs}")
        time.sleep(1)
    raise TimeoutError(f"pod {pod_name} not Succeeded after {timeout}s (phase={last})")


def wait_for_deployment_ready(namespace: str, name: str, *, timeout: int = 180) -> None:
    kubectl(
        "rollout",
        "status",
        f"deployment/{name}",
        "-n",
        namespace,
        f"--timeout={timeout}s",
    )


def exec_interactive(
    namespace: str, pod_name: str, *, container: str | None, command: list[str]
) -> int:
    args = ["kubectl", "exec", "-it", pod_name, "-n", namespace]
    if container:
        args.extend(["-c", container])
    args.append("--")
    args.extend(command)
    return run_interactive(args)


# ---------------------------------------------------------------------------
# Manifest builders
# ---------------------------------------------------------------------------


def namespace_manifest(name: str, labels: dict[str, str] | None = None) -> dict:
    md: dict[str, Any] = {"name": name}
    if labels:
        md["labels"] = labels
    return {"apiVersion": "v1", "kind": "Namespace", "metadata": md}


def secret_manifest(
    name: str, namespace: str, data: dict[str, bytes], *, secret_type: str = "Opaque"
) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": name, "namespace": namespace},
        "type": secret_type,
        "data": {k: base64.b64encode(v).decode("ascii") for k, v in data.items()},
    }


def configmap_manifest(name: str, namespace: str, data: dict[str, str]) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name, "namespace": namespace},
        "data": data,
    }


def service_manifest(
    name: str,
    namespace: str,
    *,
    selector: dict[str, str],
    port: int,
    target_port: int | None = None,
    labels: dict[str, str] | None = None,
) -> dict:
    md: dict[str, Any] = {"name": name, "namespace": namespace}
    if labels:
        md["labels"] = labels
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": md,
        "spec": {
            "selector": selector,
            "ports": [
                {
                    "port": port,
                    "targetPort": target_port if target_port is not None else port,
                    "protocol": "TCP",
                }
            ],
        },
    }


def pod_manifest(
    name: str,
    namespace: str,
    *,
    labels: dict[str, str],
    image: str,
    command: list[str] | None = None,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    volumes: list[dict] | None = None,
    volume_mounts: list[dict] | None = None,
    runtime_class: str | None = None,
    container_security_context: dict | None = None,
    pod_security_context: dict | None = None,
    image_pull_policy: str = "IfNotPresent",
    memory: str = "256Mi",
    cpu: str = "1",
    stdin_open: bool = False,
    tty: bool = False,
    container_name: str = "main",
    restart_policy: str = "Always",
    ports: list[dict] | None = None,
    working_dir: str | None = None,
    automount_service_account_token: bool = False,
) -> dict:
    container: dict = {
        "name": container_name,
        "image": image,
        "imagePullPolicy": image_pull_policy,
        "resources": {"limits": {"memory": memory, "cpu": cpu}},
    }
    if command:
        container["command"] = command
    if args:
        container["args"] = args
    if env:
        container["env"] = [{"name": k, "value": v} for k, v in env.items()]
    if volume_mounts:
        container["volumeMounts"] = volume_mounts
    if container_security_context:
        container["securityContext"] = container_security_context
    if stdin_open:
        container["stdin"] = True
    if tty:
        container["tty"] = True
    if ports:
        container["ports"] = ports
    if working_dir:
        container["workingDir"] = working_dir

    spec: dict = {
        "restartPolicy": restart_policy,
        "containers": [container],
        "automountServiceAccountToken": automount_service_account_token,
    }
    if volumes:
        spec["volumes"] = volumes
    if runtime_class:
        spec["runtimeClassName"] = runtime_class
    if pod_security_context:
        spec["securityContext"] = pod_security_context

    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": labels,
        },
        "spec": spec,
    }


def deployment_manifest(
    name: str,
    namespace: str,
    *,
    labels: dict[str, str],
    pod_spec: dict,
    replicas: int = 1,
) -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": {
            "replicas": replicas,
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": pod_spec,
            },
        },
    }


def network_policy_manifest(
    name: str,
    namespace: str,
    *,
    pod_selector: dict,
    ingress: list[dict] | None = None,
    egress: list[dict] | None = None,
) -> dict:
    policy_types: list[str] = []
    if ingress is not None:
        policy_types.append("Ingress")
    if egress is not None:
        policy_types.append("Egress")
    spec: dict[str, Any] = {
        "podSelector": pod_selector,
        "policyTypes": policy_types,
    }
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
    }


# ---------------------------------------------------------------------------
# Reusable spec fragments
# ---------------------------------------------------------------------------


def tmpfs_volume(name: str, size: str = "64Mi") -> dict:
    return {"name": name, "emptyDir": {"medium": "Memory", "sizeLimit": size}}


def disk_emptydir_volume(name: str, size: str | None = None) -> dict:
    ed: dict[str, Any] = {}
    if size is not None:
        ed["sizeLimit"] = size
    return {"name": name, "emptyDir": ed}


def secret_volume(name: str, secret_name: str, *, default_mode: int = 0o644) -> dict:
    """Default mode 0o644 matches the K8s API default. With Secret volumes
    owned by root:fsGroup, the pod's runAsUser needs world-read (0o644) or
    group-read (0o440 + matching fsGroup) to actually read the file."""
    return {
        "name": name,
        "secret": {"secretName": secret_name, "defaultMode": default_mode},
    }


def configmap_volume(name: str, configmap_name: str) -> dict:
    return {"name": name, "configMap": {"name": configmap_name}}


def hostpath_volume(name: str, path: str, *, hp_type: str = "Directory") -> dict:
    return {"name": name, "hostPath": {"path": path, "type": hp_type}}


def hardened_container_security_context(
    *, uid: int | None = None, gid: int | None = None
) -> dict:
    """Hardening flags safe for any of our containers. Pass uid/gid for
    images whose default user we need to override (e.g. agent image)."""
    sc: dict[str, Any] = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "readOnlyRootFilesystem": True,
        "runAsNonRoot": True,
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    if uid is not None:
        sc["runAsUser"] = uid
    if gid is not None:
        sc["runAsGroup"] = gid
    return sc
