"""kubectl wrappers + manifest builders. Low-level, no domain logic."""

from __future__ import annotations

import base64
import json
import logging
import time
from dataclasses import dataclass
from typing import Any

import yaml

from .process import run_command, run_interactive

LOGGER = logging.getLogger("agent-uplink")


# ---------------------------------------------------------------------------
# kubectl wrappers
# ---------------------------------------------------------------------------


# kubeconfig context every deploy-side kubectl call targets; None uses the
# current-context. Set once at startup via set_kube_context().
_KUBE_CONTEXT: str | None = None


def set_kube_context(context: str | None) -> None:
    """Select the context for all deploy-side kubectl calls. Call once at startup;
    empty/None uses the kubeconfig's current-context."""
    global _KUBE_CONTEXT
    _KUBE_CONTEXT = context or None


def _context_args() -> list[str]:
    return ["--context", _KUBE_CONTEXT] if _KUBE_CONTEXT else []


def kubectl(
    *args: str,
    stdin: bytes | None = None,
    raise_error: bool = True,
) -> str:
    return run_command(
        ["kubectl", *_context_args(), *args], stdin=stdin, raise_error=raise_error
    )


def apply_manifests(manifests: list[dict]) -> None:
    """Apply a list of manifests as a single multi-doc YAML via stdin."""
    docs = [yaml.safe_dump(m, sort_keys=False) for m in manifests]
    payload = ("---\n" + "---\n".join(docs)).encode("utf-8")
    kubectl("apply", "-f", "-", stdin=payload)


def list_namespaces(label_selector: str) -> list[dict]:
    """Return namespace objects matching a label selector (the raw items from
    `kubectl get -o json`). Empty list if none match or the query fails."""
    out = kubectl(
        "get", "namespace", "-l", label_selector, "-o", "json", raise_error=False
    )
    if not out.strip():
        return []
    try:
        return json.loads(out).get("items", [])
    except json.JSONDecodeError:
        return []


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


def wait_for_pod_ready(namespace: str, pod_name: str, *, timeout: int = 180) -> None:
    try:
        kubectl(
            "wait",
            "--for=condition=Ready",
            f"pod/{pod_name}",
            "-n",
            namespace,
            f"--timeout={timeout}s",
        )
    except RuntimeError as exc:
        # kubectl wait only says "timed out"; capture pod status + events for the
        # real cause before teardown deletes the namespace.
        status = kubectl(
            "get", "pod", pod_name, "-n", namespace, "-o", "wide",
            raise_error=False,
        ).strip()
        events = kubectl(
            "get", "events", "-n", namespace,
            "--field-selector", f"involvedObject.name={pod_name}",
            raise_error=False,
        ).strip()
        detail = "\n\n".join(part for part in (status, events) if part)
        raise RuntimeError(
            f"pod {pod_name} in {namespace} not Ready after {timeout}s"
            + (f":\n{detail}" if detail else "")
        ) from exc


def wait_for_pod_succeeded(
    namespace: str, pod_name: str, *, timeout: int = 120
) -> None:
    """Block until a Pod with restartPolicy=Never reaches Succeeded.
    Raises if it ends up Failed or doesn't terminate in time."""
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
    args = ["kubectl", *_context_args(), "exec", "-it", pod_name, "-n", namespace]
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


@dataclass
class Resources:
    """Container resource requests + limits. `memory`/`cpu` are the limits;
    `*_request` are the scheduler reservation, defaulting to the limit when unset.
    A request below the limit gives Burstable QoS; `cpu=None` omits the CPU limit
    entirely (uncapped burst)."""

    memory: str = "256Mi"
    cpu: str | None = "1"
    memory_request: str | None = None
    cpu_request: str | None = None


@dataclass
class Stdio:
    """Interactive stdio knobs (for `kubectl exec -it`)."""

    stdin: bool = False
    tty: bool = False


def container_spec(
    *,
    image: str,
    name: str = "main",
    command: list[str] | None = None,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    volume_mounts: list[dict] | None = None,
    security_context: dict | None = None,
    image_pull_policy: str = "IfNotPresent",
    resources: Resources | None = None,
    stdio: Stdio | None = None,
    ports: list[dict] | None = None,
    working_dir: str | None = None,
) -> dict:
    resources = resources or Resources()
    stdio = stdio or Stdio()
    requests: dict = {"memory": resources.memory_request or resources.memory}
    cpu_request = resources.cpu_request or resources.cpu
    if cpu_request is not None:
        requests["cpu"] = cpu_request
    limits: dict = {"memory": resources.memory}
    if resources.cpu is not None:
        limits["cpu"] = resources.cpu
    container: dict = {
        "name": name,
        "image": image,
        "imagePullPolicy": image_pull_policy,
        "resources": {"requests": requests, "limits": limits},
    }
    if command:
        container["command"] = command
    if args:
        container["args"] = args
    if env:
        container["env"] = [{"name": k, "value": v} for k, v in env.items()]
    if volume_mounts:
        container["volumeMounts"] = volume_mounts
    if security_context:
        container["securityContext"] = security_context
    if stdio.stdin:
        container["stdin"] = True
    if stdio.tty:
        container["tty"] = True
    if ports:
        container["ports"] = ports
    if working_dir:
        container["workingDir"] = working_dir
    return container


def pod_spec(
    *,
    container: dict,
    volumes: list[dict] | None = None,
    runtime_class: str | None = None,
    pod_security_context: dict | None = None,
    restart_policy: str = "Always",
    host_network: bool = False,
    dns_policy: str | None = None,
    automount_service_account_token: bool = False,
    extra_containers: list[dict] | None = None,
) -> dict:
    spec: dict = {
        "restartPolicy": restart_policy,
        "containers": [container, *(extra_containers or [])],
        "automountServiceAccountToken": automount_service_account_token,
    }
    if volumes:
        spec["volumes"] = volumes
    if runtime_class:
        spec["runtimeClassName"] = runtime_class
    if pod_security_context:
        spec["securityContext"] = pod_security_context
    if host_network:
        spec["hostNetwork"] = True
    if dns_policy:
        spec["dnsPolicy"] = dns_policy
    return spec


def pod_manifest(name: str, namespace: str, *, labels: dict[str, str], spec: dict) -> dict:
    """Wrap a `pod_spec(...)` result in a Pod manifest. Build the spec with
    `pod_spec(container=container_spec(...), ...)`."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": spec,
    }


def deployment_manifest(
    name: str,
    namespace: str,
    *,
    labels: dict[str, str],
    pod_spec: dict,
    replicas: int = 1,
    strategy: str | None = None,
) -> dict:
    spec: dict[str, Any] = {
        "replicas": replicas,
        "selector": {"matchLabels": labels},
        "template": {
            "metadata": {"labels": labels},
            "spec": pod_spec,
        },
    }
    if strategy is not None:
        spec["strategy"] = {"type": strategy}
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": name, "namespace": namespace, "labels": labels},
        "spec": spec,
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
    """Memory-backed emptyDir (tmpfs), counting against the pod's memory limit.
    Reserve for paths needing tmpfs: an overlayfs upperdir (kata's virtio-fs is
    rejected as one) or a unix socket. Use emptydir_volume otherwise."""
    return {"name": name, "emptyDir": {"medium": "Memory", "sizeLimit": size}}


def emptydir_volume(name: str, size: str) -> dict:
    """Disk-backed emptyDir on node ephemeral storage, not the pod's memory
    budget. sizeLimit caps ephemeral-storage use."""
    return {"name": name, "emptyDir": {"sizeLimit": size}}


def secret_volume(name: str, secret_name: str) -> dict:
    """Secret volume. K8s default mode (0o644) so runAsUser can read it
    regardless of fsGroup."""
    return {"name": name, "secret": {"secretName": secret_name}}


def configmap_volume(name: str, configmap_name: str) -> dict:
    return {"name": name, "configMap": {"name": configmap_name}}


def hostpath_volume(name: str, path: str, *, hp_type: str = "Directory") -> dict:
    return {"name": name, "hostPath": {"path": path, "type": hp_type}}


def hardened_container_security_context(
    *, uid: int | None = None, gid: int | None = None
) -> dict:
    """Hardening flags safe for any of our containers. Pass uid/gid to override
    an image's default user."""
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
