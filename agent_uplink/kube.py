"""Kubernetes context resolution for agent-uplink.

Reads host kubeconfig contexts (via `kubectl config view --flatten --minify`),
resolves bearer-token or client-certificate credentials, and produces a KubePlan
that the orchestrator uses to:

  - Wire mitm to present client certs on the upstream TLS leg (client cert auth).
  - Add cluster CAs to mitm's upstream trust store.
  - Inject the real bearer token as an Authorization header via the allow-list.
  - Mount a sanitized pod kubeconfig (mitm CA for trust, real cred stripped).

Only two auth methods are supported in v1:
  - Static bearer token (user.token or user.tokenFile)
  - Client certificate (user.client-certificate-data + user.client-key-data)

exec / auth-provider (EKS/GKE/AKS plugins, OIDC) and username/password are
rejected at startup with a clear "unsupported in v1" error. insecure-skip-tls-verify
contexts are also refused.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .process import run_command

_BEARER_PLACEHOLDER = "agent-uplink-placeholder"


@dataclass
class KubePlan:
    """Products of kubeconfig resolution; consumed by cli.py."""

    # Synthetic allow rules — one per cluster host. Bearer rules carry the
    # resolved Authorization header; cert rules carry none (the cert is
    # presented on the TLS leg by mitm's client_certs option, not via a header).
    rules: list[dict] = field(default_factory=list)
    # Filename -> PEM bytes (cert + key concatenated) for mitm's client_certs
    # directory. mitmproxy looks up <host>.pem when connecting to that host.
    client_certs: dict[str, bytes] = field(default_factory=dict)
    # All cluster CA PEMs concatenated — passed to mitm as its upstream trust
    # bundle (additive to the system trust store).
    upstream_ca_bundle: bytes = b""
    # Sanitized kubeconfig: real server URLs, mitm CA for trust, real
    # credentials stripped (bearer token replaced with placeholder, client
    # cert/key fields absent).
    pod_kubeconfig: bytes = b""


def _kubectl_view(context: str, kubeconfig_path: Path | None) -> dict[str, Any]:
    """Return the flattened, minified kubeconfig for one context as parsed JSON.

    --flatten inlines file-based certs/keys into their *-data counterparts.
    --minify trims to the single selected context, cluster, and user.
    """
    cmd = [
        "kubectl", "config", "view",
        "--flatten",
        "--minify",
        "--output=json",
        f"--context={context}",
    ]
    if kubeconfig_path is not None:
        cmd.append(f"--kubeconfig={kubeconfig_path}")
    raw = run_command(cmd)
    return json.loads(raw)


def _host_from_url(server: str) -> str:
    """Return the hostname (without port) from a k8s API server URL."""
    parsed = urllib.parse.urlparse(server)
    return parsed.hostname or server


def resolve(
    kubeconfig_path: Path | None,
    context_names: list[str],
    mitm_ca_cert: bytes,
) -> KubePlan:
    """Resolve kubeconfig contexts into a KubePlan.

    For each named context, reads the cluster CA, server URL, and user
    credentials from the host kubeconfig; validates the auth method; builds
    mitm wiring and a sanitized pod kubeconfig. Real credentials (token or
    client key) never appear in the pod kubeconfig or in the KubePlan's rules
    in cleartext beyond what the mitm rules engine already holds.

    Raises ValueError on any unsupported or unsafe configuration.
    """
    if not context_names:
        return KubePlan()

    clusters_out: list[dict] = []
    users_out: list[dict] = []
    contexts_out: list[dict] = []
    rules: list[dict] = []
    client_certs: dict[str, bytes] = {}
    ca_pems: list[bytes] = []
    seen_hosts: dict[str, str] = {}  # host -> context name (for clash detection)

    for ctx_name in context_names:
        data = _kubectl_view(ctx_name, kubeconfig_path)

        cluster_entries = data.get("clusters") or []
        user_entries = data.get("users") or []
        context_entries = data.get("contexts") or []

        if not cluster_entries:
            raise ValueError(f"context {ctx_name!r}: no cluster found in kubeconfig")
        if not user_entries:
            raise ValueError(f"context {ctx_name!r}: no user found in kubeconfig")

        cluster_entry = cluster_entries[0]
        user_entry = user_entries[0]
        ctx_entry = context_entries[0] if context_entries else {}

        cluster_name = cluster_entry["name"]
        user_name = user_entry["name"]
        cluster = cluster_entry["cluster"]
        user = user_entry.get("user") or {}
        ctx_spec = ctx_entry.get("context") or {}

        server = cluster.get("server", "")
        if not server:
            raise ValueError(f"context {ctx_name!r}: cluster has no server URL")

        if cluster.get("insecure-skip-tls-verify"):
            raise ValueError(
                f"context {ctx_name!r}: insecure-skip-tls-verify is not supported; "
                "a cluster CA (certificate-authority-data) is required"
            )

        ca_data = cluster.get("certificate-authority-data")
        if not ca_data:
            raise ValueError(
                f"context {ctx_name!r}: cluster has no certificate-authority-data; "
                "a cluster CA is required"
            )

        ca_pem = base64.b64decode(ca_data)
        host = _host_from_url(server)

        if host in seen_hosts:
            raise ValueError(
                f"contexts {ctx_name!r} and {seen_hosts[host]!r} both resolve to "
                f"API server host {host!r}; they cannot both be selected"
            )
        seen_hosts[host] = ctx_name

        # Detect auth method and reject unsupported ones.
        if user.get("exec") or user.get("auth-provider"):
            raise ValueError(
                f"context {ctx_name!r}: exec and auth-provider credentials are not "
                "supported in agent-uplink v1; use a static bearer token or a "
                "client certificate instead"
            )
        if user.get("username") or user.get("password"):
            raise ValueError(
                f"context {ctx_name!r}: username/password credentials are not "
                "supported; use a static bearer token or a client certificate"
            )

        token = user.get("token")
        token_file = user.get("tokenFile")
        client_cert_data = user.get("client-certificate-data")
        client_key_data = user.get("client-key-data")

        if token or token_file:
            if token_file and not token:
                token = Path(token_file).read_text(encoding="utf-8").strip()
            rule: dict[str, Any] = {
                "name": f"kube-{ctx_name}",
                "host": re.escape(host),
                "inject": {"headers": {"Authorization": f"Bearer {token}"}},
            }
            pod_user_data: dict[str, Any] = {"token": _BEARER_PLACEHOLDER}

        elif client_cert_data and client_key_data:
            cert_pem = base64.b64decode(client_cert_data)
            key_pem = base64.b64decode(client_key_data)
            cert_filename = f"{host}.pem"
            if cert_filename in client_certs and client_certs[cert_filename] != cert_pem + key_pem:
                raise ValueError(
                    f"context {ctx_name!r}: host {host!r} already has a different "
                    f"client certificate from context {seen_hosts[host]!r}"
                )
            client_certs[cert_filename] = cert_pem + key_pem
            rule = {
                "name": f"kube-{ctx_name}",
                "host": re.escape(host),
            }
            pod_user_data = {}

        else:
            raise ValueError(
                f"context {ctx_name!r}: no supported credentials found; expected "
                "token, tokenFile, or client-certificate-data + client-key-data"
            )

        rules.append(rule)
        ca_pems.append(ca_pem)

        mitm_ca_b64 = base64.b64encode(mitm_ca_cert).decode("ascii")
        clusters_out.append({
            "name": cluster_name,
            "cluster": {
                "server": server,
                "certificate-authority-data": mitm_ca_b64,
            },
        })
        users_out.append({"name": user_name, "user": pod_user_data})
        ctx_out: dict[str, Any] = {"cluster": cluster_name, "user": user_name}
        if ctx_spec.get("namespace"):
            ctx_out["namespace"] = ctx_spec["namespace"]
        contexts_out.append({"name": ctx_name, "context": ctx_out})

    pod_kubeconfig_dict: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Config",
        "current-context": context_names[0],
        "preferences": {},
        "clusters": clusters_out,
        "users": users_out,
        "contexts": contexts_out,
    }
    pod_kubeconfig_bytes = yaml.dump(
        pod_kubeconfig_dict, default_flow_style=False, allow_unicode=True
    ).encode("utf-8")

    # Concatenate all cluster CAs into a single PEM bundle.
    upstream_ca_bundle = b"\n".join(ca_pems)

    return KubePlan(
        rules=rules,
        client_certs=client_certs,
        upstream_ca_bundle=upstream_ca_bundle,
        pod_kubeconfig=pod_kubeconfig_bytes,
    )
