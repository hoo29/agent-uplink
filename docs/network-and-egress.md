# NetworkPolicy perimeter

`k3s` ships a built-in NetworkPolicy controller (iptables-based) that enforces the policies against pods' host-side veth interfaces. Kata pods only egress through that veth, so the policies hold for the agent pod too. The per-session policies are:

| Policy | Selector | Effect |
|---|---|---|
| `default-deny` | all pods | Deny all ingress + egress unless another policy allows it |
| `agent-egress` | `app=agent` | Egress only to `app=mitm` on TCP 8080 + `kube-system/kube-dns` on UDP/TCP 53, plus TCP 22 to any `--ssh-cidr` ranges and the `app=ssh-agent` holder on TCP 8765 when `--ssh-key-dir` is set (see SSH egress) |
| `mitm-policy` | `app=mitm` | Ingress from `app=agent` on TCP 8080; egress to the whole internet (incl. the real AWS endpoints it re-signs for) except link-local (`169.254.0.0/16`, `fe80::/10`) |
| `ssh-agent-policy` | `app=ssh-agent` | Present only with `--ssh-key-dir`: ingress from `app=agent` on TCP 8765 (the signing bridge); no egress (the holder does pure crypto) |

The mitm pod forwards on the agent's behalf, so its egress is where an agent-driven request leaves the perimeter. The default
rules allow `GET` to any host, so the link-local `except` is what stops an agent from pivoting through the proxy to the node's
cloud-metadata service (`169.254.169.254`, common to all clouds) and reading the instance's IAM role credentials. Blocking at L3
also defeats a hostname that resolves to a metadata IP (DNS rebinding), which the mitm addon can't see. Private ranges (`10/8`,
`172.16/12`, `192.168/16`) are deliberately not blocked — a private-IP kube API server is a supported destination — so an agent
under the default rules can still reach other in-cluster/VPC services by IP over `GET`; for untrusted workloads pair
`--no-default-rules` with an explicit host allow-list.

## SSH egress

By default the agent pod can only reach `mitm` and `kube-dns`, so SSH is blocked. The SSH transport bypasses mitm (SSH is not
HTTP — there is no allow-list, rule engine, or per-request credential injection for it; reachability is the only control). Two
flags open it:

- `--ssh-cidr <CIDR> [<CIDR> ...]` — adds an `agent-egress` rule allowing TCP 22 only to those `ipBlock` CIDRs (a bare IP becomes
  `/32`; CIDRs are normalised to their network address). Those CIDRs are reachable on no other port; everything else stays denied.
  This `ipBlock` set is the sole control on SSH egress, so scope it tightly. NetworkPolicy matches resolved IPs, not DNS names —
  `kube-dns` still resolves the target, but the returned IP must fall inside an allowed CIDR (mind DNS/CDN churn for hosts like
  GitHub).
- `--ssh-key-dir <DIR>` — the private keys never enter the agent pod. They are loaded into an `ssh-agent` running in a dedicated
  holder pod (`app=ssh-agent`), which the agent reaches over a `socat` TCP bridge, so it can request signatures but never read the
  key bytes. The agent container is `privileged`/`CAP_SYS_ADMIN` inside the kata guest, so a same-pod sidecar would not be a
  boundary against it; the holder is a separate, hardened pod (non-root, read-only root, `drop=[ALL]`), modelled on mitm. Host→key
  mapping stays client-side: for each private key a `<name>.pub` is derived host-side via `ssh-keygen -y` (which also rejects
  passphrase-protected keys, since the holder's `ssh-add` runs non-interactively) and, with any `config`, dropped file-by-file into
  the agent's `~/.ssh` via per-file subPath mounts; the agent gets `SSH_AUTH_SOCK` pointing at the bridged socket. Per-file mounts
  (not a single read-only mount over `~/.ssh`, which the image pre-creates user-owned) keep the directory writable so ssh can
  create `known_hosts`, and `~/.ssh/config` is read by default with no Include. Pin a key to a host with
  `IdentityFile ~/.ssh/<name>.pub` + `IdentitiesOnly yes`; ssh loads the public half locally and the holder signs.

Topology: the holder runs `ssh-agent` + `socat TCP-LISTEN→UNIX` (port 8765); a `ssh-agent-relay` sidecar in the agent pod runs
`socat UNIX-LISTEN→TCP` to present the socket locally. `agent-egress` adds a rule to the holder on 8765; `ssh-agent-policy` accepts
that ingress and grants the holder no egress (it does pure crypto). The SSH connection leaves the agent pod via the `--ssh-cidr`
rule — only signing is delegated. This buys key confidentiality (no theft/reuse), not per-host authorization: anyone who can reach
the agent socket can sign for any host the key works on, so the CIDR set remains the egress control (tighten further with OpenSSH
8.9+ destination-constrained keys if needed).

The two flags are independent but want each other: keys without a CIDR can't reach anything on 22, and a CIDR without keys opens egress with nothing to authenticate with — each case logs a warning. Implementation: `--ssh-cidr` flows into `_network_policies`, `--ssh-key-dir` is split by `agent_uplink/sshagent.py` into the holder + agent Secrets and wired in `cli.py` (`_ssh_agent_manifests`, the relay sidecar in `_agent_pod_manifest`); both are orchestrator-level (universal) concerns, so no `Agent` subclass is involved. The holder/sidecar reuse the agent image purely for its `ssh-agent`/`socat` binaries.

## Git over HTTPS

SSH egress (above) is for shelling into machines, not git; it bypasses mitm, so it has no allow-list or credential
injection. Git runs over HTTPS through mitm, so the same rule engine governs it and injects credentials host-side.

To avoid editing existing SSH remotes, the agent image bakes `/etc/gitconfig` with git `insteadOf` rules that
rewrite SSH URLs to their HTTPS form at operation time for github.com, gitlab.com, bitbucket.org (both
`git@host:owner/repo` and `ssh://git@host/owner/repo`). So `git clone git@github.com:owner/repo.git` transparently
becomes an HTTPS clone routed through mitm. Submodules with SSH URLs are rewritten the same way.

Two orchestrator-level flags layer a runtime overlay on top of the baked defaults (wired in `cli.py` via
`agent_uplink/git.py`; no `Agent` subclass involved):

- `--git-https-rewrite <HOST> [<HOST> ...]` — additional hosts (e.g. self-hosted GitLab) to rewrite SSH→HTTPS.
  Auth for them still needs a matching `--rules` entry.
- `--no-git-identity` — by default the host's `user.name`/`user.email` (read via `git config --global`) are
  surfaced so commits are attributed; this flag omits them.

The overlay is shipped as the `git-config` Secret and mounted read-only at `/etc/gitconfig.d/agent-uplink.inc`,
which the baked `/etc/gitconfig` pulls in via `include.path` (a missing file is silently ignored). It carries only
name/email + host rewrites, no secrets, so it is safe in the agent pod; the agent's `~/.gitconfig` is left
writable. `GIT_TERMINAL_PROMPT=0` is set so denied/unconfigured auth fails fast instead of hanging.

Auth is opt-in. The default allow-list only permits `GET`/`OPTIONS`/`HEAD`, but git transport POSTs to
`git-upload-pack` (fetch) and `git-receive-pack` (push). Pass `--rules examples/rules/git.yaml` to allow those
endpoints and inject HTTP Basic auth (keyring value = `base64("<user>:<token>")`; the token never enters the pod).
The rule injects auth on `info/refs` too, since a private repo's discovery `GET` returns `401` otherwise. Without
such a rule, even a public clone is denied at `git-upload-pack`.

## Kubernetes cluster access

`--kube-context <ctx> [<ctx> ...]` exposes one or more host kubeconfig contexts to the agent. Unlike SSH egress, k8s traffic flows through mitmproxy and is fully governed by the allow-list; no NetworkPolicy is modified.

Auth methods supported:
- Static bearer token (`user.token` or `user.tokenFile`) — injected as an `Authorization: Bearer` header on the upstream leg.
- Client certificate (`user.client-certificate-data` + `user.client-key-data`) — presented by mitmproxy during upstream TLS.

`exec`/`auth-provider` contexts (EKS, GKE, AKS, OIDC) are rejected at startup with a clear error. `insecure-skip-tls-verify` is also refused; a cluster CA is required.

Produced per context:
- A sanitized pod kubeconfig (real server URL, mitm CA for trust, real credential stripped — placeholder token for bearer, no cert/key fields for client cert).
- A synthetic allow rule for the API server host; bearer rules carry the `Authorization` injection, cert rules carry none.
- For client cert auth: a `<host>.pem` file (cert + key) mounted into mitm's `client_certs` directory.
- All cluster serving CAs are combined into an upstream trust bundle (`ssl_verify_upstream_trusted_ca`) so mitmproxy can verify
  the API server's certificate. That option replaces mitmproxy's default trust store rather than augmenting it, so the mitm
  container concatenates its own `certifi` roots with the cluster CAs at startup (into `/tmp/upstream-ca-bundle.pem`) and trusts
  the combined file — otherwise every public upstream (pypi.org, etc.) would fail TLS.

`--kubeconfig <path>` overrides the source file (default: `$KUBECONFIG` then `~/.kube/config`).

Implementation lives in `agent_uplink/kube.py` (`resolve()`) and is an orchestrator-level concern wired in `cli.py`; no `Agent` subclass is involved.

See `examples/kube/README.md` for worked examples.
