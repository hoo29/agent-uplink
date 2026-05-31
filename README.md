# agent-uplink

Run a coding agent in a Kata Containers microVM on a local k3s cluster with restricted network access. All^ outbound traffic is routed through a mitmproxy pod that enforces an allowlist and can inject credentials from your OS keyring, so secrets never enter the agent pod.

Agent-agnostic: orchestration is generic, each agent is a subclass under `agent_uplink/agents/<name>/`. Today only `claude` is implemented.

**Linux only** (WSL2 works). Tested against k3s.

## Architecture

```mermaid
flowchart LR
    subgraph host["host"]
        keyring[("OS keyring")]
        awscreds[("AWS creds<br/>(host env)")]
        dockerd["docker build + push<br/>→ localhost:5000"]
    end

    subgraph registry_ns["agent-uplink-system (long-lived)"]
        registry["registry:2<br/>(hostPort 5000)"]
    end

    subgraph session_ns["agent-uplink-&lt;id&gt; (per-session)"]
        subgraph agent_pod["Pod: agent (kata-clh)"]
            agent["agent CLI"]
        end
        subgraph mitm_pod["Pod: mitm"]
            mitm["mitmproxy<br/>+ filter addon"]
        end
        subgraph sigv4_pods["Pods: sigv4-&lt;profile&gt;"]
            sidecar["aws-sigv4-proxy<br/>(one per profile)"]
        end
        rules[("Secret: rules-json")]
        certs[("Secret: mitm-certs")]
        creds[("Secret: aws-creds-*")]
    end

    internet(("Internet"))
    aws(("AWS APIs"))

    dockerd -->|push| registry
    registry -->|pull| agent_pod
    keyring -.->|resolved at startup| rules
    awscreds -.->|host-side export| creds
    rules --> mitm
    certs --> mitm
    creds --> sidecar
    agent -->|HTTPS_PROXY=http://mitm:8080| mitm
    mitm -->|allowed + injected| internet
    mitm -->|SigV4 reroute by dummy AKIA| sidecar
    sidecar -->|re-signed| aws
```

## Install

```bash
pip install -e .
```

Requires `kubectl`, `docker`, Python 3.10+, and a k3s cluster with a kata RuntimeClass (`kubectl get runtimeclass`). `aws` CLI is needed for `--aws-profiles`. Run from inside your home directory.

On first run `agent-uplink` will print the one-time `/etc/rancher/k3s/registries.yaml` snippet needed so containerd can pull from the in-cluster registry at `localhost:5000`.

## Usage

```bash
agent-uplink claude --anthropic                                       # Anthropic API
agent-uplink claude --bedrock                                         # AWS Bedrock (bearer token)
agent-uplink claude --anthropic --rules examples/rules/atlassian.yaml
agent-uplink claude --bedrock --aws-profiles profile1 profile2
agent-uplink claude --anthropic --force-rebuild
agent-uplink claude --anthropic --rules examples/rules/ecr.yaml         # authenticated docker pulls (ECR)
```

`--anthropic` reads `~/.claude/.credentials.json` (run `claude login` first). `--bedrock` reads `keyring get bedrock key`.

Each run creates a session namespace `agent-uplink-<id>`, torn down on exit.

### Authenticated docker pulls

`~/.docker/config.json` is never mounted into the pod. Private registry auth is handled the same way as everything else — a mitm rule injects the `Authorization` header on the registry host. The in-pod `dockerd` pulls anonymously; mitm adds the credential. `examples/rules/ecr.yaml` shows this for AWS ECR (Basic auth, token resolved on the host via `{{exec:...}}`, never entering the pod).

## Rules

YAML allow-list, first match wins. Match priority is by **layer**, not regex length: your rules first, then the agent's auth rule, then agent defaults, then the generic `GET`/`OPTIONS`/`HEAD`-anywhere catch-all last. `--no-default-rules` (or `replace_defaults: true`) keeps only your rules (and drops the auth rule).

```yaml
rules:
  - name: my-rule
    host: '<regex>'             # required
    methods: [GET, POST]        # optional
    paths: ['<regex>']          # optional
    inject:                     # optional
      headers:
        Authorization: 'Bearer {{keyring:my-service:my-user}}'
```

Header values support two placeholder forms, both resolved on the host before the mitm pod starts:

- `{{keyring:SERVICE:USERNAME}}` — static secret from the OS keyring (`keyring set my-service my-user`).
- `{{exec:COMMAND}}` — stdout (trailing newline stripped) of a host shell command, for short-lived dynamic credentials the keyring can't hold (e.g. an AWS CodeArtifact auth token). Off unless you pass `--allow-exec`.

See `examples/rules/`.

## Security

This is a fun side project that was nearly all written with claude, no guarantees about security are made. It's a local, single-user tool, and the agent is assumed cooperative. Known limitations of the egress control:

- Default rules allow `GET`/`OPTIONS`/`HEAD` to any host, so with defaults on, anything the agent can read can be exfiltrated via GET query strings/headers. For untrusted workloads, run `--no-default-rules` with an explicit allow-list.
- DNS to kube-dns is allowed (`^`) — a residual exfiltration channel the mitm allow-list never sees.
- `--allow-exec` lets a `--rules` file run host shell commands at startup - only enable it for rules files you trust.
- For the `claude` agent, only an allow-list of non-secret `~/.claude/settings.json` keys is copied into the pod (secret-bearing keys like `apiKeyHelper` and unknown `env` vars are dropped).

^ NetworkPolicies can't restrict traffic for pod <-> host where the pod is scheduled.
