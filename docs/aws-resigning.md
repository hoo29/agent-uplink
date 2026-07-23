# AWS SigV4 re-signing

When one or more `--aws-profiles` are supplied (directly or via an agent's `discover_aws_profiles()` hook), a Secret
`agent-aws-creds` is created with dummy values: a deterministic dummy AKIA per profile (`AKIA` + first 16 hex chars of
`sha256(profile)`) plus a fixed dummy secret. The container's AWS SDK signs requests with these fake creds; the resulting
signature is bogus and never reaches AWS.

The allow-list is checked first, on the original AWS host. Only if a rule permits the request does the addon re-sign it: for a
`*.amazonaws.com` request whose `Authorization` header is `AWS4-HMAC-SHA256`, it extracts the AKIA from the `Credential=` field,
looks it up in the real-credentials map (the `aws-sigv4-creds` Secret mounted into the mitm pod), derives the service and region
from the host (a pattern parse — `service.region.amazonaws.com`, with global/region-less hosts signing as `us-east-1`; not a
frozen endpoint table), strips the dummy `Authorization` / `X-Amz-Date` / `X-Amz-Security-Token` / `X-Amz-Content-Sha256`
headers, and re-signs with the real credentials before forwarding straight to AWS. The original `Host` is preserved. (Re-signing
and `inject.headers` are mutually exclusive on an AWS host — the re-signer overwrites `Authorization`, so injected headers would
be discarded.)

S3 is signed with `x-amz-content-sha256: UNSIGNED-PAYLOAD` at headers time so large objects keep streaming; every other service
buffers the body and signs the real SHA256 payload hash (AWS API bodies are small). The SigV4 implementation is stdlib-only (the
addon ships as a ConfigMap into the stock mitmproxy image, so it can't use botocore).

That buffering is why the addon, not mitmproxy, decides which bodies stream. mitmproxy's `stream_large_bodies` option reruns its
check as body bytes arrive — after `requestheaders` has returned — and switches a flow to streaming once the buffered body passes
the limit, which breaks re-signing: the stripped dummy headers go upstream the moment streaming begins, and the re-signing in the
`request` hook lands after they are on the wire, so a non-S3 body over the limit reaches AWS with no `Authorization` header while
the log claims success. The option is therefore left unset and `_apply_streaming` decides per flow, before the headers are
flushed: bodies over 1MB or of unknown length stream, everything else buffers, and a flow awaiting SigV4 always buffers. A
signable body over 8MB is logged, since it is held in the pod whole.

So an AWS host is reachable only if an allow rule matches it (e.g. a rule with `hosts: ['s3\.eu-west-2\.amazonaws\.com']`); the
mere presence of an AWS signature grants nothing. A request to `*.amazonaws.com` that no rule allows returns `403`. A matched AWS
host signed with an unknown AKIA is forwarded unchanged (and fails at AWS with the dummy signature); a non-`AWS4-HMAC-SHA256`
request to a matched host is handled normally (e.g. anonymous `GET`).

Security note: re-signing uses the real profile credentials and is not scoped to a single service, so any allowed AWS request
runs with that profile's full IAM permissions. Scope both the profile you pass and the host rules you write — don't pass broad
admin profiles.

Real AWS credentials are obtained on the host via `aws configure export-credentials` (with an `aws sso login` fallback),
collected into a single JSON map (dummy AKIA → `{access_key_id, secret_access_key, session_token?}`), and wrapped in one K8s
Secret (`aws-sigv4-creds`) mounted read-only into the mitm pod only. The agent pod never sees it; `mitm-policy`'s unrestricted
egress lets mitm reach the real AWS endpoints directly, and `agent-egress` confines the agent to mitm so it can't reach AWS
itself.
