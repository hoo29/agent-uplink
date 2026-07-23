"""mitmproxy addon: enforce allow-list rules, inject pre-resolved headers, and
re-sign AWS SigV4 requests with real per-profile credentials.

Receives a JSON rules file mounted into the container. The host process resolves
any `{{keyring:...}}` placeholders before writing this file, so the addon never
touches the user's keyring or YAML.

AWS requests arrive signed with deterministic *dummy* credentials (the agent pod
only ever holds those). After the allow-list authorises the request, the addon
looks up the real credentials for the dummy AKIA, derives the service and region
from the host, strips the bogus signature and re-signs in place with the real
key before forwarding straight to AWS. Real credentials live only in this pod
(mounted from a Secret), never in the agent pod.

Stdlib only — the addon ships as a ConfigMap into the stock mitmproxy image, so
it cannot depend on botocore. SigV4 is implemented from the AWS reference.
"""

import datetime
import hashlib
import hmac
import ipaddress
import json
import logging
import re
from typing import NamedTuple
from urllib.parse import quote, unquote

from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader
from mitmproxy.proxy import layer
from mitmproxy.proxy.layers import TCPLayer

# This addon runs inside the mitmproxy container as its own process, so it logs
# under the module name (not agent-uplink's host-side "agent-uplink" logger).
# Messages keep an "agent-uplink" prefix so they're greppable in mitm's output.
logger = logging.getLogger(__name__)

# AWS SigV4 Authorization header:
#   AWS4-HMAC-SHA256 Credential=AKIA.../20240101/us-east-1/bedrock/aws4_request, ...
_SIGV4_AKIA_RE = re.compile(
    r"AWS4-HMAC-SHA256\s+Credential=([A-Z0-9]+)/", re.IGNORECASE
)
# The dummy-signature headers the agent's SDK set; stripped before re-signing.
_SIGV4_HEADERS_TO_STRIP = (
    "Authorization",
    "X-Amz-Date",
    "X-Amz-Security-Token",
    "X-Amz-Content-Sha256",
)

_UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD"

# Bodies at or below this are buffered; anything larger (or of unknown length)
# is relayed chunk by chunk. Streaming is decided here, per flow, rather than
# with mitmproxy's `stream_large_bodies` option — see `_apply_streaming`.
_STREAM_THRESHOLD = 1024 * 1024

# A signable body this size is logged: SigV4 outside S3 covers the payload hash,
# so the whole body is held in the pod to compute it, and that is worth being
# able to explain. AWS's own per-request limits bound it (~50MB for the largest,
# a direct Lambda code upload); S3, the service with no such ceiling, signs with
# an unsigned payload and streams instead.
_LARGE_SIGNABLE_BODY = 8 * 1024 * 1024

# Headers never included in the signature, lower-cased. Mirrors the AWS SDK
# signers that aws-sigv4-proxy delegates to: the SDK owns `authorization`, while
# `user-agent` / `x-amzn-trace-id` are added or rewritten by hops so AWS excludes
# them. The hop-by-hop headers below are added/rewritten by mitmproxy on the way
# out, so signing them would not match what AWS receives. Everything else on the
# request IS signed — S3 rejects any `x-amz-*` (or content-*) header that is
# present but absent from SignedHeaders ("headers present ... which were not
# signed"), which a fixed minimal signed-header set could not satisfy.
_UNSIGNED_HEADERS = frozenset(
    {
        "authorization",
        "user-agent",
        "x-amzn-trace-id",
        "connection",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "expect",
    }
)

# A region label in an AWS host: us-east-1, eu-west-2, ap-southeast-1,
# us-gov-west-1, etc.
_REGION_RE = re.compile(r"^[a-z]{2}-[a-z]+(-[a-z]+)?-\d+$")
# Hosts whose service label differs from the SigV4 signing name.
_SIGNING_NAME_OVERRIDES = {
    "bedrock-runtime": "bedrock",
    "bedrock-agent-runtime": "bedrock",
}
_AWS_SUFFIX = ".amazonaws.com"


def parse_aws_host(host: str) -> tuple[str, str]:
    """Derive (signing-name, region) from an AWS host.

    Pattern-based, so it handles any region/service rather than depending on a
    frozen endpoint table:

      sts.eu-west-2.amazonaws.com     -> ('sts', 'eu-west-2')
      ssm.eu-west-2.amazonaws.com     -> ('ssm', 'eu-west-2')
      s3.eu-west-2.amazonaws.com      -> ('s3',  'eu-west-2')
      bucket.s3.eu-west-2.amazonaws.com -> ('s3', 'eu-west-2')
      id.execute-api.us-east-1.amazonaws.com -> ('execute-api', 'us-east-1')
      sts.amazonaws.com               -> ('sts', 'us-east-1')   # global endpoint

    Region-less (global) endpoints sign as us-east-1, the aws partition's global
    signing region.
    """
    base = host[: -len(_AWS_SUFFIX)] if host.endswith(_AWS_SUFFIX) else host
    labels = base.split(".")
    region = None
    region_idx = None
    for i, label in enumerate(labels):
        if _REGION_RE.match(label):
            region, region_idx = label, i
            break
    if region is not None and region_idx is not None and region_idx > 0:
        service = labels[region_idx - 1]
    else:
        # Global endpoint (no region label) or a degenerate host: the service is
        # the last label and the request signs as us-east-1.
        service = labels[-1]
        region = region or "us-east-1"
    return _SIGNING_NAME_OVERRIDES.get(service, service), region


def _canonical_uri(path: str, service: str) -> str:
    """Canonical URI for the canonical request.

    S3 uses the path exactly as the client encoded it (single-encoded). Every
    other service re-encodes it (so a wire `%XX` becomes `%25XX`), matching
    botocore's SigV4 behaviour.
    """
    if not path:
        return "/"
    if service == "s3":
        return path
    return quote(path, safe="/")


def _canonical_query(raw_query: str) -> str:
    """Canonical query string: each key/value decoded then RFC3986-encoded once,
    sorted by encoded key then value."""
    if not raw_query:
        return ""
    items = []
    for part in raw_query.split("&"):
        if not part:
            continue
        key, _, value = part.partition("=")
        items.append(
            (quote(unquote(key), safe="-_.~"), quote(unquote(value), safe="-_.~"))
        )
    items.sort()
    return "&".join(f"{k}={v}" for k, v in items)


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_key: str, datestamp: str, region: str, service: str) -> bytes:
    k_date = _hmac(("AWS4" + secret_key).encode("utf-8"), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def _now() -> datetime.datetime:
    # Wrapped so tests can freeze the signing timestamp.
    return datetime.datetime.now(datetime.timezone.utc)


def _collect_signed_headers(req: http.Request, amz_date: str, payload_hash: str,
                            token: str | None) -> dict[str, str]:
    """All headers that go into the signature, lower-cased name -> trimmed value.

    Signs every header on the request except the `_UNSIGNED_HEADERS` ignore-list,
    matching the AWS SDK signers aws-sigv4-proxy delegates to. S3 enforces that
    any header it receives appears in SignedHeaders, so a fixed minimal set is
    not enough — `content-type`, `x-amz-*` extensions, `range`, etc. must all be
    signed. The synthetic host / x-amz-date / x-amz-content-sha256 / security
    token are set before collection so they're included too.
    """
    signed: dict[str, str] = {}
    for name, value in req.headers.items(multi=True):
        lname = name.lower()
        if lname in _UNSIGNED_HEADERS:
            continue
        # Trim and collapse internal runs of whitespace, per the SigV4 spec.
        trimmed = " ".join(value.split())
        if lname in signed:
            signed[lname] = f"{signed[lname]},{trimmed}"
        else:
            signed[lname] = trimmed
    # `host` is not a normal header field on the request object; add it explicitly.
    signed["host"] = req.host
    signed["x-amz-date"] = amz_date
    signed["x-amz-content-sha256"] = payload_hash
    if token:
        signed["x-amz-security-token"] = token
    return signed


def sigv4_sign(
    req: http.Request,
    creds: dict,
    service: str,
    region: str,
    payload_hash: str,
) -> None:
    """Sign `req` in place with SigV4, setting X-Amz-Date, X-Amz-Content-Sha256,
    the session token (when present) and the Authorization header. Every header
    present on the request (minus the `_UNSIGNED_HEADERS` ignore-list) is signed,
    so S3 never rejects a present-but-unsigned header.
    """
    access_key = creds["access_key_id"]
    secret_key = creds["secret_access_key"]
    token = creds.get("session_token")

    now = _now()
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    raw_path, _, raw_query = (req.path or "/").partition("?")
    canonical_uri = _canonical_uri(raw_path, service)
    canonical_qs = _canonical_query(raw_query)

    req.headers["X-Amz-Date"] = amz_date
    req.headers["X-Amz-Content-Sha256"] = payload_hash
    if token:
        req.headers["X-Amz-Security-Token"] = token

    signed = _collect_signed_headers(req, amz_date, payload_hash, token)
    signed_headers = ";".join(sorted(signed))
    canonical_headers = "".join(f"{k}:{signed[k]}\n" for k in sorted(signed))

    canonical_request = "\n".join(
        [
            req.method,
            canonical_uri,
            canonical_qs,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(
        _signing_key(secret_key, datestamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    req.headers["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )


class CompiledRule(NamedTuple):
    """A rule with its regexes pre-compiled, kept as named fields so the match
    loop reads by name instead of by tuple index."""

    hosts: list  # list[re.Pattern]; request host matches if ANY fullmatches
    methods: set
    paths: list
    inject_headers: dict
    name: str


class CompiledL4Rule(NamedTuple):
    """An l4_forward rule: match the connection's CONNECT target by hostname
    regex and/or literal-IP CIDR, and if matched tunnel it raw (no TLS
    termination, no allow-list, no injection)."""

    hosts: list  # list[re.Pattern]; CONNECT hostname matches if ANY fullmatches
    cidrs: list  # list[ipaddress.IPv4Network | IPv6Network]
    name: str


def _declared_body_size(msg) -> int | None:
    """The body size from `Content-Length`, or None when it is absent or
    unparseable (chunked transfers, which have no declared size)."""
    raw = msg.headers.get("Content-Length")
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _apply_streaming(flow: http.HTTPFlow, msg) -> None:
    """Decide, before the headers are flushed, whether this body streams.

    mitmproxy's own `stream_large_bodies` option cannot be used here. It reruns
    its check as body bytes accumulate — after this hook has returned — and
    flips a flow to streaming the moment the buffered body passes the limit
    (`proxy/layers/http/__init__.py`, `check_body_size`). That silently undid the
    non-streaming choice AWS signing depends on: the dummy signature had already
    been stripped, the stripped headers went upstream the instant streaming
    began, and the re-signing in the `request` hook landed after they were on the
    wire — so a non-S3 AWS request with a body over the limit reached AWS with no
    Authorization header at all, while the log claimed it was signed.

    Deciding per flow here keeps that override switched off (the option is left
    unset, so `check_body_size` returns immediately) and makes the choice final.
    """
    size = _declared_body_size(msg)
    msg.stream = size is None or size > _STREAM_THRESHOLD


class RuleEnforcer:
    def __init__(self) -> None:
        self._compiled: list[CompiledRule] = []
        self._l4_rules: list[CompiledL4Rule] = []
        # dummy AKIA -> {access_key_id, secret_access_key, session_token?}
        self._aws_creds: dict[str, dict] = {}

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="rules_file",
            typespec=str,
            default="",
            help="Path to JSON rules file (resolved by agent-uplink host)",
        )
        loader.add_option(
            name="aws_creds_file",
            typespec=str,
            default="",
            help="Path to JSON map: dummy AKIA -> real AWS credentials",
        )

    def configure(self, updates) -> None:
        if "rules_file" in updates and ctx.options.rules_file:
            with open(ctx.options.rules_file) as f:
                data = json.load(f)
            self._compiled = [
                CompiledRule(
                    hosts=[re.compile(h) for h in (r.get("hosts") or [])],
                    methods=set(r.get("methods") or []),
                    paths=[re.compile(p) for p in (r.get("paths") or [])],
                    inject_headers=r.get("inject", {}).get("headers", {}),
                    name=r.get("name", "<unnamed>"),
                )
                for r in data["rules"]
                if not r.get("l4_forward")
            ]
            self._l4_rules = [
                CompiledL4Rule(
                    hosts=[re.compile(h) for h in (r.get("hosts") or [])],
                    cidrs=[
                        ipaddress.ip_network(c) for c in (r.get("cidrs") or [])
                    ],
                    name=r.get("name", "<unnamed>"),
                )
                for r in data["rules"]
                if r.get("l4_forward")
            ]
            logger.info(
                f"agent-uplink: loaded {len(self._compiled)} rules, "
                f"{len(self._l4_rules)} l4_forward rules"
            )
        if "aws_creds_file" in updates and ctx.options.aws_creds_file:
            with open(ctx.options.aws_creds_file) as f:
                self._aws_creds = json.load(f)
            logger.info(
                f"agent-uplink: loaded {len(self._aws_creds)} AWS signing identities"
            )

    def _match_l4(self, target_host: str) -> "str | None":
        """Return the name of the first l4_forward rule matching the CONNECT
        target, else None. `target_host` is the literal host the client put in
        the request (the CONNECT authority) — NOT a DNS-resolved address. A
        literal IP is matched against `cidrs`; anything else against `hosts`.
        """
        literal_ip = None
        try:
            literal_ip = ipaddress.ip_address(target_host)
        except ValueError:
            pass
        for rule in self._l4_rules:
            if literal_ip is not None:
                if any(literal_ip in net for net in rule.cidrs):
                    return rule.name
            elif any(h.fullmatch(target_host) for h in rule.hosts):
                return rule.name
        return None

    def next_layer(self, nextlayer: layer.NextLayer) -> None:
        """Before any TLS is terminated, decide whether this connection should be
        tunnelled raw. mitm runs as an explicit HTTP proxy, so the CONNECT target
        is in context.server.address — the host/IP the client asked for, before
        DNS resolution. On an l4_forward match we install a raw TCPLayer: mitm
        relays bytes without decrypting, so the agent's TLS (incl. any client
        cert / mTLS) goes end-to-end to the upstream. Such connections bypass the
        allow-list and header injection entirely.

        `ignore=True` relays without constructing a TCPFlow. A recording
        TCPLayer appends every relayed chunk to `flow.messages` and mitmproxy
        holds that flow for the rest of the process, so a tunnelled transfer
        costs its full size in RAM permanently — 1.5GB streamed pins 1.5GB, and
        the next transfer adds its own. The recorded bytes are TLS ciphertext
        here in any case, so there is nothing to inspect. It also skips a
        per-chunk hook dispatch (~24k round trips per GB), which is most of the
        relay's CPU cost.
        """
        if nextlayer.layer is not None:
            return  # another layer already decided
        address = nextlayer.context.server.address
        if not address:
            return
        target_host = address[0]
        matched = self._match_l4(target_host)
        if matched is not None:
            logger.info(
                f"agent-uplink L4-FORWARD [{matched}] {target_host}:{address[1]} "
                "(raw TCP tunnel, TLS end-to-end, allow-list bypassed)"
            )
            nextlayer.layer = TCPLayer(nextlayer.context, ignore=True)

    def _match_rule(self, req: http.Request):
        """Return (name, inject_headers) for the first allow rule that matches,
        else None. Matching is host (any of `hosts` fullmatch) + optional method
        + optional path. First match wins; rules are pre-ordered by layer.
        """
        for rule in self._compiled:
            if not any(h.fullmatch(req.host) for h in rule.hosts):
                continue
            if rule.methods and req.method not in rule.methods:
                continue
            if rule.paths and not any(p.fullmatch(req.path) for p in rule.paths):
                continue
            return rule.name, rule.inject_headers
        return None

    def _signable_akia(self, req: http.Request) -> str | None:
        """The dummy AKIA from an AWS-signed request we hold real creds for, else
        None. Only AWS hosts carrying an AWS4-HMAC-SHA256 signature qualify; the
        allow-list must already have authorised the request."""
        if not req.host.endswith(_AWS_SUFFIX):
            return None
        m = _SIGV4_AKIA_RE.match(req.headers.get("Authorization", ""))
        if not m:
            return None
        return m.group(1) if m.group(1) in self._aws_creds else None

    def _begin_sigv4(self, flow: http.HTTPFlow, akia: str, rule_name: str) -> None:
        """Strip the dummy signature, then either sign now (S3, which can use an
        unsigned payload so large objects keep streaming) or defer to the request
        hook (every other service needs the real body hash, so buffer the body).
        """
        req = flow.request
        service, region = parse_aws_host(req.host)
        for h in _SIGV4_HEADERS_TO_STRIP:
            req.headers.pop(h, None)

        if service == "s3":
            sigv4_sign(req, self._aws_creds[akia], service, region, _UNSIGNED_PAYLOAD)
            logger.info(
                f"agent-uplink SIGV4 [{rule_name}/{akia}] {req.method} "
                f"{req.host}{req.path} ({service}/{region}, unsigned-payload)"
            )
            return

        declared = _declared_body_size(req)
        if declared is not None and declared > _LARGE_SIGNABLE_BODY:
            logger.warning(
                f"agent-uplink sigv4 buffering {declared}B to sign {req.method} "
                f"{req.host}{req.path} ({service}) — the payload hash is signed, "
                "so the body cannot stream"
            )

        # Buffer the body so the request hook can hash it, and keep the headers
        # pending until then so the real signature goes out with them.
        flow.request.stream = False
        flow.metadata["aws_sign"] = {
            "akia": akia,
            "service": service,
            "region": region,
            "rule": rule_name,
        }

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # Enforce + inject at headers time, not in the `request` hook. A streamed
        # request has its headers flushed upstream as soon as they arrive, with
        # the body behind them, so the `request` hook is too late to change a
        # header. AWS signing that needs the body keeps the flow non-streaming
        # (see _begin_sigv4), which holds the headers back until `request`.
        req = flow.request
        matched = self._match_rule(req)
        if matched is None:
            logger.warning(f"agent-uplink DENY {req.method} {req.host}{req.path}")
            flow.response = http.Response.make(
                403,
                b"agent-uplink: request not permitted by rules\n",
                {"Content-Type": "text/plain"},
            )
            return
        _apply_streaming(flow, req)
        name, inject_headers = matched
        # A matched AWS request signed with a known dummy AKIA is re-signed with
        # real credentials. inject.headers and re-signing are mutually exclusive
        # on such a request: the signer overwrites Authorization, so any injected
        # header would be discarded — we skip them.
        akia = self._signable_akia(req)
        if akia is not None:
            self._begin_sigv4(flow, akia, name)
            return
        if req.host.endswith(_AWS_SUFFIX) and _SIGV4_AKIA_RE.match(
            req.headers.get("Authorization", "")
        ):
            # Authorised AWS host signed with an AKIA we hold no creds for. Leave
            # it untouched; it will fail at AWS with the dummy signature.
            logger.warning(
                f"agent-uplink sigv4 no creds host={req.host} "
                f"(request allowed but not re-signed)"
            )
        for k, v in inject_headers.items():
            req.headers[k] = v
        logger.info(f"agent-uplink ALLOW [{name}] {req.method} {req.host}{req.path}")

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        # Nothing in this addon inspects response bodies, so a large download (a
        # git pack, an image layer, an S3 object) is relayed chunk by chunk
        # instead of being held in the pod.
        if flow.response is not None:
            _apply_streaming(flow, flow.response)

    def request(self, flow: http.HTTPFlow) -> None:
        # Second hook, reached only for AWS flows _begin_sigv4 deferred: the body
        # is fully buffered now, so hash it and sign with the real credentials.
        meta = flow.metadata.get("aws_sign")
        if not meta:
            return
        req = flow.request
        payload_hash = hashlib.sha256(req.raw_content or b"").hexdigest()
        sigv4_sign(
            req, self._aws_creds[meta["akia"]], meta["service"], meta["region"],
            payload_hash,
        )
        logger.info(
            f"agent-uplink SIGV4 [{meta['rule']}/{meta['akia']}] {req.method} "
            f"{req.host}{req.path} ({meta['service']}/{meta['region']})"
        )


addons = [RuleEnforcer()]
