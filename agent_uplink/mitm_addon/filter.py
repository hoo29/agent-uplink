"""mitmproxy addon: enforce allow-list rules, inject pre-resolved headers,
and route AWS SigV4 requests to per-profile aws-sigv4-proxy sidecars.

Receives a JSON rules file mounted into the container. The host process
resolves any `{{keyring:...}}` placeholders before writing this file, so the
addon never touches the user's keyring or YAML.
"""

import json
import logging
import re
from typing import NamedTuple

from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader

# This addon runs inside the mitmproxy container as its own process, so it logs
# under the module name (not agent-uplink's host-side "agent-uplink" logger).
# Messages keep an "agent-uplink" prefix so they're greppable in mitm's output.
logger = logging.getLogger(__name__)

# AWS SigV4 Authorization header:
#   AWS4-HMAC-SHA256 Credential=AKIA.../20240101/us-east-1/bedrock/aws4_request, ...
_SIGV4_AKIA_RE = re.compile(
    r"AWS4-HMAC-SHA256\s+Credential=([A-Z0-9]+)/", re.IGNORECASE
)
_SIGV4_HEADERS_TO_STRIP = (
    "Authorization",
    "X-Amz-Date",
    "X-Amz-Security-Token",
    "X-Amz-Content-Sha256",
)


class CompiledRule(NamedTuple):
    """A rule with its regexes pre-compiled, kept as named fields so the match
    loop reads by name instead of by tuple index."""

    host: re.Pattern
    methods: set
    paths: list
    inject_headers: dict
    name: str


class RuleEnforcer:
    def __init__(self) -> None:
        self._compiled: list[CompiledRule] = []
        self._sigv4_routes: dict[str, dict] = {}

    def load(self, loader: Loader) -> None:
        loader.add_option(
            name="rules_file",
            typespec=str,
            default="",
            help="Path to JSON rules file (resolved by agent-uplink host)",
        )

    def configure(self, updates) -> None:
        if "rules_file" not in updates or not ctx.options.rules_file:
            return
        with open(ctx.options.rules_file) as f:
            data = json.load(f)
        rules = data["rules"]
        self._compiled = [
            CompiledRule(
                host=re.compile(r["host"]),
                methods=set(r.get("methods") or []),
                paths=[re.compile(p) for p in (r.get("paths") or [])],
                inject_headers=r.get("inject", {}).get("headers", {}),
                name=r.get("name", "<unnamed>"),
            )
            for r in rules
        ]
        self._sigv4_routes = data.get("aws_sigv4_routes") or {}
        logger.info(
            f"agent-uplink: loaded {len(self._compiled)} rules"
            f", {len(self._sigv4_routes)} sigv4 routes"
        )

    def _match_rule(self, req: http.Request):
        """Return (name, inject_headers) for the first allow rule that matches,
        else None. Matching is host (fullmatch) + optional method + optional
        path. First match wins; rules are pre-ordered by the host (layer order).
        """
        for rule in self._compiled:
            if not rule.host.fullmatch(req.host):
                continue
            if rule.methods and req.method not in rule.methods:
                continue
            if rule.paths and not any(p.fullmatch(req.path) for p in rule.paths):
                continue
            return rule.name, rule.inject_headers
        return None

    def _reroute_sigv4(self, req: http.Request, rule_name: str) -> bool:
        """If `req` is an AWS-signed request we have a sidecar route for, strip
        its (bogus) signature and reroute it to the aws-sigv4-proxy sidecar to be
        re-signed with the real credentials. Returns True if rerouted.

        Only called *after* an allow rule has authorised the AWS host — the
        allow-list, not the mere presence of an AWS signature, is what permits an
        AWS request (so a profile's full IAM scope is not implicitly reachable).
        """
        if not self._sigv4_routes:
            return False
        if not req.host.endswith(".amazonaws.com"):
            return False
        m = _SIGV4_AKIA_RE.match(req.headers.get("Authorization", ""))
        if not m:
            return False
        route = self._sigv4_routes.get(m.group(1))
        if route is None:
            # Authorised AWS host signed with an AKIA we have no sidecar for.
            # Leave it unrerouted; it will fail at AWS with the dummy signature.
            logger.warning(
                f"agent-uplink sigv4 no route akia={m.group(1)} host={req.host}"
            )
            return False
        original_host = req.host
        for h in _SIGV4_HEADERS_TO_STRIP:
            req.headers.pop(h, None)
        # In-namespace, mitm→sidecar-only leg (NetworkPolicy), so plaintext HTTP.
        req.scheme = "http"
        req.host = route["upstream_host"]
        req.port = int(route["upstream_port"])
        # sigv4-proxy uses the Host header to pick the AWS service/region.
        req.headers["Host"] = original_host
        logger.info(
            f"agent-uplink SIGV4 [{rule_name}/{m.group(1)}] {req.method} "
            f"{original_host}{req.path} → {route['upstream_host']}"
        )
        return True

    def requestheaders(self, flow: http.HTTPFlow) -> None:
        # Enforce + inject at headers time, not in the `request` hook. With
        # `stream_large_bodies` set, mitmproxy flushes the request headers
        # upstream as soon as they arrive and streams the body behind them, so
        # the `request` hook (which fires only after the full body is received)
        # is too late to overwrite Authorization. The addon never reads the
        # body, so headers-time enforcement loses nothing.
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
        name, inject_headers = matched
        # A matched AWS request signed with a dummy AKIA is rerouted to the
        # re-signing sidecar. inject.headers and SigV4 rerouting are mutually
        # exclusive on *.amazonaws.com: a rerouted request is re-signed by the
        # sidecar, so any inject.headers on it would be discarded — we skip them.
        if self._reroute_sigv4(req, name):
            return
        for k, v in inject_headers.items():
            req.headers[k] = v
        logger.info(f"agent-uplink ALLOW [{name}] {req.method} {req.host}{req.path}")


addons = [RuleEnforcer()]
