"""mitmproxy addon: enforce allow-list rules, inject pre-resolved headers,
and route AWS SigV4 requests to per-profile aws-sigv4-proxy sidecars.

Receives a JSON rules file mounted into the container. The host process
resolves any `{{keyring:...}}` placeholders before writing this file, so the
addon never touches the user's keyring or YAML.
"""

import json
import logging
import re

from mitmproxy import ctx, http
from mitmproxy.addonmanager import Loader

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


class RuleEnforcer:
    def __init__(self) -> None:
        self._compiled: list[tuple] = []
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
            (
                re.compile(r["host"]),
                set(r.get("methods") or []),
                [re.compile(p) for p in (r.get("paths") or [])],
                r.get("inject", {}).get("headers", {}),
                r.get("name", "<unnamed>"),
            )
            for r in rules
        ]
        self._sigv4_routes = data.get("aws_sigv4_routes") or {}
        logger.info(
            f"agent-uplink: loaded {len(self._compiled)} rules"
            f", {len(self._sigv4_routes)} sigv4 routes"
        )

    def _try_sigv4_route(self, flow: http.HTTPFlow) -> bool:
        """Reroute AWS-signed requests to the matching sigv4-proxy sidecar.

        Returns True if the request was rerouted (caller should skip the
        normal allow-list check).
        """
        if not self._sigv4_routes:
            return False
        req = flow.request
        if not req.host.endswith(".amazonaws.com"):
            return False
        auth = req.headers.get("Authorization", "")
        m = _SIGV4_AKIA_RE.match(auth)
        if not m:
            return False
        akia = m.group(1)
        route = self._sigv4_routes.get(akia)
        if route is None:
            logger.warning(
                f"agent-uplink DENY [sigv4-no-route] {req.method} "
                f"{req.host}{req.path} akia={akia}"
            )
            flow.response = http.Response.make(
                403,
                b"agent-uplink: no sigv4-proxy route for this AKIA\n",
                {"Content-Type": "text/plain"},
            )
            return True

        original_host = req.host
        for h in _SIGV4_HEADERS_TO_STRIP:
            req.headers.pop(h, None)
        req.scheme = "http"
        req.host = route["upstream_host"]
        req.port = int(route["upstream_port"])
        # sigv4-proxy uses the Host header to pick the AWS service/region.
        req.headers["Host"] = original_host
        logger.info(
            f"agent-uplink SIGV4 [{akia}] {req.method} "
            f"{original_host}{req.path} → {route['upstream_host']}"
        )
        return True

    def request(self, flow: http.HTTPFlow) -> None:
        if self._try_sigv4_route(flow):
            return
        req = flow.request
        for host_re, methods, path_res, inject_headers, name in self._compiled:
            if not host_re.fullmatch(req.host):
                continue
            if methods and req.method not in methods:
                continue
            if path_res and not any(p.fullmatch(req.path) for p in path_res):
                continue
            for k, v in inject_headers.items():
                req.headers[k] = v
            logger.info(
                f"agent-uplink ALLOW [{name}] {req.method} {req.host}{req.path}")
            return
        logger.warning(f"agent-uplink DENY {req.method} {req.host}{req.path}")
        flow.response = http.Response.make(
            403,
            b"agent-uplink: request not permitted by rules\n",
            {"Content-Type": "text/plain"},
        )


addons = [RuleEnforcer()]
