"""mitmproxy addon: enforce allow-list rules and inject pre-resolved headers.

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


class RuleEnforcer:
    def __init__(self) -> None:
        self._compiled: list[tuple] = []

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
            rules = json.load(f)["rules"]
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
        logger.info(f"agent-uplink: loaded {len(self._compiled)} rules")

    def request(self, flow: http.HTTPFlow) -> None:
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
