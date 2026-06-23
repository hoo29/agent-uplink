"""Test-only mitm addon: after the real filter.py has matched/injected, rewrite
the upstream destination to the local sink. This keeps filter.py unmodified and
its host-matching (bedrock-runtime.<region>.amazonaws.com) intact, while routing
the actual connection to 127.0.0.1 so nothing reaches AWS.

Loaded AFTER filter.py so it runs second in the requestheaders hook chain.
Order matters: filter.py must inject/deny first; we only redirect survivors.
Done in requestheaders (not request) because the bearer path streams large
bodies: mitm flushes headers + opens the upstream connection before the request
body arrives, so a later hook can't change the destination.
"""

import os

SINK_HOST = "127.0.0.1"
SINK_PORT = int(os.environ.get("SINK_PORT", "8443"))


def requestheaders(flow):
    # Only redirect requests filter.py allowed (it sets a 403 response on deny).
    if flow.response is not None:
        return
    flow.request.host = SINK_HOST
    flow.request.port = SINK_PORT
    flow.request.scheme = "https"
