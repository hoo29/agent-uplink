"""Fake bedrock-runtime upstream: a TLS server that streams a large SSE-style
body, mimicking a Converse/converse-stream response. Stands in for AWS so no
request leaves the box and nothing is billed.

Reads the request body fully (so large request payloads are exercised end to
end), then streams `RESP_MB` of chunked output back with a small inter-chunk
delay to imitate token streaming.
"""

import os
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RESP_MB = float(os.environ.get("SINK_RESP_MB", "8"))
CHUNK = b"x" * 16384
CHUNK_DELAY_S = float(os.environ.get("SINK_CHUNK_DELAY_S", "0.001"))
PORT = int(os.environ.get("SINK_PORT", "8443"))
CERT = sys.argv[1]
KEY = sys.argv[2]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # silence per-request logging
        pass

    def _drain_body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        remaining = n
        while remaining > 0:
            buf = self.rfile.read(min(remaining, 65536))
            if not buf:
                break
            remaining -= len(buf)
        return n

    def do_POST(self):
        body_len = self._drain_body()
        auth = self.headers.get("Authorization", "<none>")
        if self.path == "/ping":  # canary: tiny immediate response
            self.send_response(200)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"pong")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.amazon.eventstream")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("x-seen-auth", auth[:32])
        self.send_header("x-seen-reqbytes", str(body_len))
        self.end_headers()
        sent = 0
        target = int(RESP_MB * 1024 * 1024)
        while sent < target:
            data = CHUNK
            self.wfile.write(b"%x\r\n" % len(data))
            self.wfile.write(data)
            self.wfile.write(b"\r\n")
            sent += len(data)
            if CHUNK_DELAY_S:
                time.sleep(CHUNK_DELAY_S)
        self.wfile.write(b"0\r\n\r\n")

    do_GET = do_POST


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
httpd = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
print(f"sink: https://127.0.0.1:{PORT}  resp={RESP_MB}MB delay={CHUNK_DELAY_S}s", flush=True)
httpd.serve_forever()
