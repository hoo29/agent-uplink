"""Minimal request-reflecting HTTP(S) server for the integration tests.

Listens on :8080 (HTTP) and :8443 (HTTPS, self-signed cert generated at start).
Every request gets a 200 whose JSON body reflects the method, path and (lower
-cased) headers the server actually received. The tests read that body back out
of the agent pod's `curl` output to assert what mitm forwarded — e.g. that an
injected Authorization header arrived, or that a SigV4 signature was stripped
and the original Host preserved.
"""

import http.server
import json
import ssl
import subprocess
import threading


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self):
        body = json.dumps(
            {
                "method": self.command,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _respond

    def log_message(self, *args):  # silence per-request stderr noise
        pass


def serve_http(port: int) -> None:
    http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


def serve_https(port: int) -> None:
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", "/tmp/key.pem", "-out", "/tmp/cert.pem",
            "-days", "2", "-nodes", "-subj", "/CN=echo",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
    httpd = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


if __name__ == "__main__":
    threading.Thread(target=serve_https, args=(8443,), daemon=True).start()
    serve_http(8080)
