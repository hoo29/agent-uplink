"""Concurrent load driver: fire N simultaneous large POSTs at the fake Bedrock
host THROUGH the mitm proxy, mimicking many subagents streaming at once.

Each request sends REQ_MB of body (large context) and streams the response back
chunk by chunk (so the proxy holds many concurrent streamed flows at once).
Reports per-request status, byte counts, latency, and any failures.

Usage:
  driver.py <concurrency> <rounds>
Env:
  PROXY      e.g. http://127.0.0.1:8080 (mitm)
  REQ_MB     request body size per call (default 4)
  CA         CA bundle to trust mitm's cert (mitm confdir CA)
"""

import concurrent.futures as cf
import os
import sys
import time

import requests

PROXY = os.environ.get("PROXY", "http://127.0.0.1:8080")
REQ_MB = float(os.environ.get("REQ_MB", "4"))
CA = os.environ.get("CA")  # path to mitmproxy-ca-cert.pem
URL = "https://bedrock-runtime.us-east-1.amazonaws.com/model/foo/converse-stream"

CONC = int(sys.argv[1]) if len(sys.argv) > 1 else 8
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 1

proxies = {"http": PROXY, "https": PROXY}
body = b"x" * int(REQ_MB * 1024 * 1024)


def one(i):
    t0 = time.monotonic()
    try:
        r = requests.post(
            URL, data=body, proxies=proxies, verify=CA or False,
            stream=True, timeout=120,
            headers={"Content-Type": "application/json"},
        )
        recv = 0
        for chunk in r.iter_content(65536):
            recv += len(chunk)
        dt = time.monotonic() - t0
        return (i, r.status_code, r.headers.get("x-seen-reqbytes"),
                r.headers.get("x-seen-auth"), recv, round(dt, 2), None)
    except Exception as e:  # noqa: BLE001
        return (i, None, None, None, 0, round(time.monotonic() - t0, 2), repr(e))


def main():
    print(f"driver: conc={CONC} rounds={ROUNDS} req={REQ_MB}MB proxy={PROXY}")
    total_fail = 0
    for rnd in range(ROUNDS):
        t0 = time.monotonic()
        with cf.ThreadPoolExecutor(max_workers=CONC) as ex:
            results = list(ex.map(one, range(CONC)))
        for i, code, reqb, auth, recv, dt, err in results:
            if err:
                total_fail += 1
                print(f"  [r{rnd} #{i}] FAIL {dt}s {err}")
            else:
                print(f"  [r{rnd} #{i}] {code} reqbytes={reqb} auth={auth} "
                      f"recv={recv} {dt}s")
        print(f"  round {rnd}: {round(time.monotonic()-t0,2)}s wall")
    print(f"DONE failures={total_fail}/{CONC*ROUNDS}")
    sys.exit(1 if total_fail else 0)


if __name__ == "__main__":
    main()
