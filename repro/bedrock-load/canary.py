"""Event-loop head-of-line probe. While heavy streams saturate mitm, fire a
tiny request every 0.5s through the SAME proxy and record its latency. A single
asyncio event loop that's busy pumping large streams will delay these tiny
requests; the spread between min and max canary latency is the hang the agent
sees when many subagents stream at once.

Usage: canary.py <seconds>
Env: PROXY, CA (same as driver.py)
"""

import os
import sys
import time

import requests

PROXY = os.environ.get("PROXY", "http://127.0.0.1:8080")
CA = os.environ.get("CA")
DURATION = float(sys.argv[1]) if len(sys.argv) > 1 else 10
URL = "https://bedrock-runtime.us-east-1.amazonaws.com/ping"
proxies = {"http": PROXY, "https": PROXY}

lat = []
end = time.monotonic() + DURATION
while time.monotonic() < end:
    t0 = time.monotonic()
    try:
        r = requests.post(URL, data=b"ping", proxies=proxies, verify=CA or False,
                          timeout=30, headers={"x-canary": "1"})
        # drain tiny response
        _ = r.content
        lat.append(time.monotonic() - t0)
    except Exception as e:  # noqa: BLE001
        lat.append(-1.0)
        print(f"  canary FAIL {repr(e)[:80]}", flush=True)
    time.sleep(0.5)

ok = [x for x in lat if x >= 0]
if ok:
    ok.sort()
    print(f"canary: n={len(lat)} fail={len(lat)-len(ok)} "
          f"min={ok[0]*1000:.0f}ms p50={ok[len(ok)//2]*1000:.0f}ms "
          f"max={ok[-1]*1000:.0f}ms")
else:
    print(f"canary: n={len(lat)} ALL FAILED")
