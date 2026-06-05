# Single image used by the integration tests for three roles:
#   * agent-probe  — a stand-in for the real agent pod (labelled app=agent) that
#     we exec curl/nc/dig into to observe egress + injection behaviour.
#   * echo-upstream — a tiny HTTP(S) server that reflects the request headers it
#     received, so we can assert what mitm forwarded/injected/stripped.
#   * dockerd-target — proves an in-pod dockerd runs under privileged + the
#     default (runc) runtime, i.e. without kata installed.
#
# Built FROM docker:dind so the same image can host the in-pod dockerd smoke test.
# The mitmproxy CA (public cert only) is baked in so curl trusts mitm's TLS
# interception, exactly like the real agent image does.
FROM docker:27-dind

RUN apk add --no-cache \
    curl \
    bind-tools \
    openssl \
    python3 \
    socat \
    netcat-openbsd \
    ca-certificates

# Trust mitm's CA so `curl https://...` validates the intercepted TLS without -k.
COPY mitm-ca.pem /usr/local/share/ca-certificates/mitm-ca.crt
RUN update-ca-certificates

COPY echo.py /echo.py
