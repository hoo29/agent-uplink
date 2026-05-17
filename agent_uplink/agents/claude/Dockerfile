FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
  aggregate \
  ca-certificates \
  coreutils \
  curl \
  dnsutils \
  file \
  fzf \
  git \
  gnupg2 \
  iputils-ping \
  jq \
  less \
  net-tools \
  procps \
  python3 \
  unzip \
  util-linux \
  vim \
  wget \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
  && unzip awscliv2.zip \
  && ./aws/install \
  && rm -rf ./aws*

ARG USER_UID=1000
ARG USER_GID=1000
ARG USERNAME=huw
RUN if [ "${USER_GID}" != "1000" ]; then groupadd --gid "${USER_GID}" "${USERNAME}"; fi \
  && if [ "${USER_UID}" != "1000" ]; then \
       useradd --uid "${USER_UID}" --gid "${USER_GID}" --shell /bin/bash --create-home "${USERNAME}"; \
     else \
       usermod --login "${USERNAME}" --move-home --home "/home/${USERNAME}" "$(getent passwd 1000 | cut -d: -f1)"; \
     fi
ARG CACHE_BUST=0
RUN echo "cache-bust=${CACHE_BUST}" \
  && su - ${USERNAME} -c "curl -fsSL https://claude.ai/install.sh | bash"

COPY certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
RUN update-ca-certificates

USER ${USERNAME}

ENV SHELL=/bin/bash
ENV EDITOR=vim
ENV VISUAL=vim
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
ENV AWS_CA_BUNDLE=/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
ENV PATH="$PATH:/home/${USERNAME}/.local/bin"
ENV USERNAME=${USERNAME}
