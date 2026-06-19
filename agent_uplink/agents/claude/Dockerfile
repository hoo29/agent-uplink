FROM ubuntu:24.04

# Prerequisites for the keyring/repo setup below (the base image has neither).
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates curl gnupg2 \
  && rm -rf /var/lib/apt/lists/*

RUN install -m 0755 -d /etc/apt/keyrings \
  && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc \
  && chmod a+r /etc/apt/keyrings/docker.asc \
  && . /etc/os-release \
  && printf "Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.asc\n" \
    "${UBUNTU_CODENAME:-$VERSION_CODENAME}" "$(dpkg --print-architecture)" \
  > /etc/apt/sources.list.d/docker.sources \
  && curl -fsSL https://get.opentofu.org/opentofu.gpg -o /etc/apt/keyrings/opentofu.gpg \
  && curl -fsSL https://packages.opentofu.org/opentofu/tofu/gpgkey \
    | gpg --no-tty --batch --dearmor -o /etc/apt/keyrings/opentofu-repo.gpg \
  && chmod a+r /etc/apt/keyrings/opentofu.gpg /etc/apt/keyrings/opentofu-repo.gpg \
  && printf "Types: deb\nURIs: https://packages.opentofu.org/opentofu/tofu/any/\nSuites: any\nComponents: main\nSigned-By: /etc/apt/keyrings/opentofu.gpg /etc/apt/keyrings/opentofu-repo.gpg\n" \
  > /etc/apt/sources.list.d/opentofu.sources 

RUN apt-get update && apt-get install -y --no-install-recommends \
  aggregate \
  containerd.io \
  coreutils \
  dnsutils \
  docker-buildx-plugin \
  docker-ce \
  docker-ce-cli \
  docker-compose-plugin \
  file \
  fzf \
  git \
  iputils-ping \
  jq \
  kmod \
  less \
  maven \
  net-tools \
  openjdk-21-jdk \
  openssh-client \
  procps \
  python3 \
  python3-venv \
  tofu \
  unzip \
  util-linux \
  vim \
  wget \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
  && unzip awscliv2.zip \
  && ./aws/install \
  && rm -rf ./aws* \
  && case "$(dpkg --print-architecture)" in \
       amd64) ssm_arch=64bit ;; \
       arm64) ssm_arch=arm64 ;; \
       *) echo "unsupported arch for ssm plugin" >&2; exit 1 ;; \
     esac \
  && curl -fsSL "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_${ssm_arch}/session-manager-plugin.deb" -o session-manager-plugin.deb \
  && dpkg -i session-manager-plugin.deb \
  && rm -f session-manager-plugin.deb \
  && curl -fsSL "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/$(dpkg --print-architecture)/kubectl" -o /usr/local/bin/kubectl \
  && chmod 0755 /usr/local/bin/kubectl \
  && curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-4 | bash

ARG USER_UID=1000
ARG USER_GID=1000
ARG USERNAME=huw
RUN if [ "${USER_GID}" != "1000" ]; then groupadd --gid "${USER_GID}" "${USERNAME}"; fi \
  && if [ "${USER_UID}" != "1000" ]; then \
       useradd --uid "${USER_UID}" --gid "${USER_GID}" --shell /bin/bash --create-home "${USERNAME}"; \
     else \
       usermod --login "${USERNAME}" --move-home --home "/home/${USERNAME}" "$(getent passwd 1000 | cut -d: -f1)"; \
     fi \
  && usermod -aG docker "${USERNAME}" \
  && su - ${USERNAME} -c "python3 -m venv ~/.venv \
  && ~/.venv/bin/pip install --no-cache-dir --upgrade pip \
  && ~/.venv/bin/pip install --no-cache-dir ansible ansible-lint little-timmy"

ARG CACHE_BUST=0
RUN echo "cache-bust=${CACHE_BUST}" \
  && su - ${USERNAME} -c "curl -fsSL https://claude.ai/install.sh | bash"

COPY certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
RUN update-ca-certificates

COPY --chmod=0755 dockerd-entrypoint.sh /usr/local/bin/dockerd-entrypoint.sh

# SSH->HTTPS rewrites for the default git hosts; the runtime overlay it includes
# is mounted by the orchestrator (see agent_uplink/git.py).
COPY gitconfig /etc/gitconfig

# Point ssh at keys mounted read-only at ~/.sshclaude (--ssh-key-dir) so ~/.ssh
# stays writable for known_hosts. Ubuntu's /etc/ssh/ssh_config includes this dir.
# The Include path must be absolute (ssh only expands '~' in user configs, not
# system-wide ones), so bake in the agent user's home.
COPY ssh_config /etc/ssh/ssh_config.d/agent-uplink.conf
RUN sed -i "s|__USERNAME__|${USERNAME}|" /etc/ssh/ssh_config.d/agent-uplink.conf

ENV SHELL=/bin/bash
ENV EDITOR=vim
ENV VISUAL=vim
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
ENV AWS_CA_BUNDLE=/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
ENV PATH="$PATH:/home/${USERNAME}/.local/bin"
ENV USERNAME=${USERNAME}
