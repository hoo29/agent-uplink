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
  kmod \
  less \
  maven \
  net-tools \
  openjdk-21-jdk \
  openssh-client \
  procps \
  python3 \
  python3-venv \
  unzip \
  util-linux \
  vim \
  wget \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN install -m 0755 -d /etc/apt/keyrings \
  && curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc \
  && chmod a+r /etc/apt/keyrings/docker.asc \
  && . /etc/os-release \
  && printf "Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.asc\n" \
    "${UBUNTU_CODENAME:-$VERSION_CODENAME}" "$(dpkg --print-architecture)" \
  > /etc/apt/sources.list.d/docker.sources \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin \
  && rm -rf /var/lib/apt/lists/*

RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
  && unzip awscliv2.zip \
  && ./aws/install \
  && rm -rf ./aws*

RUN curl -fsSL "https://dl.k8s.io/release/$(curl -fsSL https://dl.k8s.io/release/stable.txt)/bin/linux/$(dpkg --print-architecture)/kubectl" -o /usr/local/bin/kubectl \
  && chmod 0755 /usr/local/bin/kubectl

RUN install -m 0755 -d /etc/apt/keyrings \
  && curl -fsSL https://get.opentofu.org/opentofu.gpg -o /etc/apt/keyrings/opentofu.gpg \
  && curl -fsSL https://packages.opentofu.org/opentofu/tofu/gpgkey \
    | gpg --no-tty --batch --dearmor -o /etc/apt/keyrings/opentofu-repo.gpg \
  && chmod a+r /etc/apt/keyrings/opentofu.gpg /etc/apt/keyrings/opentofu-repo.gpg \
  && printf "Types: deb\nURIs: https://packages.opentofu.org/opentofu/tofu/any/\nSuites: any\nComponents: main\nSigned-By: /etc/apt/keyrings/opentofu.gpg /etc/apt/keyrings/opentofu-repo.gpg\n" \
  > /etc/apt/sources.list.d/opentofu.sources \
  && apt-get update \
  && apt-get install -y --no-install-recommends tofu \
  && rm -rf /var/lib/apt/lists/*

ARG USER_UID=1000
ARG USER_GID=1000
ARG USERNAME=huw
RUN if [ "${USER_GID}" != "1000" ]; then groupadd --gid "${USER_GID}" "${USERNAME}"; fi \
  && if [ "${USER_UID}" != "1000" ]; then \
       useradd --uid "${USER_UID}" --gid "${USER_GID}" --shell /bin/bash --create-home "${USERNAME}"; \
     else \
       usermod --login "${USERNAME}" --move-home --home "/home/${USERNAME}" "$(getent passwd 1000 | cut -d: -f1)"; \
     fi \
  && usermod -aG docker "${USERNAME}"

ARG CACHE_BUST=0
RUN echo "cache-bust=${CACHE_BUST}" \
  && su - ${USERNAME} -c "curl -fsSL https://claude.ai/install.sh | bash"

COPY certs/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
RUN update-ca-certificates

COPY --chmod=0755 dockerd-entrypoint.sh /usr/local/bin/dockerd-entrypoint.sh

ENV SHELL=/bin/bash
ENV EDITOR=vim
ENV VISUAL=vim
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
ENV AWS_CA_BUNDLE=/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt
ENV PATH="$PATH:/home/${USERNAME}/.local/bin"
ENV USERNAME=${USERNAME}
