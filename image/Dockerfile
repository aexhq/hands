# The aex hand image: the guest agent plus a curated toolchain. Built for ARM64 (Lambda MicroVM
# and Graviton). The hand guest binary is compiled separately (musl static) and copied in, so this
# stage stays a thin, cached runtime layer. glibc (gnu) target, matching the ubuntu base.
#
#   docker build -f image/Dockerfile --build-arg BIN=target/aarch64-unknown-linux-gnu/release/hand-guest -t aex-hand:dev .
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    HOME=/home/agent \
    CARGO_HOME=/workspace/.aex/cargo \
    RUSTUP_HOME=/workspace/.aex/rustup \
    GOPATH=/workspace/.aex/go \
    GOMODCACHE=/workspace/.aex/go/pkg/mod \
    npm_config_prefix=/workspace/.aex/npm \
    PIP_CACHE_DIR=/workspace/.aex/pip \
    PIPX_HOME=/workspace/.aex/pipx \
    PIPX_BIN_DIR=/workspace/.aex/bin \
    UV_CACHE_DIR=/workspace/.aex/uv \
    PATH=/workspace/.aex/bin:/workspace/.aex/npm/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    AEX_HAND_WORKSPACE=/workspace \
    AEX_HAND_HOME=/home/agent \
    AEX_HAND_SPILL_DIR=/var/aex/ops \
    AEX_HAND_LISTEN=0.0.0.0:7000

# Curated toolchain. Installers are redirected into /workspace/.aex/** (see ENV above) so their
# output is captured by workspace sync; system-wide installs are ephemeral and the agent is told so.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git openssh-client \
      build-essential pkg-config \
      python3 python3-venv python3-pip pipx \
      nodejs npm \
      ripgrep jq unzip zip zstd xz-utils file less \
      procps coreutils bash \
    && rm -rf /var/lib/apt/lists/*

# ubuntu:24.04 ships a uid-1000 "ubuntu" user; remove it, then create "agent" as uid 1000.
RUN deluser --remove-home ubuntu 2>/dev/null || true; \
    userdel -f ubuntu 2>/dev/null || true; \
    groupdel ubuntu 2>/dev/null || true; \
    useradd --create-home --home-dir /home/agent --shell /bin/bash --uid 1000 --user-group agent \
    && mkdir -p /workspace /var/aex/ops \
    && chown -R agent:agent /workspace /home/agent /var/aex

ARG BIN
COPY ${BIN} /usr/local/bin/hand-guest
RUN chmod 0755 /usr/local/bin/hand-guest

USER agent
WORKDIR /workspace
EXPOSE 7000
ENTRYPOINT ["/usr/local/bin/hand-guest"]
