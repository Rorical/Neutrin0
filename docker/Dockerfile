# syntax=docker/dockerfile:1.7
#
# Multi-stage Dockerfile for the `neutrin0-node` binary. Build from the
# repository root so the workspace is the context:
#
#   docker build -f docker/Dockerfile -t neutrin0-node .
#
# Stage 1: builder pinned to the same toolchain CI uses
# (rust-toolchain.toml -> 1.99.0). We compile `neutrin0-node` with
# `--locked --release`, then copy the binary into a slim runtime stage.
#
# Stage 2: minimal Debian-slim runtime — libp2p QUIC + RocksDB need
# libstdc++ and libssl from glibc, so we cannot use scratch or distroless
# static. We expose a single 30303/tcp port by convention; tests can
# remap as needed.

ARG RUST_VERSION=1.99.0

# --- builder ------------------------------------------------------------------
FROM rust:${RUST_VERSION}-slim-bookworm AS builder

# RocksDB build prerequisites + git for cargo metadata.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        libclang-dev \
        libprotobuf-dev \
        libssl-dev \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.sp1/bin:${PATH}"
RUN curl -fsSL https://sp1up.succinct.xyz | bash \
    && /root/.sp1/bin/sp1up --version 6.10.0 \
    && rustup target add wasm32-unknown-unknown

# An image runs on other hosts than the one that built it, so drop the
# repository's `target-cpu=native` default (.cargo/config.toml).
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS=""

WORKDIR /src
# Copy the entire workspace; cargo will figure out the dependency graph.
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p neutrin0-node \
    && cp /src/target/release/neutrin0-node /usr/local/bin/neutrin0-node

# --- runtime ------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 65532 neutrin0

COPY --from=builder /usr/local/bin/neutrin0-node /usr/local/bin/neutrin0-node

# Persistent state directory. `data_dir` in the node config points
# here; mount a persistent volume so restarts resume from disk.
RUN mkdir -p /var/lib/neutrin0 \
    && chown neutrin0:neutrin0 /var/lib/neutrin0

USER neutrin0
WORKDIR /home/neutrin0

# Default node network ports.
EXPOSE 30303/tcp 30303/udp

ENV RUST_LOG="info,libp2p=warn,libp2p_swarm=info"

ENTRYPOINT ["/usr/local/bin/neutrin0-node"]
CMD ["--config", "/etc/neutrin0/config.toml"]
