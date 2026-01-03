# GentlyOS - Content-Addressable AI System
# Multi-stage build for minimal runtime image

# Build stage
FROM rust:1.75-slim-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY gently-cli ./gently-cli

# Build release binary
RUN cargo build --release -p gently-cli

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    libpcap0.8 \
    curl \
    jq \
    git \
    && rm -rf /var/lib/apt/lists/*

# Ensure /bin/sh exists (for shell scripts)
RUN ln -sf /bin/bash /bin/sh

# Create gently user
RUN useradd -m -s /bin/bash gently

# Copy binary
COPY --from=builder /app/target/release/gently /usr/local/bin/gently

# Data directories
RUN mkdir -p /data/blobs /data/genesis /data/knowledge /data/ipfs \
    && chown -R gently:gently /data

# Set user
USER gently
WORKDIR /home/gently

# Volumes for persistent data
VOLUME ["/data/blobs", "/data/genesis", "/data/knowledge", "/data/ipfs"]

# Environment
ENV GENTLY_DATA_DIR=/data
ENV GENTLY_BLOB_DIR=/data/blobs
ENV GENTLY_LOG_LEVEL=info
ENV RUST_LOG=info
ENV SHELL=/bin/bash

# Ports
# 3000 - MCP server
# 4001 - IPFS swarm
# 8080 - Health/metrics
EXPOSE 3000 4001 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD gently status || exit 1

ENTRYPOINT ["gently"]
CMD ["--help"]
