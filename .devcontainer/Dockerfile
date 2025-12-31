# ESP Monorepo - Rust Development Container
# Security-focused development environment with cross-compilation support

FROM rust:1.85-bookworm

WORKDIR /workspace

# Environment variables for Rust tooling
ENV CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_BACKTRACE=1 \
    CARGO_INCREMENTAL=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Build essentials
    build-essential \
    pkg-config \
    libssl-dev \
    # Cross-compilation (Windows GNU target)
    mingw-w64 \
    # Cross-compilation (musl for static Linux builds - RHEL, Alpine, etc.)
    musl-tools \
    # Development tools
    git \
    curl \
    # Debugging tools
    gdb \
    lldb \
    # Utilities
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install Rust toolchain components
RUN rustup component add \
    clippy \
    rustfmt \
    rust-src \
    rust-analyzer \
    llvm-tools-preview

# Add cross-compilation targets
RUN rustup target add \
    x86_64-pc-windows-gnu \
    x86_64-unknown-linux-gnu \
    x86_64-unknown-linux-musl

# Install security-focused cargo tools
RUN cargo install --locked cargo-audit && \
    cargo install --locked cargo-deny@0.18.3

# Git configuration defaults
RUN git config --global init.defaultBranch main && \
    git config --global core.autocrlf input && \
    git config --global pull.rebase false

CMD ["/bin/bash"]
