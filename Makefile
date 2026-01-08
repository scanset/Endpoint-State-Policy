# ESP Monorepo Makefile
# Provides convenient commands for development, testing, and building

.PHONY: help build build-all build-libs test lint clean check security audit format docs install dev release run run-compiler

# Default target
help:
	@echo "ESP Monorepo - Available Commands"
	@echo "=================================="
	@echo ""
	@echo "Building:"
	@echo "  make build        - Build the agent binary"
	@echo "  make build-all    - Build all crates (libraries + binaries)"
	@echo "  make build-libs   - Build libraries only"
	@echo "  make dev          - Build agent in development mode"
	@echo "  make release      - Build optimized release agent"
	@echo "  make clean        - Clean all build artifacts"
	@echo ""
	@echo "Running:"
	@echo "  make run ESP=<file>         - Run agent on ESP file"
	@echo "  make run-compiler ESP=<file> - Run compiler on ESP file"
	@echo ""
	@echo "Testing:"
	@echo "  make test         - Run all tests"
	@echo "  make test-unit    - Run unit tests only"
	@echo "  make test-doc     - Run documentation tests"
	@echo "  make test-all     - Run all tests with all features"
	@echo ""
	@echo "Quality:"
	@echo "  make check        - Quick compilation check"
	@echo "  make lint         - Run clippy linter (strict)"
	@echo "  make lint-quick   - Run clippy linter (warnings only)"
	@echo "  make format       - Format code with rustfmt"
	@echo "  make format-check - Check code formatting"
	@echo ""
	@echo "Security:"
	@echo "  make security     - Run all security checks"
	@echo "  make audit        - Check for vulnerabilities"
	@echo "  make deny         - Check dependency policies"
	@echo ""
	@echo "Documentation:"
	@echo "  make docs         - Generate and open documentation"
	@echo "  make docs-all     - Generate all documentation"
	@echo ""
	@echo "Pre-commit:"
	@echo "  make pre-commit   - Run pre-commit checks"
	@echo ""
	@echo "Examples:"
	@echo "  make run ESP=policy.esp"
	@echo "  make run ESP=/path/to/policies/"
	@echo "  make run-compiler ESP=policy.esp"
	@echo ""

# =============================================================================
# Building
# =============================================================================

# Build agent binary (default)
build:
	cargo build --package agent

# Build all crates
build-all:
	cargo build --workspace

# Build libraries only
build-libs:
	cargo build --package common
	cargo build --package compiler
	cargo build --package execution_engine
	cargo build --package contract_kit

# Development build (agent)
dev:
	ESP_BUILD_PROFILE=development cargo build --package agent

# Release build (agent)
release:
	ESP_BUILD_PROFILE=production cargo build --release --package agent

# Release build all
release-all:
	ESP_BUILD_PROFILE=production cargo build --release --workspace

# =============================================================================
# Running
# =============================================================================

# Run the agent
# Usage: make run ESP=policy.esp
# Usage: make run ESP=/path/to/policies/
run:
ifndef ESP
	@echo "Usage: make run ESP=<file.esp|directory>"
	@echo ""
	@echo "Examples:"
	@echo "  make run ESP=policy.esp"
	@echo "  make run ESP=/path/to/policies/"
	@exit 1
endif
	cargo run --package agent -- $(ESP) $(ARGS)

# Run the agent in release mode
run-release:
ifndef ESP
	@echo "Usage: make run-release ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run --release --package agent -- $(ESP) $(ARGS)

# Run the compiler
# Usage: make run-compiler ESP=policy.esp
# Usage: make run-compiler ESP=/path/to/policies/
run-compiler:
ifndef ESP
	@echo "Usage: make run-compiler ESP=<file.esp|directory>"
	@echo ""
	@echo "Examples:"
	@echo "  make run-compiler ESP=policy.esp"
	@echo "  make run-compiler ESP=/path/to/policies/ --sequential"
	@exit 1
endif
	cargo run --package compiler -- $(ESP) $(ARGS)

# Run compiler in release mode
run-compiler-release:
ifndef ESP
	@echo "Usage: make run-compiler-release ESP=<file.esp|directory>"
	@exit 1
endif
	cargo run --release --package compiler -- $(ESP) $(ARGS)

# =============================================================================
# Testing
# =============================================================================

test:
	ESP_BUILD_PROFILE=testing cargo test --workspace

test-unit:
	cargo test --workspace --lib

test-doc:
	cargo test --workspace --doc

test-all:
	cargo test --workspace --all-features

# Test specific crate
test-common:
	cargo test --package common

test-compiler:
	cargo test --package compiler

test-engine:
	cargo test --package execution_engine

test-kit:
	cargo test --package contract_kit

test-agent:
	cargo test --package agent

# =============================================================================
# Code Quality
# =============================================================================

check:
	cargo check --workspace --all-targets --all-features

# Strict linting (CI/pre-commit)
lint:
	cargo clippy --workspace --all-targets --all-features -- \
		-D warnings \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic \
		-D clippy::indexing_slicing

# Quick linting (development)
lint-quick:
	cargo clippy --workspace --all-targets -- -D warnings

# Auto-fix linting issues
lint-fix:
	cargo clippy --workspace --all-targets --all-features --fix --allow-dirty -- \
		-D warnings

format:
	cargo fmt --all

format-check:
	cargo fmt --all -- --check

# =============================================================================
# Security
# =============================================================================

security: audit deny

audit:
	cargo audit

deny:
	@echo "Note: cargo-deny requires Rust 1.85+"
	@echo "Install with: cargo install cargo-deny"
	@which cargo-deny > /dev/null && cargo deny check || \
		echo "cargo-deny not found. Run in CI/CD or install Rust 1.85+"

# =============================================================================
# Documentation
# =============================================================================

docs:
	cargo doc --workspace --all-features --no-deps --open

docs-all:
	cargo doc --workspace --all-features --document-private-items

# =============================================================================
# Dependency Management
# =============================================================================

outdated:
	cargo outdated --workspace

tree:
	cargo tree --workspace

bloat:
	cargo bloat --release --crates

# =============================================================================
# Cleaning
# =============================================================================

clean:
	cargo clean

clean-all: clean
	rm -rf target/
	rm -rf common/target/
	rm -rf compiler/target/
	rm -rf execution_engine/target/
	rm -rf contract_kit/target/
	rm -rf agent/target/

# =============================================================================
# Pre-commit & CI
# =============================================================================

pre-commit: format-check lint test
	@echo "✓ Pre-commit checks passed"

ci: format-check lint test-all security
	@echo "✓ CI checks passed"

# =============================================================================
# Installation
# =============================================================================

# Install agent binary to ~/.cargo/bin
install:
	cargo install --path agent

# Install development tools
install-tools:
	cargo install cargo-audit cargo-outdated cargo-watch cargo-tree cargo-bloat

# =============================================================================
# Cross-compilation
# =============================================================================

build-windows:
	ESP_BUILD_PROFILE=production cargo build --release --package agent --target x86_64-pc-windows-gnu

build-linux:
	ESP_BUILD_PROFILE=production cargo build --release --package agent --target x86_64-unknown-linux-gnu

# =============================================================================
# Watch Mode (Development)
# =============================================================================

watch:
	cargo watch -x 'check --workspace' -x 'test --workspace'

watch-test:
	cargo watch -x 'test --workspace'

watch-agent:
	cargo watch -x 'build --package agent'

# =============================================================================
# Benchmarking
# =============================================================================

bench:
	cargo bench --workspace

# =============================================================================
# Analysis
# =============================================================================

analyze:
	@echo "Running code analysis..."
	@cargo tree --workspace --duplicates
	@cargo bloat --release --crates
