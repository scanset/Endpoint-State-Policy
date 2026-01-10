# ESP Monorepo Makefile
# Provides convenient commands for development, testing, and building

.PHONY: help build build-all build-libs test lint clean check security audit format docs dev release

# Default target
help:
	@echo "ESP Monorepo - Available Commands"
	@echo "=================================="
	@echo ""
	@echo "Building:"
	@echo "  make build        - Build all library crates"
	@echo "  make build-all    - Build all crates including compiler binary"
	@echo "  make dev          - Build in development mode"
	@echo "  make release      - Build optimized release"
	@echo "  make clean        - Clean all build artifacts"
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

# =============================================================================
# Building
# =============================================================================

# Build library crates (default)
build:
	cargo build --package common
	cargo build --package compiler
	cargo build --package execution_engine

# Build all crates including compiler binary
build-all:
	cargo build --workspace

# Development build
dev:
	ESP_BUILD_PROFILE=development cargo build --workspace

# Release build
release:
	ESP_BUILD_PROFILE=production cargo build --release --workspace

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

# Install development tools
install-tools:
	cargo install cargo-audit cargo-outdated cargo-watch cargo-tree cargo-bloat

# =============================================================================
# Watch Mode (Development)
# =============================================================================

watch:
	cargo watch -x 'check --workspace' -x 'test --workspace'

watch-test:
	cargo watch -x 'test --workspace'

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
