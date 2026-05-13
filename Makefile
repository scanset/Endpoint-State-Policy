# ESP Monorepo Makefile
# Provides convenient commands for development, testing, and building

.PHONY: help build build-all build-libs test lint clean check security audit deny sbom build-auditable format docs dev release

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
	@echo "  make security     - Run all security checks (audit + deny + sbom)"
	@echo "  make audit        - Check for vulnerabilities (cargo-audit)"
	@echo "  make deny         - Check dependency policies (cargo-deny)"
	@echo "  make sbom         - Regenerate CycloneDX SBOM at docs/sbom/"
	@echo "  make build-auditable - Release build with embedded SBOM (cargo-auditable)"
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

# Full security gate: vulnerability scan + dependency policy + SBOM
# Implements NIST SP 800-218 SSDF tasks PW.4.4 (verify components),
# PW.8.2 (automated vulnerability detection), PS.3.2 (component provenance).
security: audit deny sbom

audit:
	@which cargo-audit > /dev/null && cargo audit || \
		(echo "cargo-audit not found. Run: make install-tools" && exit 1)

deny:
	@which cargo-deny > /dev/null && cargo deny check || \
		(echo "cargo-deny not found. Run: make install-tools" && exit 1)

# Generate per-crate CycloneDX SBOMs and stage them under docs/sbom/.
# Implements NIST SP 800-218 SSDF PS.3.2 (provenance for components).
# cargo-cyclonedx 0.5+ writes each SBOM next to its crate's Cargo.toml;
# we relocate them after generation so all SBOMs live in one place.
sbom:
	@which cargo-cyclonedx > /dev/null || \
		(echo "cargo-cyclonedx not found. Run: make install-tools" && exit 1)
	@mkdir -p docs/sbom
	cargo cyclonedx --format json --spec-version 1.5 --quiet
	@find . -maxdepth 3 -name '*.cdx.json' -not -path './target/*' -not -path './docs/*' \
		-exec mv {} docs/sbom/ \;
	@echo "Generated SBOMs:"
	@ls -1 docs/sbom/*.cdx.json

# Release build with embedded dependency tree (cargo-auditable)
# Compiled binaries can be re-audited post-distribution with `cargo audit bin <binary>`.
# Implements NIST SP 800-218 SSDF PW.4.4 (ongoing component verification) and
# RV.1.1 (ongoing vulnerability monitoring of deployed software).
build-auditable:
	@which cargo-auditable > /dev/null && \
		ESP_BUILD_PROFILE=production cargo auditable build --release --workspace || \
		(echo "cargo-auditable not found. Run: make install-tools" && exit 1)

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
# Security/SBOM tooling supports NIST SP 800-218 SSDF compliance:
#   cargo-audit       - PW.8.2 / RV.1.1 vulnerability scanning
#   cargo-deny        - PS.3.2 / PW.4.4 license + source verification
#   cargo-cyclonedx   - PS.3.2 SBOM generation (CycloneDX)
#   cargo-auditable   - PW.4.4 binary-embedded dependency provenance
install-tools:
	cargo install cargo-audit cargo-deny cargo-cyclonedx cargo-auditable \
		cargo-outdated cargo-watch cargo-tree cargo-bloat

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
