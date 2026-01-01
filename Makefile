# ESP Monorepo Makefile
# Provides convenient commands for development, testing, and building

.PHONY: help build test lint lint-quick clean check security audit format docs install dev release

# Default target
help:
	@echo "ESP Monorepo - Available Commands"
	@echo "=================================="
	@echo ""
	@echo "Development:"
	@echo "  make dev          - Build in development mode"
	@echo "  make build        - Build all crates"
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
	@echo "  make lint         - Run clippy linter"
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

# Development builds
dev:
	ESP_BUILD_PROFILE=development cargo build --workspace

build:
	cargo build --workspace

release:
	ESP_BUILD_PROFILE=production cargo build --release --workspace

# Testing
test:
	ESP_BUILD_PROFILE=testing cargo test --workspace

test-unit:
	cargo test --workspace --lib

test-doc:
	cargo test --workspace --doc

test-all:
	cargo test --workspace --all-features

# Code quality
check:
	cargo check --workspace --all-targets --all-features

lint:
	cargo clippy --workspace --all-targets --all-features -- \
		-D warnings \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic \
		-D clippy::indexing_slicing

lint-fix:
	cargo clippy --workspace --all-targets --all-features --fix --allow-dirty -- \
		-D warnings

format:
	cargo fmt --all

format-check:
	cargo fmt --all -- --check

# Security checks
security: audit deny

audit:
	cargo audit

# Note: cargo-deny requires Rust 1.85+, run in CI or with newer Rust
deny:
	@echo "Note: cargo-deny requires Rust 1.85+"
	@echo "Install with: cargo install cargo-deny"
	@which cargo-deny > /dev/null && cargo deny check || \
		echo "cargo-deny not found. Run in CI/CD or install Rust 1.85+"

# Documentation
docs:
	cargo doc --workspace --all-features --no-deps --open

docs-all:
	cargo doc --workspace --all-features --document-private-items

# Dependency management
outdated:
	cargo outdated --workspace

tree:
	cargo tree --workspace

bloat:
	cargo bloat --release --crates

# Cleaning
clean:
	cargo clean

clean-all: clean
	rm -rf target/
	rm -rf common/target/
	rm -rf compiler/target/
	rm -rf agent_core/target/
	rm -rf contract_kit/target/
	rm -rf agent/target/

# Pre-commit checks
# ESP Monorepo Makefile
# Provides convenient commands for development, testing, and building

.PHONY: help build test lint lint-quick clean check security audit format docs install dev release

# Default target
help:
	@echo "ESP Monorepo - Available Commands"
	@echo "=================================="
	@echo ""
	@echo "Development:"
	@echo "  make dev          - Build in development mode"
	@echo "  make build        - Build all crates"
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
	@echo "  make lint         - Run clippy linter"
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

# Development builds
dev:
	ESP_BUILD_PROFILE=development cargo build --workspace

build:
	cargo build --workspace

release:
	ESP_BUILD_PROFILE=production cargo build --release --workspace

# Testing
test:
	ESP_BUILD_PROFILE=testing cargo test --workspace

test-unit:
	cargo test --workspace --lib

test-doc:
	cargo test --workspace --doc

test-all:
	cargo test --workspace --all-features

# Code quality
check:
	cargo check --workspace --all-targets --all-features

lint:
	cargo clippy --workspace --all-targets --all-features -- \
		-D warnings \
		-D clippy::unwrap_used \
		-D clippy::expect_used \
		-D clippy::panic \
		-D clippy::indexing_slicing

lint-fix:
	cargo clippy --workspace --all-targets --all-features --fix --allow-dirty -- \
		-D warnings

format:
	cargo fmt --all

format-check:
	cargo fmt --all -- --check

# Security checks
security: audit deny

audit:
	cargo audit

# Note: cargo-deny requires Rust 1.85+, run in CI or with newer Rust
deny:
	@echo "Note: cargo-deny requires Rust 1.85+"
	@echo "Install with: cargo install cargo-deny"
	@which cargo-deny > /dev/null && cargo deny check || \
		echo "cargo-deny not found. Run in CI/CD or install Rust 1.85+"

# Documentation
docs:
	cargo doc --workspace --all-features --no-deps --open

docs-all:
	cargo doc --workspace --all-features --document-private-items

# Dependency management
outdated:
	cargo outdated --workspace

tree:
	cargo tree --workspace

bloat:
	cargo bloat --release --crates

# Cleaning
clean:
	cargo clean

clean-all: clean
	rm -rf target/
	rm -rf common/target/
	rm -rf compiler/target/
	rm -rf agent_core/target/
	rm -rf contract_kit/target/
	rm -rf agent/target/

# Pre-commit checks
pre-commit:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets -- -D warnings
	cargo test --workspace --lib
	@echo "✓ Pre-commit checks passed"

# Installation helpers
install:
	cargo install --path agent --features cli

install-tools:
	cargo install cargo-audit cargo-outdated cargo-watch cargo-tree cargo-bloat

# Cross-compilation targets
build-windows:
	ESP_BUILD_PROFILE=production cargo build --release --target x86_64-pc-windows-gnu

build-linux:
	ESP_BUILD_PROFILE=production cargo build --release --target x86_64-unknown-linux-gnu

# Watch mode for development
watch:
	cargo watch -x 'check --workspace' -x 'test --workspace'

watch-test:
	cargo watch -x 'test --workspace'

# Benchmarking (if criterion is set up)
bench:
	cargo bench --workspace

# Analysis
analyze:
	@echo "Running code analysis..."
	@cargo tree --workspace --duplicates
	@cargo bloat --release --cratesd"

lint-quick:
	cargo clippy --workspace --all-targets -- -D warnings

# Installation helpers
install:
	cargo install --path agent --features cli

install-tools:
	cargo install cargo-audit cargo-outdated cargo-watch cargo-tree cargo-bloat

# Cross-compilation targets
build-windows:
	ESP_BUILD_PROFILE=production cargo build --release --target x86_64-pc-windows-gnu

build-linux:
	ESP_BUILD_PROFILE=production cargo build --release --target x86_64-unknown-linux-gnu

# Watch mode for development
watch:
	cargo watch -x 'check --workspace' -x 'test --workspace'

watch-test:
	cargo watch -x 'test --workspace'

# Benchmarking (if criterion is set up)
bench:
	cargo bench --workspace

# Analysis
analyze:
	@echo "Running code analysis..."
	@cargo tree --workspace --duplicates
	@cargo bloat --release --crates
