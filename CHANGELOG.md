# Changelog with Security Notes

## [0.2.0] - 2026-01-08

### Added

- **Platform-Specific Cryptography** (common): New `crypto` module providing FIPS 140-3 compliant hashing with platform-native backends:
  - Windows: Windows CNG (BCrypt) - built into Windows 10/11/Server 2016+
  - Linux/Unix: OpenSSL FIPS provider
- **Cross-Compilation Support**: Windows builds no longer require OpenSSL. The `windows` crate provides native CNG bindings that cross-compile cleanly from Linux.
- **Canonical JSON Serialization** (common): New `crypto::canonical` module ensures deterministic JSON output for consistent content hashing regardless of field ordering.
- **Results Module Restructure** (common): New consolidated result types for cleaner API:
  - `ExecutionEnvelope`: Universal wrapper with WHO/WHAT/WHERE/WHEN metadata (agent, host, timestamps, signature)
  - `ExecutionSummary`: Aggregate statistics with posture scoring and criticality breakdown
  - `Evidence`: Raw collected data container with collection metadata
  - `EvidenceSummary`: CUI-free evidence summary for attestations
  - `PolicyIdentity`: Lightweight policy identification for attestations
  - `CollectionRecord`: Metadata about individual collection operations
- **CTN Type Documentation** (contract_kit): Comprehensive reference documentation for all CTN types in `contract_kit/docs/`:
  - `ctn_file_metadata.md`: File permissions, ownership, existence validation
  - `ctn_file_content.md`: File content validation with string operations
  - `ctn_json_record.md`: Structured JSON field validation with record checks
  - `ctn_tcp_listener.md`: TCP port listening state validation
  - `ctn_k8s_resource.md`: Kubernetes API resource validation
  - `ctn_computed_values.md`: RUN operation result validation
- **Test ESP Policies** (esp): Three reference policies demonstrating CTN types:
  - `test_file_metadata.esp`: System file permissions validation (CIS 6.1.1, 6.1.2)
  - `test_file_content.esp`: System account configuration validation (CIS 5.4.1)
  - `test_tcp_listener.esp`: Network port validation (CIS 3.4.1)
- **Agent CLI** (agent): New reference CLI application using `execution_engine` for batch scanning with JSON output

### Changed

- **Crate Rename**: `agent_core` renamed to `execution_engine` to better reflect its purpose as the resolution and execution framework
- **Executor Trait Signature** (execution_engine): `execute_with_contract` now takes owned `HashMap<String, CollectedData>` instead of reference, enabling executors to include collected data in results without cloning
- **CtnExecutionResult** (execution_engine): Now includes `collected_data: HashMap<String, CollectedData>` field and `with_collected_data()` builder method for evidence preservation
- **Attestation Hashing** (common): `attestation::hashing` module now re-exports from `crypto` module for backwards compatibility. Existing code using `hash_content()`, `verify_hash()`, and `sha256_hash()` continues to work unchanged.
- **Dependencies** (common): Crypto dependencies are now platform-conditional:
  - `openssl` only included on non-Windows targets
  - `windows` crate with `Win32_Security_Cryptography` feature only included on Windows targets
- **Clippy Lint Rules**: Enforced stricter linting across all crates:
  - `#![deny(clippy::unwrap_used)]` - Prevents panics from `.unwrap()` in production code
  - `#![deny(clippy::expect_used)]` - Prevents panics from `.expect()` in production code
  - `#![deny(clippy::indexing_slicing)]` - Requires safe `.get()` access instead of direct indexing
  - `#![allow(...)]` attributes added to test modules where these patterns are acceptable
- **Makefile**: Updated for agent-focused workflow:
  - `make build` now builds the agent
  - `make run ESP=<path>` runs agent on file or directory
  - `make run-compiler ESP=<path>` runs compiler only
  - `make lint` runs strict clippy checks
  - Removed cross-compilation targets (simplified for development)
- **README.md**: Streamlined from ~500 to ~150 lines:
  - Removed verbose trust model diagrams (referenced doc instead)
  - Removed embedded code examples (referenced `esp/` directory)
  - Added Dev Container setup instructions
  - Added CTN types table with links to documentation
  - Updated architecture diagram

### Fixed

- **Safe Indexing** (contract_kit): Fixed clippy `indexing_slicing` violations in collectors:
  - `command.rs`: 4 fixes for command output parsing
  - `tcp_listener.rs`: 8 fixes for `/proc/net/tcp` parsing
  - All direct array indexing (`parts[0]`) replaced with safe `.get()` access

### Removed

- **Feature-Gated OpenSSL** (common): The `attestation` feature no longer gates the `openssl` dependency. Cryptography is always available via the platform-appropriate backend.
- **Consolidated CTN Types** (contract_kit): Reduced total number of contracts by consolidating platform-specific implementations:
  - Removed RHEL-specific RPM, systemd, sysctl, SELinux contracts (moved to platform-specific extensions)
  - Core CTN types now focus on cross-platform primitives: `file_metadata`, `file_content`, `json_record`, `tcp_listener`, `k8s_resource`, `computed_values`

### Documentation

- **Scanner Development Guide**: Major update with new sections:
  - Command Execution: Sandbox constraints, environment variable handling, output parsing
  - Understanding Command Output: Detailed examples for `/proc/net/tcp`, `stat`, `kubectl`
  - Type Conversion Rules: Source data to ResolvedValue mapping
  - Safe Output Parsing: Using `.get()` instead of direct indexing
  - Updated best practices and checklists
- **ESP Language Guide**: Updated to reference test policies and CTN documentation:
  - Part 3-5 now use `test_file_metadata.esp`, `test_file_content.esp`, `test_tcp_listener.esp` as examples
  - Added links to `contract_kit/docs/` throughout
  - Updated CTN Type Reference table with documentation links
- **Common Crate README**: Added documentation for new result types:
  - `ExecutionEnvelope`, `ExecutionSummary`, `Evidence`, `PolicyIdentity`
  - Updated module structure to reflect new files
- **Results Module README**: New comprehensive documentation covering:
  - Security model (attestation vs full results)
  - Module structure with new consolidated types
  - Key types reference with usage examples

## [0.1.4] - 2026-01-06

### Added
- **Platform-Specific Cryptography** (common): New `crypto` module providing FIPS 140-3 compliant hashing with platform-native backends:
  - Windows: Windows CNG (BCrypt) - built into Windows 10/11/Server 2016+
  - Linux/Unix: OpenSSL FIPS provider
- **Cross-Compilation Support**: Windows builds no longer require OpenSSL. The `windows` crate provides native CNG bindings that cross-compile cleanly from Linux.
- **Canonical JSON Serialization** (common): New `crypto::canonical` module ensures deterministic JSON output for consistent content hashing regardless of field ordering.

### Changed
- **Attestation Hashing** (common): `attestation::hashing` module now re-exports from `crypto` module for backwards compatibility. Existing code using `hash_content()`, `verify_hash()`, and `sha256_hash()` continues to work unchanged.
- **Dependencies** (common): Crypto dependencies are now platform-conditional:
  - `openssl` only included on non-Windows targets
  - `windows` crate with `Win32_Security_Cryptography` feature only included on Windows targets

### Removed
- **Feature-Gated OpenSSL** (common): The `attestation` feature no longer gates the `openssl` dependency. Cryptography is always available via the platform-appropriate backend.


## [0.1.3] - 2026-01-03

### Changed
- **Evidence Propagation** (agent_core): `ExecutionEngine::build_evidence()` now extracts evidence from `CtnExecutionResult.details` and propagates it to `PolicyExecutionResult.evidence`. Previously, evidence was always `None`.


## [0.1.1] - 2026-01-01

### Fixed
- K8sResourceCollector now correctly uses in-cluster authentication when running inside Kubernetes pods. Previously, kubectl would fail to auto-detect ServiceAccount credentials when `KUBERNETES_SERVICE_HOST` was set.

# 31 DEC 2025 - v.0.1 release
