# Changelog with Security Notes

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
