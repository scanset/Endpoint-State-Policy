//! # Scan Results Module
//!
//! Provides types and utilities for ESP compliance validation results.
//!
//! ## Architecture
//!
//! ```text
//! ExecutionEnvelope (wraps all result types)
//! ├── result_id, agent, host, timestamps, content_hash, signature
//! │
//! ├── For Attestations (CUI-free, network-safe)
//! │   ├── ExecutionSummary
//! │   ├── CheckAttestation[] (PolicyIdentity + Outcome)
//! │   └── EvidenceSummary (hash only, no actual values)
//! │
//! └── For Full Results (CUI included, local storage)
//!     ├── ExecutionSummary
//!     ├── PolicyResult[] (includes findings)
//!     └── Evidence (complete collected data)
//! ```
//!
//! ## Cryptographic Hashing
//!
//! The `crypto` module provides FIPS 140-3 compliant hashing using platform-native
//! cryptography:
//! - **Windows**: Windows CNG (BCrypt) - built into all modern Windows versions
//! - **Linux/Unix**: OpenSSL FIPS provider
//!
//! ## Features
//!
//! This module supports two output modes via feature flags:
//!
//! ### `attestation` (default)
//!
//! CUI-free attestations safe for network transport:
//! - No actual system values
//! - Only pass/fail metadata
//! - Content hashing for integrity
//! - Signature-ready structure
//!
//! ### `full-results`
//!
//! Complete results with evidence (contains CUI):
//! - Expected/actual values
//! - Raw collected data
//! - For local storage only
//!
//! ## Required META Fields
//!
//! Both output modes require these META fields:
//!
//! - `esp_scan_id` - Unique policy identifier
//! - `platform` - Target platform
//! - `criticality` - Criticality level
//! - `control_mapping` - Framework:ControlID pairs

// ============================================================================
// Core modules (always available)
// ============================================================================

// Cryptographic utilities (platform-specific implementation)
pub mod crypto;

// Common types (Outcome, Criticality, etc.)
pub mod common;

// Error types
pub mod error;

// New consolidated types
pub mod envelope;
pub mod evidence;
pub mod identity;
pub mod summary;

// ============================================================================
// Feature-gated modules
// ============================================================================

#[cfg(feature = "attestation")]
pub mod attestation;

#[cfg(feature = "full-results")]
pub mod full;

// ============================================================================
// Crypto re-exports (always available)
// ============================================================================

pub use crypto::{hash_content, hex_decode, hex_encode, sha256_hash, verify_hash, HashingError};

// ============================================================================
// Common re-exports (always available)
// ============================================================================

pub use common::{
    ControlMapping, ControlMappingError, CriteriaCounts, Criticality, Outcome, PolicyOutcome,
    ResultCounts, Weight,
};

pub use error::{ResultError, ResultGenerationError};

// ============================================================================
// New consolidated type re-exports (always available)
// ============================================================================

pub use envelope::{AgentInfo, ExecutionEnvelope, HostInfo, SignatureInfo};
pub use evidence::{CollectionRecord, CollectionSummary, Evidence, EvidenceSummary};
pub use identity::PolicyIdentity;
pub use summary::{CriticalityBreakdown, CriticalityStats, ExecutionSummary};

// ============================================================================
// Attestation re-exports (default feature)
// ============================================================================

#[cfg(feature = "attestation")]
pub use attestation::{
    validate_metadata, AttestationBuildError, AttestationBuilder, AttestationEnvelope,
    AttestationSummary, CheckAttestation, CriticalityBreakdown as AttestationCriticalityBreakdown,
    CriticalityStats as AttestationCriticalityStats, ScanAttestation, REQUIRED_META_FIELDS,
};

// ============================================================================
// Full results re-exports (opt-in feature)
// ============================================================================

#[cfg(feature = "full-results")]
pub use full::{
    ComplianceFinding, EspMetadata, Evidence as FullEvidence, FindingSeverity,
    FullResultBuildError, FullResultBuilder, HostContext, PolicyResult, ScanMetadata, ScanResult,
    ScanSummary, TimestampInfo, UserContext,
};

// ============================================================================
// Convenience type aliases
// ============================================================================

/// Primary attestation type for network transport
#[cfg(feature = "attestation")]
pub type Attestation = ScanAttestation;

/// Primary result type for local storage
#[cfg(feature = "full-results")]
pub type FullResult = ScanResult;
