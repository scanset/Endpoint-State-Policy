//! # Scan Results Module
//!
//! Provides types and utilities for ESP compliance validation results.
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
//! ```rust,ignore
//! use common::results::{AttestationBuilder, ScanAttestation};
//!
//! let mut builder = AttestationBuilder::new("agent-1", "controller");
//! builder.add_check(&metadata, outcome, criteria)?;
//! let attestation = builder.build()?;
//! ```
//!
//! ### `full-results`
//!
//! Complete results with evidence (contains CUI):
//! - Expected/actual values
//! - Raw collected data
//! - For local storage only
//!
//! ```rust,ignore
//! use common::results::full::{FullResultBuilder, ScanResult};
//!
//! let mut builder = FullResultBuilder::new("scan-1", "agent-1", "daemon");
//! builder.add_policy(&metadata, outcome, criteria, findings, evidence)?;
//! let result = builder.build();
//! ```
//!
//! ## Required META Fields
//!
//! Both output modes require these META fields:
//!
//! - `esp_scan_id` - Unique policy identifier
//! - `platform` - Target platform
//! - `criticality` - Criticality level
//! - `control_mapping` - Framework:ControlID pairs

// Common types (always available)
pub mod common;
pub mod error;

// Feature-gated modules
#[cfg(feature = "attestation")]
pub mod attestation;

#[cfg(feature = "full-results")]
pub mod full;

// ============================================================================
// Common re-exports (always available)
// ============================================================================

pub use common::{
    ControlMapping, ControlMappingError, CriteriaCounts, Criticality, Outcome, PolicyOutcome,
    ResultCounts, Weight,
};
pub use error::{ResultError, ResultGenerationError};

// ============================================================================
// Attestation re-exports (default feature)
// ============================================================================

#[cfg(feature = "attestation")]
pub use attestation::{
    hash_content, validate_metadata, verify_hash, AttestationBuildError, AttestationBuilder,
    AttestationEnvelope, AttestationSummary, CheckAttestation, CriticalityBreakdown,
    CriticalityStats, HashingError, ScanAttestation, REQUIRED_META_FIELDS,
};

// ============================================================================
// Full results re-exports (opt-in feature)
// ============================================================================

#[cfg(feature = "full-results")]
pub use full::{
    ComplianceFinding, EspMetadata, Evidence, FindingSeverity, FullResultBuildError,
    FullResultBuilder, HostContext, PolicyResult, ScanMetadata, ScanResult, ScanSummary,
    TimestampInfo, UserContext,
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
