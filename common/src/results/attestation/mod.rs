//! Attestation module for CUI-free compliance scan results
//!
//! This module provides types for creating attestations that can be safely
//! transported without including Controlled Unclassified Information (CUI).
//!
//! ## Key Types
//!
//! - [`ScanAttestation`] - Complete attestation for an agent scan run
//! - [`CheckAttestation`] - Individual policy check result
//! - [`AttestationEnvelope`] - Mutable metadata (excluded from signing)
//! - [`AttestationSummary`] - Aggregate statistics
//!
//! ## Usage
//!
//! ```rust,ignore
//! use common::results::attestation::{AttestationBuilder, ScanAttestation};
//!
//! let mut builder = AttestationBuilder::new("agent-001", "controller");
//!
//! for (metadata, outcome, counts) in scan_results {
//!     builder.add_check(&metadata, outcome, counts)?;
//! }
//!
//! let attestation: ScanAttestation = builder.build()?;
//! let json = attestation.to_json()?;
//! ```
//!
//! ## Required META Fields
//!
//! The attestation builder enforces these required META fields:
//!
//! - `esp_scan_id` - Unique policy identifier
//! - `platform` - Target platform (Kubernetes, Linux, etc.)
//! - `criticality` - Criticality level (critical, high, medium, low, info)
//! - `control_mapping` - Framework:ControlID pairs (e.g., "NIST-800-53:AC-6,CIS:5.1.1")
//!
//! ## Optional META Fields
//!
//! - `esp_version` - Policy version
//! - `weight` - Explicit weight override (0.0-1.0)
//! - `tags` - Comma-separated tags

pub mod builder;
pub mod hashing;
pub mod types;

// Re-export main types
pub use builder::{
    validate_metadata, AttestationBuildError, AttestationBuilder, REQUIRED_META_FIELDS,
};
pub use hashing::{hash_content, sha256_hash, to_canonical_json, verify_hash, HashingError};
pub use types::{
    AttestationEnvelope, AttestationSummary, CheckAttestation, CriticalityBreakdown,
    CriticalityStats, ScanAttestation,
};
