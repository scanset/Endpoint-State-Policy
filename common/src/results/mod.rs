//! # ESP Scan Results Module
//!
//! Types and utilities for ESP compliance validation results.
//!
//! ## Architecture
//!
//! ```text
//! ExecutionManifest (from execution_engine)
//!     │
//!     ▼ ResultBuilder
//!     │
//! ┌───┴───────────────────────────────────────────┐
//! │                                               │
//! ▼                                               ▼
//! AttestationResult                          FullResult
//! (feature: attestation)                     (feature: full-results)
//! │                                               │
//! ├── envelope (with signature block)            ├── envelope
//! ├── summary                                    ├── summary
//! └── checks[]                                   └── policies[]
//!     ├── identity                                   ├── identity
//!     ├── outcome                                    ├── outcome
//!     └── weight                                     ├── weight
//!                                                    ├── findings[]
//!                                                    └── evidence
//! ```
//!
//! ## Features
//!
//! - `attestation` (default) - CUI-free results for SaaS/network transport
//! - `full-results` - Complete results with evidence (local storage only)
//! - `assessor-evidence` - Full results with collection commands (implies full-results)
//!
//! ## Hash Architecture
//!
//! All output formats use pre-computed hashes from `ExecutionManifest`. The hashes
//! are computed ONCE during execution and passed through unchanged to ensure
//! consistency across all output formats.
//!
//! ## Content Matrix
//!
//! | Content              | Attestation | Full Results | Assessor Evidence |
//! |----------------------|-------------|--------------|-------------------|
//! | Policy ID            | ✓           | ✓            | ✓                 |
//! | Outcome              | ✓           | ✓            | ✓                 |
//! | Criticality          | ✓           | ✓            | ✓                 |
//! | Control mappings     | ✓           | ✓            | ✓                 |
//! | Weight               | ✓           | ✓            | ✓                 |
//! | Evidence hash        | ✓           | ✓            | ✓                 |
//! | Content hash         | ✓           | ✓            | ✓                 |
//! | Host ID              | ✓           | ✓            | ✓                 |
//! | Findings             | ✗           | ✓            | ✓                 |
//! | Evidence data        | ✗           | ✓            | ✓                 |
//! | Collection method    | ✗           | ✓            | ✓                 |
//! | Collection target    | ✗           | ✓            | ✓                 |
//! | Collection command   | ✗           | ✗            | ✓                 |
//! | Collection inputs    | ✗           | ✗            | ✓                 |
//!
//! ## Usage
//!
//! ### Building Attestations
//!
//! ```rust,ignore
//! use common::results::{ResultBuilder, CheckInput, Criticality, Outcome};
//!
//! let builder = ResultBuilder::from_system("agent-001");
//!
//! let checks = vec![
//!     CheckInput::new("policy-1", "linux", Criticality::High, vec![], Outcome::Pass),
//!     CheckInput::new("policy-2", "linux", Criticality::Medium, vec![], Outcome::Fail),
//! ];
//!
//! // Pre-computed hashes from ExecutionManifest
//! let attestation = builder.build_attestation(
//!     checks,
//!     manifest.content_hash,
//!     manifest.evidence_hash,
//! )?;
//! ```
//!
//! ### Building Full Results
//!
//! ```rust,ignore
//! use common::results::{ResultBuilder, PolicyInput, Criticality, Outcome};
//!
//! let builder = ResultBuilder::from_system("agent-001");
//!
//! let policies = vec![
//!     PolicyInput::new("policy-1", "linux", Criticality::High, vec![], Outcome::Pass)
//!         .with_findings(findings)
//!         .with_evidence(evidence),
//! ];
//!
//! // Pre-computed hashes from ExecutionManifest
//! let full_result = builder.build_full_result(
//!     policies,
//!     manifest.content_hash,
//!     manifest.evidence_hash,
//! )?;
//! ```

// ============================================================================
// Core modules (always available)
// ============================================================================

pub mod common;
pub mod crypto;
pub mod error;

pub mod collection_method;
pub mod envelope;
pub mod evidence;
pub mod finding;
pub mod identity;
pub mod summary;

pub mod builder;

// ============================================================================
// Feature-gated modules
// ============================================================================

#[cfg(feature = "attestation")]
pub mod attestation;

#[cfg(feature = "full-results")]
pub mod full;

#[cfg(feature = "assessor-evidence")]
pub mod assessor;

// ============================================================================
// Common re-exports (always available)
// ============================================================================

pub use common::{
    ControlMapping, ControlMappingError, CriteriaCounts, Criticality, Outcome, PolicyOutcome,
    ResultCounts, Weight,
};
pub use error::ResultError;

pub use collection_method::{CollectionMethod, CollectionMethodBuilder, CollectionMethodType};
pub use envelope::{AgentInfo, HostInfo, ResultEnvelope, SignatureBlock};
pub use evidence::{CollectionRecord, Evidence};
pub use finding::{ComplianceFinding, FindingBuilder, FindingSeverity};
pub use identity::PolicyIdentity;
pub use summary::{CriticalityBreakdown, CriticalityStats, ExecutionSummary, ScanSummary};

pub use builder::ResultBuilder;

// ============================================================================
// Crypto re-exports
// ============================================================================

pub use crypto::{hash_content, hex_decode, hex_encode, sha256_hash, HashingError};

// ============================================================================
// Attestation re-exports (feature: attestation)
// ============================================================================

#[cfg(feature = "attestation")]
pub use attestation::{AttestationBuilder, AttestationResult, CheckAttestation};

#[cfg(feature = "attestation")]
pub use builder::CheckInput;

// ============================================================================
// Full results re-exports (feature: full-results)
// ============================================================================

#[cfg(feature = "full-results")]
pub use full::{FullResult, FullResultBuilder, PolicyResult};

#[cfg(feature = "full-results")]
pub use builder::PolicyInput;

// ============================================================================
// Assessor package re-exports (feature: assessor-evidence)
// ============================================================================

#[cfg(feature = "assessor-evidence")]
pub use assessor::{
    AssessorPackage, AssessorPackageBuilder, AssessorPolicyResult, CollectionCommand, PackageInfo,
    ReproducibilityInfo,
};

#[cfg(feature = "assessor-evidence")]
pub use builder::AssessorInput;

/// Primary assessor package type (feature: assessor-evidence)
#[cfg(feature = "assessor-evidence")]
pub type AssessorResult = AssessorPackage;

// ============================================================================
// Type aliases for convenience
// ============================================================================

/// Primary attestation type (feature: attestation)
#[cfg(feature = "attestation")]
pub type Attestation = AttestationResult;

/// Primary full result type (feature: full-results)
#[cfg(feature = "full-results")]
pub type FullResults = FullResult;
