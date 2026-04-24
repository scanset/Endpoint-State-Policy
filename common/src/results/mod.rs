//! # ESP Scan Results Module
//!
//! Types and utilities for ESP compliance validation results.
//!
//! ## Architecture
//!
//! As of v2.0.0 there is **one** output type: `AssessorPackage`. Attestation
//! and full-results variants (and the corresponding Cargo features) have
//! been removed — the assessor shape is already a superset, and maintaining
//! three formats in parallel cost more than it delivered.
//!
//! ```text
//! ExecutionManifest (from execution_engine)
//!     │
//!     ▼ ResultBuilder
//!     │
//!     ▼
//! AssessorPackage
//!     ├── envelope (ResultEnvelope)
//!     │   ├── host              (polymorphic HostInfo, v2.0.0)
//!     │   ├── observations[]    (first-class evidence, v2.0.0)
//!     │   ├── identity_status
//!     │   └── signature
//!     │       ├── certificate_chain
//!     │       └── transparency
//!     ├── summary
//!     └── policies[]
//!         ├── identity
//!         ├── outcome
//!         ├── weight
//!         ├── findings[]
//!         └── observation_refs[]
//! ```
//!
//! ## Schema Version
//!
//! This module implements ESP v2.0.0 Canonical Execution Schema
//! (`docs/09_ESP_Canonical_Schema_v2_0_0.md`). Key structural points:
//! - Polymorphic `HostInfo` with free-string `host_type` discriminator
//! - Top-level `observations[]` on `ResultEnvelope` (evidence as entity)
//! - `PolicyResult.observation_refs[]` replaces inline per-policy `evidence`
//!   (the `evidence` field is retained on `PolicyResult` for the v1.x->v2.x
//!   transition window and will be removed in a follow-up release)
//! - `identity_status` in envelope (required) - PKI bootstrap status
//! - `transparency` in signature block (optional) - CT proof
//!
//! ## Hash Architecture
//!
//! The envelope carries a pre-computed `replay_hash` from `ExecutionManifest`.
//! The hash is computed ONCE during execution and passed through unchanged.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use common::results::{ResultBuilder, AssessorInput, Criticality, Outcome, IdentityStatus};
//!
//! let builder = ResultBuilder::from_system("esp-agent");
//! let identity_status = IdentityStatus::disabled("unsigned:agent:host-abc123");
//!
//! let policies = vec![
//!     AssessorInput::new("policy-1", "linux", Criticality::High, vec![], Outcome::Pass)
//!         .with_findings(findings)
//!         .with_evidence(evidence),
//! ];
//!
//! let package = builder.build_assessor_package(
//!     policies,
//!     manifest.replay_hash,
//!     identity_status,
//! )?;
//! ```

// ============================================================================
// Modules
// ============================================================================

pub mod common;
pub mod crypto;
pub mod error;

pub mod collection_method;
pub mod envelope;
pub mod evidence;
pub mod finding;
pub mod identity;
pub mod identity_status;
pub mod observation;
pub mod summary;
pub mod transparency;

pub mod assessor;
pub mod builder;

// ============================================================================
// Re-exports
// ============================================================================

pub use common::{
    ControlMapping, ControlMappingError, CriteriaCounts, Criticality, Outcome, PolicyOutcome,
    ResultCounts, Weight,
};
pub use error::ResultError;

pub use collection_method::{CollectionMethod, CollectionMethodBuilder, CollectionMethodType};
pub use envelope::{AgentInfo, HostInfo, ResultEnvelope, SignatureBlock, SCHEMA_VERSION};
pub use evidence::{CollectionRecord, Evidence};
pub use finding::{ComplianceFinding, FindingBuilder, FindingSeverity};
pub use identity::PolicyIdentity;
pub use identity_status::{generate_unsigned_signer_id, IdentityStatus};
pub use observation::{HostRef, Observation, ObservationMethod, ObservationRef};
pub use summary::{CriticalityBreakdown, CriticalityStats, ExecutionSummary, ScanSummary};
pub use transparency::{InclusionProof, TransparencyProof};

pub use assessor::{
    AssessorPackage, AssessorPackageBuilder, AssessorPolicyResult, CollectionCommand, PackageInfo,
    ReproducibilityInfo,
};
pub use builder::{AssessorInput, PolicyMetadata, ResultBuilder};

// ============================================================================
// Crypto re-exports
// ============================================================================

pub use crypto::{hash_content, hex_decode, hex_encode, sha256_hash, HashingError};

// ============================================================================
// Type aliases
// ============================================================================

/// Primary result type emitted by the agent. Alias for `AssessorPackage`.
pub type AssessorResult = AssessorPackage;
