//! Full results module with complete evidence
//!
//! **Feature**: `full-results`
//!
//! This module provides types that include complete evidence data:
//! - Expected values (what policy requires)
//! - Actual values (what was found on the system)
//! - Raw collected data
//!
//! ## WARNING: Contains CUI
//!
//! These types contain Controlled Unclassified Information (CUI) including
//! actual system configuration values. Do not transport over untrusted networks.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use common::results::full::{FullResultBuilder, ScanResult};
//!
//! let mut builder = FullResultBuilder::new("scan-001", "agent-1", "daemon");
//!
//! for (metadata, outcome, counts, findings, evidence) in scan_results {
//!     builder.add_policy(&metadata, outcome, counts, findings, evidence)?;
//! }
//!
//! let result: ScanResult = builder.build();
//!
//! // Store locally
//! let json = result.to_json()?;
//! std::fs::write("scan_result.json", json)?;
//! ```
//!
//! ## Use Cases
//!
//! - Local storage for audit trail
//! - Debugging compliance failures
//! - Enterprise features requiring evidence
//! - Incident response investigation

pub mod builder;
pub mod types;

// Re-export main types
pub use builder::{build_finding, build_policy_result, FullResultBuildError, FullResultBuilder};
pub use types::{
    ComplianceFinding, EspMetadata, Evidence, FindingSeverity, HostContext, PolicyResult,
    ResultGenerationError, ScanMetadata, ScanResult, ScanSummary, TimestampInfo, UserContext,
};
