//! Execution Manifest Types
//!
//! The `ExecutionManifest` is the complete output of policy execution, containing
//! all data needed to build any output format (attestation, full-results, assessor-evidence).
//!
//! ## Architecture
//!
//! ```text
//! ExecutionEngine::execute()
//!     └── ExecutionManifest (raw, complete, with canonical hashes)
//!             ├── Policy identity (id, platform, criticality, mappings)
//!             ├── Tree result (logical structure with pass/fail)
//!             ├── Collected data (with CollectionMethod)
//!             ├── Findings (validation failures)
//!             ├── ContentManifest → content_hash (computed ONCE)
//!             └── EvidenceManifest → evidence_hash (computed ONCE)
//!
//!             ↓ Output builders USE these hashes, never recompute ↓
//!
//! ResultBuilder::from_manifest(manifest)
//!     ├── .build_attestation()      → uses manifest.content_hash, manifest.evidence_hash
//!     ├── .build_full_results()     → uses manifest.content_hash, manifest.evidence_hash
//!     └── .build_assessor_results() → uses manifest.content_hash, manifest.evidence_hash
//! ```
//!
//! ## Hash Consistency
//!
//! The `content_hash` and `evidence_hash` are computed ONCE during execution
//! and included in all output formats. This ensures:
//!
//! - Attestations can be verified against full results
//! - Assessor packages can be linked to attestations
//! - SIEM/SOAR can trust attestation hashes

use crate::strategies::{CollectedData, CtnExecutionResult};
use crate::types::canonical_manifest::{ContentManifest, EvidenceManifest};
use crate::types::common::LogicalOp;
use crate::types::criterion::CtnNodeId;
use common::results::{ComplianceFinding, ControlMapping, CriteriaCounts, Criticality, Outcome};
use std::collections::HashMap;

// ============================================================================
// Execution Manifest
// ============================================================================

/// Complete execution output containing all data for any result format
///
/// The manifest is the single source of truth from policy execution.
/// It contains everything needed to build attestations, full results,
/// or assessor-ready results.
///
/// ## Canonical Hashes
///
/// The `content_hash` and `evidence_hash` fields are computed ONCE during
/// execution and must be used by all output builders. This ensures hash
/// consistency across all output formats.
///
/// ```rust,ignore
/// // In output builders - USE the hashes, don't recompute!
/// fn build_attestation(manifest: &ExecutionManifest) -> Attestation {
///     Attestation {
///         content_hash: manifest.content_hash.clone(),   // USE
///         evidence_hash: manifest.evidence_hash.clone(), // USE
///         // ...
///     }
/// }
/// ```
#[derive(Debug, Clone)]
pub struct ExecutionManifest {
    // ========================================================================
    // Policy Identity
    // ========================================================================
    /// Unique policy identifier (from ESP metadata)
    pub policy_id: String,

    /// Target platform (e.g., "kubernetes", "windows", "linux")
    pub platform: String,

    /// Policy criticality level
    pub criticality: Criticality,

    /// Control framework mappings (STIG, CIS, etc.)
    pub control_mappings: Vec<ControlMapping>,

    // ========================================================================
    // Execution Results
    // ========================================================================
    /// Complete tree execution result with logical structure
    ///
    /// Contains the full AND/OR/NOT tree with all CTN results.
    /// Used to determine final pass/fail respecting logical operators.
    pub tree_result: TreeResult,

    /// Aggregated criteria counts (pass/fail/error)
    pub criteria_counts: CriteriaCounts,

    /// Final pass/fail determination from tree logic
    ///
    /// This respects CRI AND/OR/NOT operators, not just flat counting.
    pub tree_passed: bool,

    // ========================================================================
    // Collected Evidence
    // ========================================================================
    /// All collected data from execution, keyed by "{ctn_type}_{object_id}"
    ///
    /// Each `CollectedData` contains:
    /// - `fields`: The actual collected values
    /// - `metadata`: Collection metadata including `method: Option<CollectionMethod>`
    ///
    /// The `CollectionMethod` has full details (command, inputs) that collectors
    /// always populate. Output builders decide what to serialize.
    pub collected_data: HashMap<String, CollectedData>,

    // ========================================================================
    // Findings
    // ========================================================================
    /// Compliance findings for failed validations (CUI)
    ///
    /// Contains expected vs actual values for non-passing criteria.
    pub findings: Vec<ComplianceFinding>,

    // ========================================================================
    // Canonical Manifests & Hashes
    // ========================================================================
    /// Canonical content manifest (what was evaluated)
    ///
    /// This is the deterministic representation of the policy evaluation context.
    /// Used to compute `content_hash`.
    pub content_manifest: ContentManifest,

    /// Canonical evidence manifest (what was observed)
    ///
    /// This is the deterministic representation of collected evidence.
    /// Used to compute `evidence_hash`.
    pub evidence_manifest: EvidenceManifest,

    /// SHA-256 hash of the content manifest
    ///
    /// Computed ONCE during execution. All output formats MUST use this
    /// value directly - never recompute.
    pub content_hash: String,

    /// SHA-256 hash of the evidence manifest
    ///
    /// Computed ONCE during execution. All output formats MUST use this
    /// value directly - never recompute.
    pub evidence_hash: String,

    // ========================================================================
    // Execution Metadata
    // ========================================================================
    /// When execution started (ISO 8601)
    pub executed_at: String,

    /// Total execution duration in milliseconds
    pub execution_duration_ms: u64,
}

impl ExecutionManifest {
    /// Create a new execution manifest
    ///
    /// Note: This creates a manifest with empty hashes. Call `finalize_hashes()`
    /// after populating the manifests, or let `ExecutionEngine::execute()` handle it.
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: Criticality,
    ) -> Self {
        let policy_id_str = policy_id.into();
        let platform_str = platform.into();

        Self {
            policy_id: policy_id_str.clone(),
            platform: platform_str.clone(),
            criticality,
            control_mappings: Vec::new(),
            tree_result: TreeResult::empty(),
            criteria_counts: CriteriaCounts::default(),
            tree_passed: false,
            collected_data: HashMap::new(),
            findings: Vec::new(),
            content_manifest: ContentManifest::new(&policy_id_str, &platform_str),
            evidence_manifest: EvidenceManifest::new(),
            content_hash: String::new(),
            evidence_hash: String::new(),
            executed_at: current_timestamp(),
            execution_duration_ms: 0,
        }
    }

    /// Check if execution passed
    pub fn is_pass(&self) -> bool {
        self.tree_passed
    }

    /// Get the overall outcome
    pub fn outcome(&self) -> Outcome {
        self.tree_result.status
    }

    /// Get total criteria count
    pub fn total_criteria(&self) -> u32 {
        self.criteria_counts.total
    }

    /// Get count of collected objects
    pub fn collected_object_count(&self) -> usize {
        self.collected_data.len()
    }

    /// Get count of findings
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Check if any CTN had collection method recorded
    pub fn has_collection_methods(&self) -> bool {
        self.collected_data.values().any(|data| data.has_method())
    }

    /// Get all CTN results flattened from tree
    pub fn all_ctn_results(&self) -> Vec<&CtnResult> {
        self.tree_result.collect_ctn_results()
    }

    /// Check if canonical hashes have been computed
    ///
    /// Returns false if hashes are empty (manifest not finalized)
    pub fn has_valid_hashes(&self) -> bool {
        !self.content_hash.is_empty() && !self.evidence_hash.is_empty()
    }

    /// Compute and set the canonical hashes from the manifests
    ///
    /// This should be called exactly ONCE after all data is collected.
    /// Typically called by `ExecutionEngine::execute()` before returning.
    pub fn finalize_hashes(&mut self) {
        self.content_hash = self.content_manifest.compute_hash();
        self.evidence_hash = self.evidence_manifest.compute_hash();
    }

    /// Set the content manifest and update hash
    pub fn set_content_manifest(&mut self, manifest: ContentManifest) {
        self.content_manifest = manifest;
        self.content_hash = self.content_manifest.compute_hash();
    }

    /// Set the evidence manifest and update hash
    pub fn set_evidence_manifest(&mut self, manifest: EvidenceManifest) {
        self.evidence_manifest = manifest;
        self.evidence_hash = self.evidence_manifest.compute_hash();
    }
}

// ============================================================================
// Tree Result
// ============================================================================

/// Result of executing a criteria tree node
///
/// Represents either a leaf CTN execution or a logical block (AND/OR/NOT)
/// combining child results. Preserves the full tree structure for accurate
/// pass/fail determination.
#[derive(Debug, Clone)]
pub struct TreeResult {
    /// Outcome of this tree node
    pub status: Outcome,

    /// Logical operator if this is a block (None for leaf nodes)
    pub logical_op: Option<LogicalOp>,

    /// Whether this block is negated (NOT)
    pub negated: bool,

    /// CTN execution results at this level (leaf nodes)
    pub ctn_results: Vec<CtnResult>,

    /// Child tree results (for logical blocks)
    pub child_results: Vec<TreeResult>,
}

impl TreeResult {
    /// Create an empty tree result (for initialization)
    pub fn empty() -> Self {
        Self {
            status: Outcome::Error,
            logical_op: None,
            negated: false,
            ctn_results: Vec::new(),
            child_results: Vec::new(),
        }
    }

    /// Create a leaf result from a single CTN execution
    pub fn leaf(ctn_result: CtnResult) -> Self {
        Self {
            status: ctn_result.status,
            logical_op: None,
            negated: false,
            ctn_results: vec![ctn_result],
            child_results: Vec::new(),
        }
    }

    /// Create a block result from children
    pub fn block(logical_op: LogicalOp, negated: bool, children: Vec<TreeResult>) -> Self {
        let combined_status = Self::apply_logical_op(&children, logical_op);
        let final_status = if negated {
            combined_status.negate()
        } else {
            combined_status
        };

        Self {
            status: final_status,
            logical_op: Some(logical_op),
            negated,
            ctn_results: Vec::new(),
            child_results: children,
        }
    }

    /// Apply logical operator to child results
    fn apply_logical_op(children: &[TreeResult], op: LogicalOp) -> Outcome {
        if children.is_empty() {
            return Outcome::Error;
        }

        match op {
            LogicalOp::And => {
                if children.iter().all(|c| c.status == Outcome::Pass) {
                    Outcome::Pass
                } else if children.iter().any(|c| c.status == Outcome::Error) {
                    Outcome::Error
                } else {
                    Outcome::Fail
                }
            }
            LogicalOp::Or => {
                if children.iter().any(|c| c.status == Outcome::Pass) {
                    Outcome::Pass
                } else if children.iter().all(|c| c.status == Outcome::Error) {
                    Outcome::Error
                } else {
                    Outcome::Fail
                }
            }
        }
    }

    /// Calculate statistics from tree
    pub fn calculate_stats(&self) -> TreeStats {
        let mut stats = TreeStats::default();

        for ctn in &self.ctn_results {
            stats.total += 1;
            match ctn.status {
                Outcome::Pass => stats.passed += 1,
                Outcome::Fail => stats.failed += 1,
                Outcome::Error => stats.errors += 1,
                _ => {}
            }
        }

        for child in &self.child_results {
            let child_stats = child.calculate_stats();
            stats.total += child_stats.total;
            stats.passed += child_stats.passed;
            stats.failed += child_stats.failed;
            stats.errors += child_stats.errors;
        }

        stats
    }

    /// Collect all CTN results from tree (flattened)
    pub fn collect_ctn_results(&self) -> Vec<&CtnResult> {
        let mut results: Vec<&CtnResult> = self.ctn_results.iter().collect();

        for child in &self.child_results {
            results.extend(child.collect_ctn_results());
        }

        results
    }

    /// Check if this is a leaf node (has CTN results)
    pub fn is_leaf(&self) -> bool {
        !self.ctn_results.is_empty()
    }

    /// Check if this is a block node (has children)
    pub fn is_block(&self) -> bool {
        !self.child_results.is_empty()
    }

    /// Get depth of tree
    pub fn depth(&self) -> usize {
        if self.child_results.is_empty() {
            1
        } else {
            1 + self
                .child_results
                .iter()
                .map(|c| c.depth())
                .max()
                .unwrap_or(0)
        }
    }
}

// ============================================================================
// CTN Result
// ============================================================================

/// Result of executing a single CTN (Criterion Type Node)
///
/// Wraps the `CtnExecutionResult` with additional context about
/// where in the tree this execution occurred.
#[derive(Debug, Clone)]
pub struct CtnResult {
    /// Node ID in the criteria tree
    pub ctn_node_id: CtnNodeId,

    /// CTN type (e.g., "file_metadata", "k8s_resource")
    pub criterion_type: String,

    /// Execution outcome
    pub status: Outcome,

    /// Full execution result including collected data
    pub execution_result: CtnExecutionResult,

    /// How long execution took in milliseconds
    pub execution_time_ms: u64,
}

impl CtnResult {
    /// Create a new CTN result
    pub fn new(
        ctn_node_id: CtnNodeId,
        criterion_type: impl Into<String>,
        execution_result: CtnExecutionResult,
        execution_time_ms: u64,
    ) -> Self {
        Self {
            ctn_node_id,
            criterion_type: criterion_type.into(),
            status: execution_result.status,
            execution_result,
            execution_time_ms,
        }
    }

    /// Check if this CTN passed
    pub fn is_pass(&self) -> bool {
        self.status == Outcome::Pass
    }

    /// Get collected data from this CTN execution
    pub fn collected_data(&self) -> &HashMap<String, CollectedData> {
        &self.execution_result.collected_data
    }

    /// Get the message from execution result
    pub fn message(&self) -> &str {
        &self.execution_result.message
    }
}

// ============================================================================
// Tree Statistics
// ============================================================================

/// Aggregated statistics from tree traversal
///
/// Flat counts of criteria by outcome, calculated from tree structure.
#[derive(Debug, Clone, Default)]
pub struct TreeStats {
    /// Total number of criteria executed
    pub total: u32,

    /// Number of criteria that passed
    pub passed: u32,

    /// Number of criteria that failed
    pub failed: u32,

    /// Number of criteria with errors
    pub errors: u32,
}

impl TreeStats {
    /// Create new stats
    pub fn new(total: u32, passed: u32, failed: u32, errors: u32) -> Self {
        Self {
            total,
            passed,
            failed,
            errors,
        }
    }

    /// Calculate pass rate as percentage (0.0 - 100.0)
    pub fn pass_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.passed as f64 / self.total as f64) * 100.0
        }
    }

    /// Check if all criteria passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.errors == 0
    }

    /// Check if any criteria had errors
    pub fn has_errors(&self) -> bool {
        self.errors > 0
    }
}

impl From<TreeStats> for CriteriaCounts {
    fn from(stats: TreeStats) -> Self {
        CriteriaCounts::new(stats.total, stats.passed, stats.failed, stats.errors)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate ISO 8601 timestamp
fn current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();

    // Simple date calculation (approximate, good enough for timestamps)
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Approximate year/month/day (not accounting for leap years perfectly)
    let years = 1970 + (days / 365);
    let day_of_year = days % 365;
    let month = (day_of_year / 30).min(11) + 1;
    let day = (day_of_year % 30) + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        years, month, day, hours, minutes, seconds
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_stats_pass_rate() {
        let stats = TreeStats::new(10, 7, 2, 1);
        assert!((stats.pass_rate() - 70.0).abs() < 0.001);
    }

    #[test]
    fn test_tree_stats_all_passed() {
        let all_pass = TreeStats::new(5, 5, 0, 0);
        assert!(all_pass.all_passed());

        let has_fail = TreeStats::new(5, 4, 1, 0);
        assert!(!has_fail.all_passed());

        let has_error = TreeStats::new(5, 4, 0, 1);
        assert!(!has_error.all_passed());
    }

    #[test]
    fn test_tree_result_empty() {
        let result = TreeResult::empty();
        assert_eq!(result.status, Outcome::Error);
        assert!(result.ctn_results.is_empty());
        assert!(result.child_results.is_empty());
    }

    #[test]
    fn test_tree_result_depth() {
        let leaf = TreeResult::empty();
        assert_eq!(leaf.depth(), 1);

        let nested = TreeResult {
            status: Outcome::Pass,
            logical_op: Some(LogicalOp::And),
            negated: false,
            ctn_results: vec![],
            child_results: vec![
                TreeResult::empty(),
                TreeResult {
                    status: Outcome::Pass,
                    logical_op: Some(LogicalOp::Or),
                    negated: false,
                    ctn_results: vec![],
                    child_results: vec![TreeResult::empty()],
                },
            ],
        };
        assert_eq!(nested.depth(), 3);
    }

    #[test]
    fn test_execution_manifest_new() {
        let manifest = ExecutionManifest::new("test-policy", "linux", Criticality::High);

        assert_eq!(manifest.policy_id, "test-policy");
        assert_eq!(manifest.platform, "linux");
        assert_eq!(manifest.criticality, Criticality::High);
        assert!(!manifest.is_pass());
        assert_eq!(manifest.collected_object_count(), 0);
        assert!(!manifest.has_valid_hashes()); // Hashes not computed yet
    }

    #[test]
    fn test_execution_manifest_finalize_hashes() {
        let mut manifest = ExecutionManifest::new("test-policy", "linux", Criticality::High);

        assert!(!manifest.has_valid_hashes());

        manifest.finalize_hashes();

        assert!(manifest.has_valid_hashes());
        assert!(manifest.content_hash.starts_with("sha256:"));
        assert!(manifest.evidence_hash.starts_with("sha256:"));
    }

    #[test]
    fn test_logical_op_and() {
        let pass1 = TreeResult {
            status: Outcome::Pass,
            logical_op: None,
            negated: false,
            ctn_results: vec![],
            child_results: vec![],
        };
        let pass2 = pass1.clone();
        let fail = TreeResult {
            status: Outcome::Fail,
            ..pass1.clone()
        };

        // AND: all pass = pass
        let result = TreeResult::block(LogicalOp::And, false, vec![pass1.clone(), pass2.clone()]);
        assert_eq!(result.status, Outcome::Pass);

        // AND: any fail = fail
        let result = TreeResult::block(LogicalOp::And, false, vec![pass1.clone(), fail.clone()]);
        assert_eq!(result.status, Outcome::Fail);
    }

    #[test]
    fn test_logical_op_or() {
        let pass = TreeResult {
            status: Outcome::Pass,
            logical_op: None,
            negated: false,
            ctn_results: vec![],
            child_results: vec![],
        };
        let fail = TreeResult {
            status: Outcome::Fail,
            ..pass.clone()
        };

        // OR: any pass = pass
        let result = TreeResult::block(LogicalOp::Or, false, vec![pass.clone(), fail.clone()]);
        assert_eq!(result.status, Outcome::Pass);

        // OR: all fail = fail
        let result = TreeResult::block(LogicalOp::Or, false, vec![fail.clone(), fail.clone()]);
        assert_eq!(result.status, Outcome::Fail);
    }

    #[test]
    fn test_negation() {
        let pass = TreeResult {
            status: Outcome::Pass,
            logical_op: None,
            negated: false,
            ctn_results: vec![],
            child_results: vec![],
        };

        // NOT pass = fail
        let result = TreeResult::block(LogicalOp::And, true, vec![pass.clone()]);
        assert_eq!(result.status, Outcome::Fail);
    }
}
