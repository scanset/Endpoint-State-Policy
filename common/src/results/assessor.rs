//! Assessor Package Result Type
//!
//! The assessor package contains everything an assessor needs to verify
//! and reproduce compliance scan results. This includes:
//!
//! - Full evidence with collection methods (including exact commands)
//! - Policy identity and control mappings
//! - Detailed findings with remediation guidance
//! - Reproducibility information
//!
//! ## Hash Architecture
//!
//! The `replay_hash` is computed ONCE during execution
//! in `ExecutionEngine::execute()` and passed to the builder. The builder
//! does NOT compute the hash - it only accepts the pre-computed value.
//!
//! The replay hash captures intent + contract + outcome rolled up through
//! the CRI tree.
//!
//! ## Identity Status
//!
//! As of schema v1.2.0, all results include an `identity_status` field that
//! indicates whether PKI identity was established. This must be provided
//! when building assessor packages.
//!
//! ## Feature Flags
//!
//! None. As of v2.0.0 this module is always compiled and `CollectionMethod`
//! always serializes `command` + `inputs` when populated.

use serde::{Deserialize, Serialize};

use super::common::Outcome;
use super::envelope::{AgentInfo, HostInfo, ResultEnvelope};
use super::error::ResultError;
use super::evidence::Evidence;
use super::finding::ComplianceFinding;
use super::identity::PolicyIdentity;
use super::identity_status::IdentityStatus;
use super::observation::{Observation, ObservationRef};
use super::summary::ExecutionSummary;

// ============================================================================
// Assessor Package
// ============================================================================

/// Complete assessor package with full evidence and reproducibility info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessorPackage {
    pub envelope: ResultEnvelope,
    pub summary: ExecutionSummary,
    pub policies: Vec<AssessorPolicyResult>,
    pub package_info: PackageInfo,
}

impl AssessorPackage {
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    pub fn all_passed(&self) -> bool {
        self.summary.failed == 0 && self.summary.errors == 0
    }

    pub fn policies_by_outcome(&self, outcome: Outcome) -> Vec<&AssessorPolicyResult> {
        self.policies
            .iter()
            .filter(|p| p.outcome == outcome)
            .collect()
    }

    pub fn failed_policies(&self) -> Vec<&AssessorPolicyResult> {
        self.policies_by_outcome(Outcome::Fail)
    }

    pub fn is_identity_bootstrapped(&self) -> bool {
        self.envelope.identity_status.is_bootstrapped()
    }
}

// ============================================================================
// Package Info
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    pub format_version: String,
    pub generated_at: String,
    pub purpose: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl Default for PackageInfo {
    fn default() -> Self {
        Self {
            format_version: "1.2.0".to_string(),
            generated_at: current_timestamp(),
            purpose: "Compliance assessment verification".to_string(),
            notes: None,
        }
    }
}

impl PackageInfo {
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

// ============================================================================
// Assessor Policy Result
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessorPolicyResult {
    pub identity: PolicyIdentity,
    pub outcome: Outcome,
    pub weight: f32,
    pub findings: Vec<ComplianceFinding>,
    pub evidence: Evidence,
    pub reproducibility: ReproducibilityInfo,
    /// Observations (raw evidence) cited by this policy, by uuid.
    ///
    /// As of v2.0.0, raw evidence lives once at `ResultEnvelope.observations[]`
    /// and policies cite it by uuid here. During the v1.x->v2.x transition the
    /// per-policy `evidence` field is also populated so legacy consumers keep
    /// working; v2.0.0 consumers should prefer resolving these refs against
    /// the envelope's observations array.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observation_refs: Vec<ObservationRef>,
}

impl AssessorPolicyResult {
    pub fn new(
        identity: PolicyIdentity,
        outcome: Outcome,
        weight: f32,
        findings: Vec<ComplianceFinding>,
        evidence: Evidence,
    ) -> Self {
        let reproducibility = ReproducibilityInfo::from_evidence(&evidence);
        Self {
            identity,
            outcome,
            weight,
            findings,
            evidence,
            reproducibility,
            observation_refs: Vec::new(),
        }
    }

    /// Attach observation references. Typically called by the builder after
    /// dedup-aware observation construction (see `ResultBuilder::build_assessor_package`).
    pub fn with_observation_refs(mut self, refs: Vec<ObservationRef>) -> Self {
        self.observation_refs = refs;
        self
    }

    pub fn passed(&self) -> bool {
        self.outcome == Outcome::Pass
    }
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}

// ============================================================================
// Reproducibility Info
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityInfo {
    pub commands: Vec<CollectionCommand>,
    pub requirements: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl ReproducibilityInfo {
    pub fn from_evidence(evidence: &Evidence) -> Self {
        let commands: Vec<CollectionCommand> = evidence
            .collection_metadata
            .iter()
            .filter_map(|record| {
                record.method.as_ref().and_then(|method| {
                    method.command.as_ref().map(|cmd| CollectionCommand {
                        object_id: record.object_id.clone(),
                        method_type: method.method_type.to_string(),
                        command: cmd.clone(),
                        target: method.target.clone(),
                        inputs: method.inputs.clone(),
                    })
                })
            })
            .collect();

        let mut requirements = Vec::new();
        let method_types: std::collections::HashSet<_> = evidence
            .collection_metadata
            .iter()
            .filter_map(|r| r.method.as_ref())
            .map(|m| m.method_type.to_string())
            .collect();

        if method_types.contains("file_read") || method_types.contains("file_stat") {
            requirements.push("File system access to target paths".to_string());
        }
        if method_types.contains("command") {
            requirements.push("Shell access with appropriate permissions".to_string());
        }
        if method_types.contains("api_call") {
            requirements.push("API access with valid credentials".to_string());
        }
        if method_types.contains("socket_inspection") {
            requirements.push("Read access to /proc/net/tcp or equivalent".to_string());
        }

        Self {
            commands,
            requirements,
            notes: None,
        }
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionCommand {
    pub object_id: String,
    pub method_type: String,
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub inputs: std::collections::HashMap<String, String>,
}

// ============================================================================
// Assessor Package Builder
// ============================================================================

/// Builder for constructing AssessorPackage instances
///
/// ## Required Fields
///
/// - `replay_hash` - Pre-computed from ExecutionManifest
/// - `identity_status` - PKI bootstrap status
/// - At least one policy result
///
/// ## Example
///
/// ```rust,ignore
/// let builder = AssessorPackageBuilder::new(agent, host)
///     .with_replay_hash(manifest.replay_hash.clone())
///     .with_identity_status(identity_status);
///
/// builder.add_policy(policy_result);
/// let package = builder.build()?;
/// ```
pub struct AssessorPackageBuilder {
    agent: AgentInfo,
    host: HostInfo,
    policies: Vec<AssessorPolicyResult>,
    replay_hash: Option<String>,
    /// Replay-hash schema version for the hash above. Defaults to `1`
    /// (legacy bundled-objects rollup) so callers that haven't migrated
    /// keep producing exactly the same envelopes as before. Callers
    /// that supply a v2 hash must call `with_replay_hash_version(2)`.
    replay_hash_version: u8,
    identity_status: Option<IdentityStatus>,
    notes: Option<String>,
    observations: Vec<Observation>,
}

impl AssessorPackageBuilder {
    pub fn new(agent: AgentInfo, host: HostInfo) -> Self {
        Self {
            agent,
            host,
            policies: Vec::new(),
            replay_hash: None,
            replay_hash_version: 1,
            identity_status: None,
            notes: None,
            observations: Vec::new(),
        }
    }

    pub fn add_policy(&mut self, policy: AssessorPolicyResult) {
        self.policies.push(policy);
    }

    /// Attach the full observations array that policies' `observation_refs`
    /// will resolve against. Typically called by `ResultBuilder::build_assessor_package`
    /// after dedup-aware construction.
    pub fn with_observations(mut self, observations: Vec<Observation>) -> Self {
        self.observations = observations;
        self
    }

    /// Set the replay hash (pre-computed from ExecutionManifest)
    ///
    /// This hash is computed ONCE in the execution engine and must be
    /// passed through unchanged to ensure consistency.
    pub fn with_replay_hash(mut self, hash: impl Into<String>) -> Self {
        self.replay_hash = Some(hash.into());
        self
    }

    /// Set the replay-hash schema version (`1` legacy, `2` per-CTN-per-OBJECT).
    /// Callers passing a v2 hash MUST call this with `2`; the default is `1`
    /// so legacy callers don't need a code change to keep producing v1 envelopes.
    pub fn with_replay_hash_version(mut self, version: u8) -> Self {
        self.replay_hash_version = version;
        self
    }

    /// Set the identity status
    pub fn with_identity_status(mut self, identity_status: IdentityStatus) -> Self {
        self.identity_status = Some(identity_status);
        self
    }

    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Build the assessor package
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - Both `policies` and `observations` are empty (the envelope would be
    ///   semantically empty — neither a policy attestation nor an observational
    ///   record). Discovery / inline-CTN envelopes legitimately have empty
    ///   `policies` but populated `observations`; that case is allowed.
    /// - `replay_hash` is not set
    /// - `identity_status` is not set
    pub fn build(self) -> Result<AssessorPackage, ResultError> {
        if self.policies.is_empty() && self.observations.is_empty() {
            return Err(ResultError::BuildError(
                "At least one policy result or observation is required".to_string(),
            ));
        }

        let replay_hash = self.replay_hash.ok_or_else(|| {
            ResultError::BuildError(
                "replay_hash is required - must be pre-computed from ExecutionManifest".to_string(),
            )
        })?;

        let identity_status = self.identity_status.ok_or_else(|| {
            ResultError::BuildError("identity_status is required for schema v1.2.0".to_string())
        })?;

        let mut summary = ExecutionSummary::new();
        for policy in &self.policies {
            let passed = policy.outcome == Outcome::Pass;
            summary.record(passed, policy.identity.criticality, policy.weight);
        }

        let envelope = ResultEnvelope::with_identity(self.agent, self.host, identity_status)
            .with_replay_hash(replay_hash)
            .with_replay_hash_version(self.replay_hash_version)
            .with_observations(self.observations);

        let mut package_info = PackageInfo::default();
        if let Some(notes) = self.notes {
            package_info = package_info.with_notes(notes);
        }

        Ok(AssessorPackage {
            envelope,
            summary,
            policies: self.policies,
            package_info,
        })
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;
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

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::results::collection_method::{CollectionMethod, CollectionMethodType};
    use crate::results::evidence::CollectionRecord;
    use crate::results::ControlMapping;
    use crate::results::Criticality;

    fn create_test_evidence() -> Evidence {
        let mut evidence = Evidence::new();
        evidence.add_data("test_obj", serde_json::json!({"field": "value"}));

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Test command")
            .target("/etc/passwd")
            .command("cat /etc/passwd")
            .input("file", "/etc/passwd")
            .build();

        evidence.add_collection_record(
            CollectionRecord::new("test_obj", "file_content", "test_collector").with_method(method),
        );
        evidence
    }

    #[test]
    fn test_assessor_package_builder_with_all_required_fields() {
        let agent = AgentInfo::with_defaults("test-agent");
        let host = HostInfo::from_system();
        let identity_status = IdentityStatus::success("scanset://test/workload");

        let mut builder = AssessorPackageBuilder::new(agent, host)
            .with_replay_hash("sha256:replay123")
            .with_identity_status(identity_status);

        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
        );
        let evidence = create_test_evidence();
        let policy = AssessorPolicyResult::new(identity, Outcome::Pass, 0.8, vec![], evidence);
        builder.add_policy(policy);

        let package = builder.build().unwrap();
        assert_eq!(package.policy_count(), 1);
        assert!(package.all_passed());
        assert_eq!(package.envelope.replay_hash, "sha256:replay123");
        assert!(package.is_identity_bootstrapped());
        assert_eq!(
            package.envelope.identity_status.signer_id,
            "scanset://test/workload"
        );
    }

    #[test]
    fn test_assessor_package_builder_with_failed_identity() {
        let agent = AgentInfo::with_defaults("test-agent");
        let host = HostInfo::from_system();
        let identity_status =
            IdentityStatus::failed("unsigned:agent:test-host", "Timeout", "BOOTSTRAP_TIMEOUT");

        let mut builder = AssessorPackageBuilder::new(agent, host)
            .with_replay_hash("sha256:replay")
            .with_identity_status(identity_status);

        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
        );
        let evidence = create_test_evidence();
        let policy = AssessorPolicyResult::new(identity, Outcome::Pass, 0.8, vec![], evidence);
        builder.add_policy(policy);

        let package = builder.build().unwrap();
        assert!(!package.is_identity_bootstrapped());
        assert!(package.envelope.identity_status.has_error());
        assert_eq!(
            package.envelope.identity_status.error_code(),
            Some("BOOTSTRAP_TIMEOUT")
        );
    }

    #[test]
    fn test_assessor_package_builder_requires_policies() {
        let agent = AgentInfo::with_defaults("test-agent");
        let host = HostInfo::from_system();

        let builder = AssessorPackageBuilder::new(agent, host)
            .with_replay_hash("sha256:replay")
            .with_identity_status(IdentityStatus::default());

        let result = builder.build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("At least one policy result or observation is required"));
    }

    #[test]
    fn test_assessor_package_builder_requires_replay_hash() {
        let agent = AgentInfo::with_defaults("test-agent");
        let host = HostInfo::from_system();

        let mut builder = AssessorPackageBuilder::new(agent, host)
            // Missing replay_hash
            .with_identity_status(IdentityStatus::default());

        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
        );
        let evidence = create_test_evidence();
        let policy = AssessorPolicyResult::new(identity, Outcome::Pass, 0.8, vec![], evidence);
        builder.add_policy(policy);

        let result = builder.build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("replay_hash is required"));
    }

    #[test]
    fn test_assessor_package_builder_requires_identity_status() {
        let agent = AgentInfo::with_defaults("test-agent");
        let host = HostInfo::from_system();

        let mut builder =
            AssessorPackageBuilder::new(agent, host).with_replay_hash("sha256:replay");
        // Missing identity_status

        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
        );
        let evidence = create_test_evidence();
        let policy = AssessorPolicyResult::new(identity, Outcome::Pass, 0.8, vec![], evidence);
        builder.add_policy(policy);

        let result = builder.build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("identity_status is required"));
    }

    #[test]
    fn test_reproducibility_info() {
        let evidence = create_test_evidence();
        let repro = ReproducibilityInfo::from_evidence(&evidence);
        assert_eq!(repro.commands.len(), 1);
        assert_eq!(repro.commands[0].command, "cat /etc/passwd");
        assert!(!repro.requirements.is_empty());
    }

    #[test]
    fn test_package_info_default() {
        let info = PackageInfo::default();
        assert_eq!(info.format_version, "1.2.0");
    }

    #[test]
    fn test_serialization_with_identity_status() {
        let agent = AgentInfo::with_defaults("test-agent");
        let host = HostInfo::from_system();
        let identity_status = IdentityStatus::success("scanset://test");

        let mut builder = AssessorPackageBuilder::new(agent, host)
            .with_replay_hash("sha256:replay")
            .with_identity_status(identity_status);

        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
        );
        let evidence = create_test_evidence();
        let policy = AssessorPolicyResult::new(identity, Outcome::Pass, 0.8, vec![], evidence);
        builder.add_policy(policy);

        let package = builder.build().unwrap();
        let json = serde_json::to_string_pretty(&package).unwrap();

        assert!(json.contains("\"identity_status\":"));
        assert!(json.contains("\"bootstrapped\": true"));

        let parsed: AssessorPackage = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_identity_bootstrapped());
    }
}
