//! Unified result builder interface
//!
//! Single entry point for building results from `ExecutionManifest`. As of
//! v2.0.0 the agent emits one shape — `AssessorPackage` — so this module
//! exposes `ResultBuilder::build_assessor_package` and its input type
//! `AssessorInput`. The attestation / full-results variants that existed
//! in v1.x are removed.
//!
//! ## Hash Architecture
//!
//! `build_assessor_package` requires a pre-computed `replay_hash` from the
//! `ExecutionManifest`. The hash is computed ONCE during execution and
//! passed through unchanged — the builder never re-hashes.
//!
//! ## Identity Status
//!
//! As of schema v1.2.0, the build method requires an `identity_status`
//! parameter that indicates whether PKI identity was established during
//! bootstrap.

use std::collections::HashMap;

use super::assessor::{AssessorPackage, AssessorPackageBuilder, AssessorPolicyResult};
use super::collection_method::{CollectionMethod, CollectionMethodType};
use super::common::{ControlMapping, Criticality, Outcome};
use super::crypto::hash_content;
use super::envelope::{AgentInfo, HostInfo};
use super::error::ResultError;
use super::evidence::Evidence;
use super::finding::ComplianceFinding;
use super::identity::PolicyIdentity;
use super::identity_status::IdentityStatus;
use super::observation::{Observation, ObservationMethod, ObservationRef};

// ============================================================================
// Policy Metadata
// ============================================================================

/// Extended policy metadata for building `PolicyIdentity`.
///
/// Contains all the optional and extended fields from the META block.
#[derive(Debug, Clone, Default)]
pub struct PolicyMetadata {
    /// Policy version/revision
    pub version: Option<String>,
    /// DSL schema version
    pub dsl_schema_version: Option<String>,
    /// Policy title
    pub title: Option<String>,
    /// Policy description
    pub description: Option<String>,
    /// Policy author
    pub author: Option<String>,
    /// Policy tags
    pub tags: Vec<String>,
    /// Extended metadata (framework-specific fields)
    pub extended: HashMap<String, String>,
}

impl PolicyMetadata {
    /// Create empty metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Set version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set DSL schema version
    pub fn with_dsl_schema_version(mut self, version: impl Into<String>) -> Self {
        self.dsl_schema_version = Some(version.into());
        self
    }

    /// Set title
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set author
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Set tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Set extended metadata (replaces existing)
    pub fn with_extended(mut self, extended: HashMap<String, String>) -> Self {
        self.extended = extended;
        self
    }

    /// Add a single extended metadata field
    pub fn with_extended_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extended.insert(key.into(), value.into());
        self
    }

    /// Check if metadata has any content
    pub fn is_empty(&self) -> bool {
        self.version.is_none()
            && self.dsl_schema_version.is_none()
            && self.title.is_none()
            && self.description.is_none()
            && self.author.is_none()
            && self.tags.is_empty()
            && self.extended.is_empty()
    }

    /// Apply this metadata to a `PolicyIdentity`
    pub fn apply_to(self, mut identity: PolicyIdentity) -> PolicyIdentity {
        if let Some(v) = self.version {
            identity.version = Some(v);
        }
        if let Some(v) = self.dsl_schema_version {
            identity.dsl_schema_version = Some(v);
        }
        if let Some(v) = self.title {
            identity.title = Some(v);
        }
        if let Some(v) = self.description {
            identity.description = Some(v);
        }
        if let Some(v) = self.author {
            identity.author = Some(v);
        }
        if !self.tags.is_empty() {
            identity.tags = self.tags;
        }
        if !self.extended.is_empty() {
            identity.metadata = self.extended;
        }
        identity
    }
}

// ============================================================================
// Result Builder
// ============================================================================

/// Unified result builder.
///
/// As of v2.0.0 the only emitted shape is `AssessorPackage`.
///
/// ```rust,ignore
/// let builder = ResultBuilder::from_system("esp-agent");
/// let identity_status = IdentityStatus::disabled("unsigned:agent:host-abc");
///
/// let package = builder.build_assessor_package(
///     policies,
///     manifest.replay_hash.clone(),
///     identity_status,
/// )?;
/// ```
pub struct ResultBuilder {
    agent: AgentInfo,
    host: HostInfo,
}

impl ResultBuilder {
    /// Create a new result builder
    pub fn new(agent: AgentInfo, host: HostInfo) -> Self {
        Self { agent, host }
    }

    /// Create with default agent and host from system.
    ///
    /// Prefer `::new(agent, channel.identify_host()?)` in production: the
    /// channel knows the target's provider context (azure.vm, aws.account,
    /// ...), whereas `from_system()` always describes the agent's own
    /// local machine.
    pub fn from_system(agent_id: impl Into<String>) -> Self {
        Self {
            agent: AgentInfo::with_defaults(agent_id),
            host: HostInfo::from_system(),
        }
    }

    /// Build an assessor package.
    ///
    /// ## Arguments
    ///
    /// * `policies` - The policy results with full evidence and collection details
    /// * `replay_hash` - Pre-computed replay hash from `ExecutionManifest`
    /// * `identity_status` - PKI bootstrap status
    pub fn build_assessor_package(
        self,
        policies: Vec<AssessorInput>,
        replay_hash: String,
        identity_status: IdentityStatus,
    ) -> Result<AssessorPackage, ResultError> {
        let host_ref = self.host.as_ref();

        let mut builder = AssessorPackageBuilder::new(self.agent, self.host)
            .with_replay_hash(replay_hash)
            .with_identity_status(identity_status);

        // Global dedup across all policies: (method_kind, target, content_hash) -> uuid.
        // Keeps the envelope's observations[] free of duplicates when multiple
        // policies cite the same underlying read.
        let mut dedup: HashMap<(String, String, String), String> = HashMap::new();
        let mut all_observations: Vec<Observation> = Vec::new();

        for policy in policies {
            let identity = policy.to_policy_identity();
            let mut refs: Vec<ObservationRef> = Vec::new();

            for record in &policy.evidence.collection_metadata {
                // The execution engine stores `evidence.data` keyed on
                // `object.identifier`, which is the composite
                // `"{ctn_type}_{object_id}"` form. `CollectionRecord.object_id`
                // carries the bare form. Try the composite first, then fall
                // back to the bare form so hand-built Evidence (unit tests,
                // alternate pipelines) still works.
                let composite_key = format!("{}_{}", record.ctn_type, record.object_id);
                let body = match policy
                    .evidence
                    .data
                    .get(&composite_key)
                    .or_else(|| policy.evidence.data.get(&record.object_id))
                {
                    Some(b) => b,
                    None => continue,
                };

                let content_hash = match hash_content(body) {
                    Ok(h) => format!("sha256:{}", h),
                    Err(_) => continue,
                };

                let obs_method =
                    map_collection_to_observation_method(record.method.as_ref(), &record.object_id);
                let target_key = record
                    .method
                    .as_ref()
                    .and_then(|m| m.target.clone())
                    .unwrap_or_else(|| record.object_id.clone());
                let dedup_key = (obs_method.kind.clone(), target_key, content_hash.clone());

                let uuid = if let Some(existing) = dedup.get(&dedup_key) {
                    existing.clone()
                } else {
                    let obs = Observation::new(host_ref.clone(), obs_method, content_hash)
                        .with_body(body.clone());
                    let uuid = obs.uuid.clone();
                    dedup.insert(dedup_key, uuid.clone());
                    all_observations.push(obs);
                    uuid
                };

                refs.push(ObservationRef::new(uuid));
            }

            let result = AssessorPolicyResult::new(
                identity,
                policy.outcome,
                policy.weight,
                policy.findings,
                policy.evidence,
            )
            .with_observation_refs(refs);
            builder.add_policy(result);
        }

        builder = builder.with_observations(all_observations);
        builder.build()
    }
}

// ============================================================================
// CollectionMethod -> ObservationMethod mapping
// ============================================================================

/// Translate a v1.x `CollectionMethod` into a v2.0.0 `ObservationMethod`.
///
/// The `kind` string follows the v2.0.0 recommended vocabulary
/// (`file_read`, `exec`, `http`, `sdk_call`, ...). Method-specific details
/// (paths, commands, endpoints) are preserved in `params` so the
/// reproducibility block can still reconstruct the original operation.
/// `inputs` are copied as string-valued params (without clobbering any
/// param already set by the kind-specific shaping).
fn map_collection_to_observation_method(
    method: Option<&CollectionMethod>,
    object_id: &str,
) -> ObservationMethod {
    let Some(m) = method else {
        return ObservationMethod::new("collected")
            .with_param("object_id", serde_json::Value::String(object_id.to_string()));
    };

    let target_value = m.target.clone().unwrap_or_else(|| object_id.to_string());

    let mut obs_method = match &m.method_type {
        CollectionMethodType::Command => {
            let mut om = ObservationMethod::new("exec");
            if let Some(cmd) = &m.command {
                om = om.with_param("command", serde_json::Value::String(cmd.clone()));
            }
            if let Some(target) = &m.target {
                om = om.with_param("target", serde_json::Value::String(target.clone()));
            }
            om
        }
        CollectionMethodType::FileRead => ObservationMethod::file_read(target_value.clone()),
        CollectionMethodType::FileStat => ObservationMethod::new("file_stat")
            .with_param("path", serde_json::Value::String(target_value.clone())),
        CollectionMethodType::ApiCall => ObservationMethod::new("api_call")
            .with_param("endpoint", serde_json::Value::String(target_value.clone())),
        CollectionMethodType::RegistryQuery => ObservationMethod::new("registry_read")
            .with_param("key", serde_json::Value::String(target_value.clone())),
        CollectionMethodType::WmiQuery => ObservationMethod::new("wmi_query")
            .with_param("query", serde_json::Value::String(target_value.clone())),
        CollectionMethodType::ProcessInspection => ObservationMethod::new("process_inspection")
            .with_param("target", serde_json::Value::String(target_value.clone())),
        CollectionMethodType::SocketInspection => ObservationMethod::new("socket_inspection")
            .with_param("target", serde_json::Value::String(target_value.clone())),
        CollectionMethodType::Computed => ObservationMethod::new("computed")
            .with_param("object_id", serde_json::Value::String(object_id.to_string())),
        CollectionMethodType::Custom(s) => ObservationMethod::new(s.clone())
            .with_param("target", serde_json::Value::String(target_value.clone())),
    };

    for (k, v) in &m.inputs {
        if !obs_method.params.contains_key(k) {
            obs_method = obs_method.with_param(k.clone(), serde_json::Value::String(v.clone()));
        }
    }

    obs_method
}


// ============================================================================
// Input Type
// ============================================================================

/// Input for building a single policy entry in an `AssessorPackage`.
#[derive(Debug, Clone)]
pub struct AssessorInput {
    pub policy_id: String,
    pub platform: String,
    pub criticality: Criticality,
    pub control_mappings: Vec<ControlMapping>,
    pub outcome: Outcome,
    pub weight: f32,
    pub metadata: PolicyMetadata,
    pub findings: Vec<ComplianceFinding>,
    pub evidence: Evidence,
}

impl AssessorInput {
    /// Create a new assessor input
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
        outcome: Outcome,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            platform: platform.into(),
            criticality,
            control_mappings,
            outcome,
            weight: criticality.default_weight(),
            metadata: PolicyMetadata::default(),
            findings: Vec::new(),
            evidence: Evidence::new(),
        }
    }

    /// Set explicit weight
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
    }

    /// Set policy metadata
    pub fn with_metadata(mut self, metadata: PolicyMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set findings
    pub fn with_findings(mut self, findings: Vec<ComplianceFinding>) -> Self {
        self.findings = findings;
        self
    }

    /// Set evidence
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence = evidence;
        self
    }

    /// Convert to `PolicyIdentity` (borrows self, clones necessary data)
    pub fn to_policy_identity(&self) -> PolicyIdentity {
        let identity = PolicyIdentity::new(
            self.policy_id.clone(),
            self.platform.clone(),
            self.criticality,
            self.control_mappings.clone(),
        );
        self.metadata.clone().apply_to(identity)
    }
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

    #[test]
    fn test_policy_metadata_builder() {
        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_title("Test Policy")
            .with_tags(vec!["baseline".to_string()])
            .with_extended_field("control_objective", "CM-6_obj.1");

        assert_eq!(metadata.version, Some("1.0.0".to_string()));
        assert_eq!(metadata.title, Some("Test Policy".to_string()));
        assert_eq!(metadata.tags, vec!["baseline"]);
        assert_eq!(
            metadata.extended.get("control_objective"),
            Some(&"CM-6_obj.1".to_string())
        );
    }

    #[test]
    fn test_policy_metadata_is_empty() {
        let empty = PolicyMetadata::new();
        assert!(empty.is_empty());

        let with_version = PolicyMetadata::new().with_version("1.0.0");
        assert!(!with_version.is_empty());

        let with_extended = PolicyMetadata::new().with_extended_field("key", "value");
        assert!(!with_extended.is_empty());
    }

    #[test]
    fn test_policy_metadata_apply_to() {
        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_title("Test Policy")
            .with_extended_field("assessment_method", "TEST");

        let identity = PolicyIdentity::new("policy-1", "linux", Criticality::High, vec![]);
        let updated = metadata.apply_to(identity);

        assert_eq!(updated.version, Some("1.0.0".to_string()));
        assert_eq!(updated.title, Some("Test Policy".to_string()));
        assert_eq!(updated.get_meta("assessment_method"), Some("TEST"));
    }

    #[test]
    fn test_build_assessor_package_wires_observations() {
        use crate::results::collection_method::{CollectionMethod, CollectionMethodType};
        use crate::results::evidence::{CollectionRecord, Evidence};

        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::disabled("unsigned:agent:test");

        // Two policies both citing the same /etc/os-release read: should
        // dedup to a single Observation with two refs.
        let mut ev1 = Evidence::new();
        ev1.add_data("os_release", serde_json::json!({"NAME": "Rocky Linux"}));
        ev1.add_collection_record(
            CollectionRecord::new("os_release", "file_content", "os_collector").with_method(
                CollectionMethod::builder()
                    .method_type(CollectionMethodType::FileRead)
                    .target("/etc/os-release")
                    .build(),
            ),
        );

        let mut ev2 = Evidence::new();
        ev2.add_data("os_release", serde_json::json!({"NAME": "Rocky Linux"}));
        ev2.add_collection_record(
            CollectionRecord::new("os_release", "file_content", "os_collector").with_method(
                CollectionMethod::builder()
                    .method_type(CollectionMethodType::FileRead)
                    .target("/etc/os-release")
                    .build(),
            ),
        );

        let policies = vec![
            AssessorInput::new(
                "policy-a",
                "linux",
                Criticality::High,
                vec![ControlMapping::new("CIS", "1.1.1")],
                Outcome::Pass,
            )
            .with_evidence(ev1),
            AssessorInput::new(
                "policy-b",
                "linux",
                Criticality::High,
                vec![ControlMapping::new("CIS", "1.1.2")],
                Outcome::Pass,
            )
            .with_evidence(ev2),
        ];

        let pkg = builder
            .build_assessor_package(policies, "sha256:replay".to_string(), identity_status)
            .unwrap();

        // Dedup: one Observation, cited twice.
        assert_eq!(pkg.envelope.observations.len(), 1);
        let obs = &pkg.envelope.observations[0];
        assert_eq!(obs.method.kind, "file_read");
        assert!(obs.content_hash.starts_with("sha256:"));
        assert!(obs.body.is_some());

        // Each policy carries exactly one ObservationRef and both point at
        // the same uuid.
        assert_eq!(pkg.policies.len(), 2);
        assert_eq!(pkg.policies[0].observation_refs.len(), 1);
        assert_eq!(pkg.policies[1].observation_refs.len(), 1);
        assert_eq!(
            pkg.policies[0].observation_refs[0].uuid,
            pkg.policies[1].observation_refs[0].uuid
        );
        assert_eq!(pkg.policies[0].observation_refs[0].uuid, obs.uuid);
    }

    #[test]
    fn test_build_assessor_package_composite_data_key() {
        // Regression: the live execution engine inserts evidence.data under
        // `"{ctn_type}_{object_id}"` (object.identifier), while
        // CollectionRecord.object_id is the bare form. The derivation must
        // resolve the composite key, not the bare one.
        use crate::results::collection_method::{CollectionMethod, CollectionMethodType};
        use crate::results::evidence::{CollectionRecord, Evidence};

        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::disabled("unsigned:agent:test");

        let mut ev = Evidence::new();
        // Composite key as produced by the engine:
        ev.add_data(
            "crypto_policy_crypto_check",
            serde_json::json!({"active_policy": "FIPS"}),
        );
        // Record carries the BARE object_id + the ctn_type separately:
        ev.add_collection_record(
            CollectionRecord::new("crypto_check", "crypto_policy", "crypto-policy-collector")
                .with_method(
                    CollectionMethod::builder()
                        .method_type(CollectionMethodType::Command)
                        .command("update-crypto-policies --check")
                        .target("update-crypto-policies")
                        .build(),
                ),
        );

        let policies = vec![AssessorInput::new(
            "policy-fips",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("KSI", "AFR-UCM")],
            Outcome::Pass,
        )
        .with_evidence(ev)];

        let pkg = builder
            .build_assessor_package(policies, "sha256:replay".to_string(), identity_status)
            .unwrap();

        assert_eq!(
            pkg.envelope.observations.len(),
            1,
            "composite-key lookup must resolve evidence.data[\"crypto_policy_crypto_check\"] \
             from record.ctn_type + record.object_id"
        );
        assert_eq!(pkg.policies[0].observation_refs.len(), 1);
        assert_eq!(pkg.envelope.observations[0].method.kind, "exec");
    }

    #[test]
    fn test_build_assessor_package_distinct_methods_no_dedup() {
        use crate::results::collection_method::{CollectionMethod, CollectionMethodType};
        use crate::results::evidence::{CollectionRecord, Evidence};

        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::disabled("unsigned:agent:test");

        let mut ev = Evidence::new();
        ev.add_data("os_release", serde_json::json!({"NAME": "Rocky Linux"}));
        ev.add_collection_record(
            CollectionRecord::new("os_release", "file_content", "c1").with_method(
                CollectionMethod::builder()
                    .method_type(CollectionMethodType::FileRead)
                    .target("/etc/os-release")
                    .build(),
            ),
        );
        // Different method against the same object_id: must not dedup.
        ev.add_data("rpm", serde_json::json!(["openssl-3.0.7-1"]));
        ev.add_collection_record(
            CollectionRecord::new("rpm", "rpm_package", "c2").with_method(
                CollectionMethod::builder()
                    .method_type(CollectionMethodType::Command)
                    .command("rpm -qa openssl")
                    .target("openssl")
                    .build(),
            ),
        );

        let policies = vec![AssessorInput::new(
            "policy-a",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )
        .with_evidence(ev)];

        let pkg = builder
            .build_assessor_package(policies, "sha256:replay".to_string(), identity_status)
            .unwrap();

        assert_eq!(pkg.envelope.observations.len(), 2);
        let kinds: Vec<_> = pkg
            .envelope
            .observations
            .iter()
            .map(|o| o.method.kind.as_str())
            .collect();
        assert!(kinds.contains(&"file_read"));
        assert!(kinds.contains(&"exec"));
        assert_eq!(pkg.policies[0].observation_refs.len(), 2);
    }

    #[test]
    fn test_build_assessor_package() {
        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::disabled("unsigned:agent:test");

        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_extended_field("responsible_role", "system-admin");

        let policies = vec![AssessorInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )
        .with_metadata(metadata)];

        let result = builder
            .build_assessor_package(policies, "sha256:replay123".to_string(), identity_status)
            .unwrap();

        assert_eq!(result.policy_count(), 1);
        assert!(result.all_passed());
        assert_eq!(result.envelope.replay_hash, "sha256:replay123");
        assert!(!result.is_identity_bootstrapped());
        assert!(result.envelope.identity_status.is_disabled());
    }
}
