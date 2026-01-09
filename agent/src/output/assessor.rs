//! Assessor package builder
//!
//! Builds complete assessor packages with full reproducibility information.
//! This format includes exact commands and inputs used during collection,
//! allowing assessors to verify and reproduce the scan.

use common::results::{
    AgentInfo, AssessorPackage, AssessorPackageBuilder, AssessorPolicyResult, Criticality,
    Evidence, HostInfo, PolicyIdentity,
};
use contract_kit::execution_api::ScanResult;

use super::OutputError;

/// Build a unified AssessorPackage containing all policy results with full reproducibility info
pub fn build_assessor_package(scan_results: &[ScanResult]) -> Result<AssessorPackage, OutputError> {
    let agent = AgentInfo::with_defaults("esp-agent");
    let host = HostInfo::from_system();
    let mut builder = AssessorPackageBuilder::new(agent, host);

    for scan_result in scan_results {
        let identity = PolicyIdentity::new(
            &scan_result.outcome.policy_id,
            &scan_result.outcome.platform,
            scan_result.outcome.criticality,
            scan_result.outcome.control_mappings.clone(),
        );

        let evidence = scan_result.evidence.clone().unwrap_or_else(Evidence::new);
        let weight = criticality_to_weight(scan_result.outcome.criticality);

        let policy_result = AssessorPolicyResult::new(
            identity,
            scan_result.outcome.outcome,
            weight,
            scan_result.findings.clone(),
            evidence,
        );

        builder.add_policy(policy_result);
    }

    builder
        .build()
        .map_err(|e| OutputError::Build(e.to_string()))
}

/// Convert criticality to default weight
fn criticality_to_weight(criticality: Criticality) -> f32 {
    match criticality {
        Criticality::Critical => 1.0,
        Criticality::High => 0.8,
        Criticality::Medium => 0.5,
        Criticality::Low => 0.3,
        Criticality::Info => 0.1,
    }
}
