//! Full result builder
//!
//! Builds complete results with findings and evidence.

use common::results::{Evidence, FullResult, PolicyInput, ResultBuilder};
use contract_kit::execution_api::ScanResult;

use super::OutputError;

/// Build a unified FullResult containing all policy results in a single envelope
pub fn build_full_result(scan_results: &[ScanResult]) -> Result<FullResult, OutputError> {
    let result_builder = ResultBuilder::from_system("esp-agent");

    // Convert all scan results to PolicyInput
    let policies: Vec<PolicyInput> = scan_results
        .iter()
        .map(|scan_result| {
            let evidence = scan_result.evidence.clone().unwrap_or_else(Evidence::new);

            PolicyInput::new(
                &scan_result.outcome.policy_id,
                &scan_result.outcome.platform,
                scan_result.outcome.criticality,
                scan_result.outcome.control_mappings.clone(),
                scan_result.outcome.outcome,
            )
            .with_findings(scan_result.findings.clone())
            .with_evidence(evidence)
        })
        .collect();

    result_builder
        .build_full_result(policies)
        .map_err(|e| e.into())
}
