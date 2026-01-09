//! Attestation builder
//!
//! Builds CUI-free attestation results for network transport.

use common::results::{AttestationResult, CheckInput, Evidence, ResultBuilder};
use contract_kit::execution_api::ScanResult;

use super::OutputError;

/// Build a unified AttestationResult containing all check attestations in a single envelope
pub fn build_attestation(scan_results: &[ScanResult]) -> Result<AttestationResult, OutputError> {
    let result_builder = ResultBuilder::from_system("esp-agent");

    // Convert all scan results to CheckInput
    let checks: Vec<CheckInput> = scan_results
        .iter()
        .map(|scan_result| {
            CheckInput::new(
                &scan_result.outcome.policy_id,
                &scan_result.outcome.platform,
                scan_result.outcome.criticality,
                scan_result.outcome.control_mappings.clone(),
                scan_result.outcome.outcome,
            )
        })
        .collect();

    // Compute combined evidence hash from all evidence
    let mut combined_evidence = Evidence::new();
    for scan_result in scan_results {
        if let Some(evidence) = &scan_result.evidence {
            combined_evidence.merge(evidence.clone());
        }
    }
    let evidence_hash = combined_evidence.compute_hash().ok();

    result_builder
        .build_attestation(checks, evidence_hash)
        .map_err(|e| e.into())
}
