//! Summary builder
//!
//! Builds minimal summary output with pass/fail counts.

use contract_kit::execution_api::ScanResult;

/// Build a unified summary JSON from all scan results
pub fn build_summary(scan_results: &[ScanResult]) -> serde_json::Value {
    let mut total_passed = 0;
    let mut total_failed = 0;
    let mut policies = Vec::new();

    for result in scan_results {
        if result.tree_passed {
            total_passed += 1;
        } else {
            total_failed += 1;
        }

        policies.push(build_policy_summary(result));
    }

    serde_json::json!({
        "agent": {
            "id": "esp-agent",
            "name": "esp-agent",
            "version": env!("CARGO_PKG_VERSION")
        },
        "summary": {
            "total_policies": scan_results.len(),
            "passed": total_passed,
            "failed": total_failed
        },
        "policies": policies
    })
}

/// Build summary for a single policy
fn build_policy_summary(result: &ScanResult) -> serde_json::Value {
    serde_json::json!({
        "policy_id": result.outcome.policy_id,
        "platform": result.outcome.platform,
        "passed": result.tree_passed,
        "outcome": format!("{:?}", result.outcome.outcome),
        "criticality": format!("{:?}", result.outcome.criticality),
        "criteria_counts": {
            "total": result.criteria_counts.total,
            "passed": result.criteria_counts.passed,
            "failed": result.criteria_counts.failed,
            "error": result.criteria_counts.error
        },
        "findings_count": result.findings.len()
    })
}
