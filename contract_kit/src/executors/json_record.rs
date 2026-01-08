//! JSON record executor
//!
//! Validates structured JSON data using record checks.

use common::results::Outcome;
use execution_engine::execution::{
    evaluate_existence_check, evaluate_item_check, record_validation::validate_record_checks,
};
use execution_engine::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::types::common::{Operation, ResolvedValue};
use execution_engine::types::execution_context::ExecutableCriterion;
use std::collections::HashMap;

pub struct JsonRecordExecutor {
    contract: CtnContract,
}

impl JsonRecordExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }
}

impl CtnExecutor for JsonRecordExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test_spec = &criterion.test;

        // Phase 1: Existence check
        let objects_expected = criterion.expected_object_count();
        let objects_found = collected_data.len();

        let existence_passed =
            evaluate_existence_check(test_spec.existence_check, objects_found, objects_expected);

        if !existence_passed {
            return Ok(CtnExecutionResult::fail(
                criterion.criterion_type.clone(),
                format!(
                    "Existence check failed: expected {} objects, found {}",
                    objects_expected, objects_found
                ),
            )
            .with_collected_data(collected_data));
        }

        // Phase 2: State validation with record checks
        let mut state_results = Vec::new();
        let mut failure_messages = Vec::new();

        for (object_id, data) in &collected_data {
            // Extract RecordData from collected data
            let record_data = match data.get_field("json_data") {
                Some(ResolvedValue::RecordData(rd)) => rd,
                Some(_) => {
                    return Err(CtnExecutionError::DataValidationFailed {
                        reason: "json_data field is not RecordData".to_string(),
                    });
                }
                None => {
                    return Err(CtnExecutionError::MissingDataField {
                        field: "json_data".to_string(),
                    });
                }
            };

            // Validate all states for this object
            for state in &criterion.states {
                // Validate record checks if present
                if !state.record_checks.is_empty() {
                    // FIXED: Use validate_record_checks from base library
                    let validation_results =
                        validate_record_checks(record_data, &state.record_checks).map_err(|e| {
                            CtnExecutionError::ExecutionFailed {
                                ctn_type: criterion.criterion_type.clone(),
                                reason: format!("Record validation failed: {}", e),
                            }
                        })?;

                    // Convert to FieldValidationResult format
                    let field_results: Vec<FieldValidationResult> = validation_results
                        .iter()
                        .map(|r| FieldValidationResult {
                            field_name: r.field_path.clone(),
                            expected_value: ResolvedValue::String(
                                r.expected.clone().unwrap_or_default(),
                            ),
                            actual_value: ResolvedValue::String(
                                r.actual.clone().unwrap_or_default(),
                            ),
                            operation: Operation::Equals,
                            passed: r.passed,
                            message: r.message.clone(),
                        })
                        .collect();

                    // Check if all validations passed
                    let all_passed = validation_results.iter().all(|r| r.passed);

                    if !all_passed {
                        for result in &validation_results {
                            if !result.passed {
                                failure_messages
                                    .push(format!("Object '{}': {}", object_id, result.message));
                            }
                        }
                    }

                    state_results.push(StateValidationResult {
                        object_id: object_id.clone(),
                        state_results: field_results,
                        combined_result: all_passed,
                        state_operator: test_spec.state_operator,
                        message: format!(
                            "Object '{}': {} ({} of {} checks passed)",
                            object_id,
                            if all_passed { "passed" } else { "failed" },
                            validation_results.iter().filter(|r| r.passed).count(),
                            validation_results.len()
                        ),
                    });
                }
            }
        }

        // Phase 3: Item check
        let objects_passing = state_results.iter().filter(|r| r.combined_result).count();
        let item_passed =
            evaluate_item_check(test_spec.item_check, objects_passing, state_results.len());

        let final_status = if existence_passed && item_passed {
            Outcome::Pass
        } else {
            Outcome::Fail
        };

        let message = if final_status == Outcome::Pass {
            format!(
                "JSON record validation passed: {} of {} objects compliant",
                objects_passing,
                state_results.len()
            )
        } else {
            format!(
                "JSON record validation failed:\n  - {}",
                failure_messages.join("\n  - ")
            )
        };

        Ok(CtnExecutionResult {
            ctn_type: criterion.criterion_type.clone(),
            status: final_status,
            test_phase: TestPhase::Complete,
            existence_result: None,
            state_results,
            item_check_result: None,
            message,
            details: serde_json::json!({
                "failures": failure_messages,
                "objects_passing": objects_passing,
            }),
            execution_metadata: Default::default(),
            collected_data,
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "json_record"
    }

    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        for data in collected_data.values() {
            if !data.has_field("json_data") {
                return Err(CtnExecutionError::MissingDataField {
                    field: "json_data".to_string(),
                });
            }
        }
        Ok(())
    }
}
