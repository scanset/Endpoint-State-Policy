//! # File Metadata Executor
//!
//! Validates file metadata (permissions, owner, group, size, existence).

use common::results::Outcome;
use execution_engine::execution::{
    evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
};
use execution_engine::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::types::common::{Operation, ResolvedValue};
use execution_engine::types::execution_context::ExecutableCriterion;
use std::collections::HashMap;

/// Executor for file_metadata validation
pub struct FileMetadataExecutor {
    contract: CtnContract,
}

impl FileMetadataExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    /// Perform comparison based on operation and data types
    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        operation: Operation,
    ) -> bool {
        match (expected, actual, operation) {
            // String comparisons
            (ResolvedValue::String(exp), ResolvedValue::String(act), Operation::Equals) => {
                exp == act
            }
            (ResolvedValue::String(exp), ResolvedValue::String(act), Operation::NotEqual) => {
                exp != act
            }

            // Boolean comparisons
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), Operation::Equals) => {
                exp == act
            }
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), Operation::NotEqual) => {
                exp != act
            }

            // Integer comparisons
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::Equals) => {
                exp == act
            }
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::NotEqual) => {
                exp != act
            }
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::GreaterThan) => {
                act > exp
            }
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::LessThan) => {
                act < exp
            }
            (
                ResolvedValue::Integer(exp),
                ResolvedValue::Integer(act),
                Operation::GreaterThanOrEqual,
            ) => act >= exp,
            (
                ResolvedValue::Integer(exp),
                ResolvedValue::Integer(act),
                Operation::LessThanOrEqual,
            ) => act <= exp,

            // Type mismatch or unsupported operation
            _ => false,
        }
    }

    /// Format a value for display in error messages
    fn format_value(&self, value: &ResolvedValue) -> String {
        match value {
            ResolvedValue::String(s) => format!("'{}'", s),
            ResolvedValue::Integer(i) => i.to_string(),
            ResolvedValue::Boolean(b) => b.to_string(),
            ResolvedValue::Float(f) => f.to_string(),
            ResolvedValue::Binary(b) => format!("<binary {} bytes>", b.len()),
            ResolvedValue::Collection(items) => format!("<collection {} items>", items.len()),
            ResolvedValue::Version(v) => v.to_string(),
            ResolvedValue::EvrString(e) => e.to_string(),
            ResolvedValue::RecordData(_) => "<record>".to_string(),
        }
    }
}

impl CtnExecutor for FileMetadataExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test_spec = &criterion.test;

        // Phase 1: Existence Check
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

        // Phase 2: State Validation
        let mut state_results = Vec::new();
        let mut failure_messages = Vec::new();

        for (object_id, data) in &collected_data {
            let mut all_field_results = Vec::new();

            // Validate each state
            for state in &criterion.states {
                for field in &state.fields {
                    let data_field_name = self
                        .contract
                        .field_mappings
                        .validation_mappings
                        .state_to_data
                        .get(&field.name)
                        .cloned()
                        .unwrap_or_else(|| field.name.clone());

                    let actual_value = match data.get_field(&data_field_name) {
                        Some(v) => v.clone(),
                        None => {
                            let msg = format!(
                                "Field '{}' (mapped to '{}') not collected",
                                field.name, data_field_name
                            );
                            all_field_results.push(FieldValidationResult {
                                field_name: field.name.clone(),
                                expected_value: field.value.clone(),
                                actual_value: ResolvedValue::String("".to_string()),
                                operation: field.operation,
                                passed: false,
                                message: msg.clone(),
                            });
                            failure_messages.push(format!("Object '{}': {}", object_id, msg));
                            continue;
                        }
                    };

                    // Perform comparison
                    let passed = self.compare_values(&field.value, &actual_value, field.operation);

                    let msg = if passed {
                        format!(
                            "Field '{}' passed: {} {:?} {}",
                            field.name,
                            self.format_value(&actual_value),
                            field.operation,
                            self.format_value(&field.value)
                        )
                    } else {
                        format!(
                            "Field '{}' failed: expected {} {:?} {}, got {}",
                            field.name,
                            self.format_value(&field.value),
                            field.operation,
                            self.format_value(&field.value),
                            self.format_value(&actual_value)
                        )
                    };

                    if !passed {
                        failure_messages.push(format!("Object '{}': {}", object_id, msg));
                    }

                    all_field_results.push(FieldValidationResult {
                        field_name: field.name.clone(),
                        expected_value: field.value.clone(),
                        actual_value,
                        operation: field.operation,
                        passed,
                        message: msg,
                    });
                }
            }

            // Combine field results using state operator (defaults to AND)
            let state_bools: Vec<bool> = all_field_results.iter().map(|r| r.passed).collect();
            let combined = evaluate_state_operator(test_spec.state_operator, &state_bools);

            state_results.push(StateValidationResult {
                object_id: object_id.clone(),
                state_results: all_field_results,
                combined_result: combined,
                state_operator: test_spec.state_operator,
                message: format!(
                    "Object '{}': {} ({} of {} fields passed)",
                    object_id,
                    if combined { "passed" } else { "failed" },
                    state_bools.iter().filter(|&&b| b).count(),
                    state_bools.len()
                ),
            });
        }

        // Phase 3: Item Check
        let objects_passing = state_results.iter().filter(|r| r.combined_result).count();
        let item_passed =
            evaluate_item_check(test_spec.item_check, objects_passing, state_results.len());

        // Final result
        let final_status = if existence_passed && item_passed {
            Outcome::Pass
        } else {
            Outcome::Fail
        };

        // Build detailed message
        let message = if final_status == Outcome::Pass {
            format!(
                "File metadata validation passed: {} of {} objects compliant",
                objects_passing,
                state_results.len()
            )
        } else if !failure_messages.is_empty() {
            format!(
                "File metadata validation failed:\n  - {}",
                failure_messages.join("\n  - ")
            )
        } else {
            format!(
                "File metadata validation failed: {} of {} objects compliant (item check failed)",
                objects_passing,
                state_results.len()
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
                "objects_expected": objects_expected,
                "objects_found": objects_found,
                "objects_passing": objects_passing,
                "test_specification": {
                    "existence_check": format!("{:?}", test_spec.existence_check),
                    "item_check": format!("{:?}", test_spec.item_check),
                    "state_operator": format!("{:?}", test_spec.state_operator),
                }
            }),
            execution_metadata: Default::default(),
            collected_data,
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "file_metadata"
    }

    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        // Validate that required fields are present
        for data in collected_data.values() {
            for required_field in &self
                .contract
                .field_mappings
                .collection_mappings
                .required_data_fields
            {
                if !data.has_field(required_field) {
                    return Err(CtnExecutionError::MissingDataField {
                        field: required_field.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}
