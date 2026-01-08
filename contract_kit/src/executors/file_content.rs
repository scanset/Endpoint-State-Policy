//! # File Content Executor
//!
//! Validates file content with string operations (contains, starts, ends, pattern_match).

use common::results::Outcome;
use execution_engine::execution::{
    comparisons::string, evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
};
use execution_engine::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::types::common::{Operation, ResolvedValue};
use execution_engine::types::execution_context::ExecutableCriterion;
use std::collections::HashMap;

/// Executor for file_content validation
pub struct FileContentExecutor {
    contract: CtnContract,
}

impl FileContentExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    /// Compare string operations using base comparison logic
    fn compare_string_operation(&self, expected: &str, actual: &str, operation: Operation) -> bool {
        // FIXED: Use the base string comparison module
        match string::compare(actual, expected, operation) {
            Ok(result) => result,
            Err(e) => {
                // Log the error and return false
                eprintln!("String comparison error: {}", e);
                false
            }
        }
    }

    /// Create a preview of content for error messages (truncated if needed)
    fn preview_content(&self, content: &str, max_len: usize) -> String {
        if content.len() <= max_len {
            content.to_string()
        } else {
            format!("{}... ({} chars total)", &content[..max_len], content.len())
        }
    }
}

impl CtnExecutor for FileContentExecutor {
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
            // Get file content
            let content = match data.get_field("file_content") {
                Some(ResolvedValue::String(c)) => c.clone(),
                Some(_) => {
                    return Err(CtnExecutionError::DataValidationFailed {
                        reason: "file_content field is not a string".to_string(),
                    });
                }
                None => {
                    return Err(CtnExecutionError::MissingDataField {
                        field: "file_content".to_string(),
                    });
                }
            };

            let mut all_field_results = Vec::new();

            // Validate each state
            for state in &criterion.states {
                for field in &state.fields {
                    // For content validation, field.name should be "content"
                    if field.name != "content" {
                        continue;
                    }

                    // Extract expected value as string
                    let expected = match &field.value {
                        ResolvedValue::String(s) => s.as_str(),
                        _ => {
                            let msg = format!(
                                "Expected value for field '{}' must be a string, got {:?}",
                                field.name, field.value
                            );
                            all_field_results.push(FieldValidationResult {
                                field_name: field.name.clone(),
                                expected_value: field.value.clone(),
                                actual_value: ResolvedValue::String(content.clone()),
                                operation: field.operation,
                                passed: false,
                                message: msg.clone(),
                            });
                            failure_messages.push(format!("Object '{}': {}", object_id, msg));
                            continue;
                        }
                    };

                    // Perform string operation
                    let passed = self.compare_string_operation(expected, &content, field.operation);

                    let msg = if passed {
                        format!("Content check passed: {:?} '{}'", field.operation, expected)
                    } else {
                        match field.operation {
                            Operation::Contains | Operation::NotContains => {
                                format!(
                                    "Content check failed: {:?} '{}' (content preview: {})",
                                    field.operation,
                                    expected,
                                    self.preview_content(&content, 100)
                                )
                            }
                            Operation::StartsWith => {
                                let actual_start = if content.len() > 50 {
                                    format!("{}...", &content[..50])
                                } else {
                                    content.clone()
                                };
                                format!(
                                    "Content check failed: expected to start with '{}', actual start: '{}'",
                                    expected, actual_start
                                )
                            }
                            Operation::EndsWith => {
                                let actual_end = if content.len() > 50 {
                                    format!("...{}", &content[content.len() - 50..])
                                } else {
                                    content.clone()
                                };
                                format!(
                                    "Content check failed: expected to end with '{}', actual end: '{}'",
                                    expected, actual_end
                                )
                            }
                            _ => {
                                format!(
                                    "Content check failed: {:?} '{}'",
                                    field.operation, expected
                                )
                            }
                        }
                    };

                    if !passed {
                        failure_messages.push(format!("Object '{}': {}", object_id, msg));
                    }

                    all_field_results.push(FieldValidationResult {
                        field_name: field.name.clone(),
                        expected_value: field.value.clone(),
                        actual_value: ResolvedValue::String(content.clone()),
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
                    "Object '{}': {} ({} of {} content checks passed)",
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
                "File content validation passed: {} of {} objects compliant",
                objects_passing,
                state_results.len()
            )
        } else if !failure_messages.is_empty() {
            format!(
                "File content validation failed:\n  - {}",
                failure_messages.join("\n  - ")
            )
        } else {
            format!(
                "File content validation failed: {} of {} objects compliant (item check failed)",
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
        "file_content"
    }

    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        // Validate that file_content field is present
        for data in collected_data.values() {
            if !data.has_field("file_content") {
                return Err(CtnExecutionError::MissingDataField {
                    field: "file_content".to_string(),
                });
            }
        }
        Ok(())
    }
}
