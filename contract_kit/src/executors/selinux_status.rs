//! SELinux status executor
//!
//! Validates SELinux enforcement mode.

use agent_core::execution::{
    evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
};
use agent_core::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use agent_core::types::common::{Operation, ResolvedValue};
use agent_core::types::execution_context::ExecutableCriterion;
use common::results::Outcome;
use std::collections::HashMap;

pub struct SelinuxStatusExecutor {
    contract: CtnContract,
}

impl SelinuxStatusExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        operation: Operation,
    ) -> bool {
        match (expected, actual, operation) {
            (ResolvedValue::String(exp), ResolvedValue::String(act), Operation::Equals) => {
                exp == act
            }
            (ResolvedValue::String(exp), ResolvedValue::String(act), Operation::NotEqual) => {
                exp != act
            }
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), Operation::Equals) => {
                exp == act
            }
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), Operation::NotEqual) => {
                exp != act
            }
            _ => false,
        }
    }
}

impl CtnExecutor for SelinuxStatusExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test_spec = &criterion.test;

        // For system-wide checks, we expect exactly 1 object
        let objects_expected = criterion.expected_object_count().max(1);
        let objects_found = collected_data.len().max(1);

        let existence_passed =
            evaluate_existence_check(test_spec.existence_check, objects_found, objects_expected);

        if !existence_passed {
            return Ok(CtnExecutionResult::fail(
                criterion.criterion_type.clone(),
                "SELinux status check failed".to_string(),
            ));
        }

        let mut state_results = Vec::new();
        let mut failure_messages = Vec::new();

        // Get the single data entry (or create pseudo-entry if no objects defined)
        let data_entries: Vec<(&String, &CollectedData)> = if collected_data.is_empty() {
            vec![]
        } else {
            collected_data.iter().collect()
        };

        let (object_id, data) = if let Some(entry) = data_entries.first() {
            entry
        } else {
            return Ok(CtnExecutionResult::error(
                criterion.criterion_type.clone(),
                "No SELinux data collected".to_string(),
            ));
        };

        let mut all_field_results = Vec::new();

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
                        let msg = format!("Field '{}' not collected", field.name);
                        all_field_results.push(FieldValidationResult {
                            field_name: field.name.clone(),
                            expected_value: field.value.clone(),
                            actual_value: ResolvedValue::String("".to_string()),
                            operation: field.operation,
                            passed: false,
                            message: msg.clone(),
                        });
                        failure_messages.push(msg);
                        continue;
                    }
                };

                let passed = self.compare_values(&field.value, &actual_value, field.operation);

                let msg = if passed {
                    format!("SELinux '{}' check passed", field.name)
                } else {
                    format!(
                        "SELinux '{}' check failed: expected {:?}, got {:?}",
                        field.name, field.value, actual_value
                    )
                };

                if !passed {
                    failure_messages.push(msg.clone());
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

        let state_bools: Vec<bool> = all_field_results.iter().map(|r| r.passed).collect();
        let combined = evaluate_state_operator(test_spec.state_operator, &state_bools);

        state_results.push(StateValidationResult {
            object_id: (*object_id).clone(),
            state_results: all_field_results,
            combined_result: combined,
            state_operator: test_spec.state_operator,
            message: format!(
                "SELinux status: {}",
                if combined { "passed" } else { "failed" }
            ),
        });

        let objects_passing = if combined { 1 } else { 0 };
        let item_passed = evaluate_item_check(test_spec.item_check, objects_passing, 1);

        let final_status = if existence_passed && item_passed {
            Outcome::Pass
        } else {
            Outcome::Fail
        };

        let message = if final_status == Outcome::Pass {
            "SELinux status validation passed".to_string()
        } else {
            format!(
                "SELinux status validation failed:\n  - {}",
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
            }),
            execution_metadata: Default::default(),
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "selinux_status"
    }

    fn validate_collected_data(
        &self,
        _collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        Ok(())
    }
}
