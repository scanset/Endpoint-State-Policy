//! Computed Values Executor
//!
//! Validates STATE fields against resolved variables instead of collected data.
//! Used for testing RUN operations.
//!
//! CURRENT STATUS: STUB - Needs ExecutionContext access to complete

use common::results::Outcome;
use execution_engine::execution::{
    evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
};
use execution_engine::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::ExecutableCriterion;
use std::collections::HashMap;
pub struct ComputedValuesExecutor {
    contract: CtnContract,
}

impl ComputedValuesExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }
}

impl CtnExecutor for ComputedValuesExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test_spec = &criterion.test;

        // Phase 1: Existence Check
        let objects_expected = criterion.expected_object_count();
        let objects_found = criterion.objects.len();

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

        // Phase 2: State Validation (STUB)
        // TODO: This needs ExecutionContext.global_variables to actually validate
        let mut state_results = Vec::new();

        for object in &criterion.objects {
            let mut all_field_results = Vec::new();

            for state in &criterion.states {
                for field in &state.fields {
                    // STUB: Always passes for now
                    all_field_results.push(FieldValidationResult {
                        field_name: field.name.clone(),
                        expected_value: field.value.clone(),
                        actual_value: ResolvedValue::String(
                            "(stub - needs ExecutionContext)".to_string(),
                        ),
                        operation: field.operation,
                        passed: true,
                        message: format!("STUB: Variable '{}' validation", field.name),
                    });
                }
            }

            // Combine field results
            let state_bools: Vec<bool> = all_field_results.iter().map(|r| r.passed).collect();
            let combined = evaluate_state_operator(test_spec.state_operator, &state_bools);

            state_results.push(StateValidationResult {
                object_id: object.identifier.clone(),
                state_results: all_field_results,
                combined_result: combined,
                state_operator: test_spec.state_operator,
                message: format!("Object '{}': stub validation", object.identifier),
            });
        }

        // Phase 3: Item Check
        let objects_passing = state_results.iter().filter(|r| r.combined_result).count();
        let item_passed =
            evaluate_item_check(test_spec.item_check, objects_passing, state_results.len());

        let final_status = if existence_passed && item_passed {
            Outcome::Pass
        } else {
            Outcome::Fail
        };

        let message = format!(
            "STUB: Computed values validation - {} of {} objects",
            objects_passing,
            state_results.len()
        );

        Ok(CtnExecutionResult {
            ctn_type: criterion.criterion_type.clone(),
            status: final_status,
            test_phase: TestPhase::Complete,
            existence_result: None,
            state_results,
            item_check_result: None,
            message,
            details: serde_json::json!({
                "stub": true,
                "note": "This executor needs ExecutionContext access to validate variables",
                "see": "COMPUTED_VALUES_IMPLEMENTATION.md"
            }),
            execution_metadata: Default::default(),
            collected_data,
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "computed_values"
    }

    fn validate_collected_data(
        &self,
        _collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        // No validation needed - we don't use collected data
        Ok(())
    }
}
