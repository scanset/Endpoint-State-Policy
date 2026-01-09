//! Computed Values Collector
//!
//! This "collector" doesn't actually collect anything from the system.
//! It's a pass-through that allows the executor to validate computed variables.

use common::results::CollectionMethod;
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::execution_context::ExecutableObject;

pub struct ComputedValuesCollector {
    id: String,
}

impl ComputedValuesCollector {
    pub fn new() -> Self {
        Self {
            id: "computed_values_collector".to_string(),
        }
    }
}

impl Default for ComputedValuesCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for ComputedValuesCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        _contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Create empty CollectedData - we're not collecting anything
        // The executor will look in resolved_variables instead
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "computed_values".to_string(),
            self.id.clone(),
        );

        // Set collection method for traceability - marks this as computed/derived
        let method = CollectionMethod::computed()
            .with_description("Computed value - no actual system collection performed");
        data.set_method(method);

        // No fields to add - validation happens against variables, not collected data
        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["computed_values".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "computed_values" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'computed_values', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false // No actual collection to batch
    }
}
