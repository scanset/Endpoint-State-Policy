//! # Entity Check Collection Support
//!
//! Utilities for collectors to properly handle entity checks by returning
//! multiple values when needed.

use crate::types::common::ResolvedValue;
use crate::types::execution_context::ExecutableCriterion;
use std::collections::{HashMap, HashSet};

/// Helper to identify which fields need entity-level collection
///
/// This allows collectors to determine which fields should return
/// ResolvedValue::Collection vs single values.
pub struct EntityCheckAnalyzer;

impl EntityCheckAnalyzer {
    /// Analyze criterion to find fields requiring entity-level collection
    ///
    /// Returns a map of field_name -> entity_check_type
    pub fn get_entity_check_fields(
        criterion: &ExecutableCriterion,
    ) -> HashMap<String, crate::types::EntityCheck> {
        let mut entity_fields = HashMap::new();

        // Check all states for entity checks
        for state in &criterion.states {
            for field in &state.fields {
                if let Some(entity_check) = field.entity_check {
                    entity_fields.insert(field.name.clone(), entity_check);
                }
            }

            // Also check record fields
            for record_check in &state.record_checks {
                if let crate::types::execution_context::ExecutableRecordContent::Nested { fields } =
                    &record_check.content
                {
                    for record_field in fields {
                        if let Some(entity_check) = record_field.entity_check {
                            // Use dot notation for record field names
                            entity_fields.insert(record_field.path.to_dot_notation(), entity_check);
                        }
                    }
                }
            }
        }

        entity_fields
    }

    /// Check if a specific field requires entity-level collection
    pub fn field_needs_entity_collection(
        criterion: &ExecutableCriterion,
        field_name: &str,
    ) -> bool {
        criterion.states.iter().any(|state| {
            state
                .fields
                .iter()
                .any(|field| field.name == field_name && field.entity_check.is_some())
        })
    }

    /// Get all field names that need entity collection (no duplicates)
    pub fn get_entity_field_names(criterion: &ExecutableCriterion) -> HashSet<String> {
        let entity_fields = Self::get_entity_check_fields(criterion);
        entity_fields.keys().cloned().collect()
    }
}

/// Extension trait for collectors to easily handle entity checks
pub trait EntityCheckCollector {
    /// Collect a field value, returning Collection if entity check is present
    ///
    /// # Arguments
    /// * `field_name` - Name of the field to collect
    /// * `criterion` - The criterion being executed (to check for entity checks)
    ///
    /// # Returns
    /// * Single value if no entity check
    /// * Collection of values if entity check present
    fn collect_field_with_entity_awareness(
        &self,
        field_name: &str,
        criterion: &ExecutableCriterion,
    ) -> Result<ResolvedValue, crate::strategies::CollectionError>;
}

/// Helper for wrapping single values as collections when needed
pub fn wrap_for_entity_check(value: ResolvedValue, needs_collection: bool) -> ResolvedValue {
    if needs_collection {
        match value {
            ResolvedValue::Collection(_) => value, // Already a collection
            single_value => ResolvedValue::Collection(vec![single_value]),
        }
    } else {
        value
    }
}

/// Helper for collectors: determine collection strategy for object
///
/// Returns (field_name, should_return_collection) pairs
pub fn get_collection_strategy(
    criterion: &ExecutableCriterion,
    _object_id: &str,
) -> HashMap<String, bool> {
    let entity_fields = EntityCheckAnalyzer::get_entity_check_fields(criterion);

    // For each field in the object, check if it needs collection
    let mut strategy = HashMap::new();

    // Get all field names from criterion states
    for state in &criterion.states {
        for field in &state.fields {
            let needs_collection = entity_fields.contains_key(&field.name);
            strategy.insert(field.name.clone(), needs_collection);
        }
    }

    strategy
}
