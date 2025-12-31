//! Filter evaluation for OBJECT and SET filters
//!
//! Filters are applied AFTER collection but BEFORE executor validation.
//! This allows filtering based on collected data while keeping collectors simple.

use crate::execution::comparisons::ComparisonExt;
use crate::strategies::CollectedData;
use crate::types::execution_context::ExecutionContext;
use crate::types::filter::ResolvedFilterSpec;
use crate::types::{FilterAction, ResolvedState};

pub struct FilterEvaluator;

impl FilterEvaluator {
    /// Evaluate filter against collected data
    ///
    /// # Returns
    /// `true` if object should be RETAINED (kept for validation)
    /// `false` if object should be DISCARDED (filtered out)
    ///
    /// # Filter Semantics
    /// - **Include filter**: Retain objects that SATISFY the states
    /// - **Exclude filter**: Retain objects that DO NOT satisfy the states
    ///
    /// # Examples
    /// ```ignore
    /// // FILTER include readable (keep only readable files)
    /// // File is readable → states satisfied → RETAIN (return true)
    /// // File not readable → states not satisfied → DISCARD (return false)
    ///
    /// // FILTER exclude readable (keep only non-readable files)
    /// // File is readable → states satisfied → DISCARD (return false)
    /// // File not readable → states not satisfied → RETAIN (return true)
    /// ```
    pub fn evaluate_filter(
        filter: &ResolvedFilterSpec,
        collected_data: &CollectedData,
        context: &ExecutionContext,
    ) -> Result<bool, FilterEvaluationError> {
        // Check if all filter states are satisfied
        let all_states_satisfied =
            Self::check_all_states_satisfied(&filter.state_refs, collected_data, context)?;

        // Determine if object should be retained based on filter action
        let should_retain = match filter.action {
            FilterAction::Include => {
                // Include filter: retain only if states ARE satisfied
                all_states_satisfied
            }
            FilterAction::Exclude => {
                // Exclude filter: retain only if states are NOT satisfied
                !all_states_satisfied
            }
        };

        Ok(should_retain)
    }

    /// Check if all states referenced in filter are satisfied
    fn check_all_states_satisfied(
        state_refs: &[String],
        collected_data: &CollectedData,
        context: &ExecutionContext,
    ) -> Result<bool, FilterEvaluationError> {
        if state_refs.is_empty() {
            return Ok(true);
        }

        for state_id in state_refs {
            let state = context.global_states.get(state_id).ok_or_else(|| {
                FilterEvaluationError::StateNotFound {
                    state_id: state_id.clone(),
                }
            })?;

            let state_satisfied = Self::evaluate_state(state, collected_data)?;

            if !state_satisfied {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Evaluate a single state against collected data
    fn evaluate_state(
        state: &ResolvedState,
        collected_data: &CollectedData,
    ) -> Result<bool, FilterEvaluationError> {
        // For each field in the state, check if it matches collected data
        for field in &state.resolved_fields {
            // Map state field name to collected data field name
            let data_field_name = &field.name;

            let actual_value = collected_data.get_field(data_field_name).ok_or_else(|| {
                FilterEvaluationError::FieldNotFound {
                    field_name: field.name.clone(),
                }
            })?;

            // FIXED: Use compare_with method on ResolvedValue (it's a trait method)
            let field_passed = field.value.compare_with(actual_value, field.operation)?;

            if !field_passed {
                return Ok(false); // One field fails = state fails
            }
        }

        Ok(true) // All fields passed
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FilterEvaluationError {
    #[error("Filter references undefined state: {state_id}")]
    StateNotFound { state_id: String },

    #[error("Field '{field_name}' not found in collected data")]
    FieldNotFound { field_name: String },

    #[error("Comparison failed: {reason}")]
    ComparisonFailed { reason: String },

    #[error("Invalid filter configuration: {reason}")]
    InvalidFilter { reason: String },
}

// Convert comparison errors to filter errors
impl From<crate::execution::comparisons::ComparisonError> for FilterEvaluationError {
    fn from(err: crate::execution::comparisons::ComparisonError) -> Self {
        FilterEvaluationError::ComparisonFailed {
            reason: err.to_string(),
        }
    }
}
