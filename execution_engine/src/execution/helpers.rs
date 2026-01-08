//! # Execution Helpers
//!
//! Centralized helper functions for TEST specification evaluation.
//! These functions provide consistent logic for all executors to use.

// FIXED: Import EntityCheck directly from compiler (it's re-exported in types/mod.rs now)
use crate::types::EntityCheck;
use crate::types::{ExistenceCheck, ItemCheck, StateJoinOp};

/// Evaluate existence check against collected object counts
pub fn evaluate_existence_check(
    check: ExistenceCheck,
    objects_found: usize,
    objects_expected: usize,
) -> bool {
    match check {
        ExistenceCheck::Any => objects_found > 0,
        ExistenceCheck::All => objects_found == objects_expected && objects_expected > 0,
        ExistenceCheck::None => objects_found == 0,
        ExistenceCheck::AtLeastOne => objects_found >= 1,
        ExistenceCheck::OnlyOne => objects_found == 1,
    }
}

/// Evaluate item check against state validation results
pub fn evaluate_item_check(check: ItemCheck, items_passing: usize, items_total: usize) -> bool {
    match check {
        ItemCheck::All => items_passing == items_total && items_total > 0,
        ItemCheck::AtLeastOne => items_passing >= 1,
        ItemCheck::OnlyOne => items_passing == 1,
        ItemCheck::NoneSatisfy => items_passing == 0,
    }
}

/// Evaluate state operator to combine multiple state results
/// FIXED: None now defaults to AND behavior
pub fn evaluate_state_operator(operator: Option<StateJoinOp>, state_results: &[bool]) -> bool {
    if state_results.is_empty() {
        return false;
    }

    match operator {
        Some(StateJoinOp::And) | None => {
            // DEFAULT TO AND when no operator specified
            state_results.iter().all(|&result| result)
        }
        Some(StateJoinOp::Or) => state_results.iter().any(|&result| result),
        Some(StateJoinOp::One) => state_results.iter().filter(|&&result| result).count() == 1,
    }
}

/// Evaluate entity check for field-level validation across multiple entities
pub fn evaluate_entity_check(check: Option<EntityCheck>, entity_results: &[bool]) -> bool {
    if entity_results.is_empty() {
        return check.is_none();
    }

    match check {
        Some(EntityCheck::All) | None => {
            // DEFAULT TO ALL when no check specified
            entity_results.iter().all(|&result| result)
        }
        Some(EntityCheck::AtLeastOne) => entity_results.iter().any(|&result| result),
        Some(EntityCheck::None) => entity_results.iter().all(|&result| !result),
        Some(EntityCheck::OnlyOne) => entity_results.iter().filter(|&&result| result).count() == 1,
    }
}

/// Helper to determine if a TEST specification requires state evaluation
pub fn requires_state_evaluation(existence_check: ExistenceCheck, item_check: ItemCheck) -> bool {
    // If existence check is "none", state evaluation is not needed
    if matches!(existence_check, ExistenceCheck::None) {
        return false;
    }

    // If item check expects satisfaction, state evaluation is needed
    !matches!(item_check, ItemCheck::NoneSatisfy)
}

/// Create detailed existence result
pub fn create_existence_result(
    check: ExistenceCheck,
    objects_found: usize,
    objects_expected: usize,
) -> crate::strategies::ExistenceResult {
    let passed = evaluate_existence_check(check, objects_found, objects_expected);

    let message = if passed {
        format!(
            "Existence check '{}' passed: {} of {} objects found",
            existence_check_to_str(check),
            objects_found,
            objects_expected
        )
    } else {
        format!(
            "Existence check '{}' failed: {} of {} objects found",
            existence_check_to_str(check),
            objects_found,
            objects_expected
        )
    };

    crate::strategies::ExistenceResult {
        existence_check: check,
        objects_expected,
        objects_found,
        passed,
        message,
    }
}

/// Create detailed item check result
pub fn create_item_check_result(
    check: ItemCheck,
    items_passing: usize,
    items_total: usize,
) -> crate::strategies::ItemCheckResult {
    let passed = evaluate_item_check(check, items_passing, items_total);

    let message = if passed {
        format!(
            "Item check '{}' passed: {} of {} objects satisfied requirements",
            item_check_to_str(check),
            items_passing,
            items_total
        )
    } else {
        format!(
            "Item check '{}' failed: {} of {} objects satisfied requirements",
            item_check_to_str(check),
            items_passing,
            items_total
        )
    };

    crate::strategies::ItemCheckResult {
        item_check: check,
        objects_passing: items_passing,
        objects_total: items_total,
        passed,
        message,
    }
}

// Helper functions for string conversion
fn existence_check_to_str(check: ExistenceCheck) -> &'static str {
    match check {
        ExistenceCheck::Any => "any",
        ExistenceCheck::All => "all",
        ExistenceCheck::None => "none",
        ExistenceCheck::AtLeastOne => "at_least_one",
        ExistenceCheck::OnlyOne => "only_one",
    }
}

fn item_check_to_str(check: ItemCheck) -> &'static str {
    match check {
        ItemCheck::All => "all",
        ItemCheck::AtLeastOne => "at_least_one",
        ItemCheck::OnlyOne => "only_one",
        ItemCheck::NoneSatisfy => "none_satisfy",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_operator_none_defaults_to_and() {
        // None should default to AND behavior
        assert!(evaluate_state_operator(None, &[true, true, true]));
        assert!(!evaluate_state_operator(None, &[true, false, true]));
        assert!(!evaluate_state_operator(None, &[false, false, false]));
    }

    #[test]
    fn test_entity_check_none_defaults_to_all() {
        // None should default to ALL behavior
        assert!(evaluate_entity_check(None, &[true, true, true]));
        assert!(!evaluate_entity_check(None, &[true, false, true]));
    }

    #[test]
    fn test_requires_state_evaluation() {
        // None existence check doesn't need state evaluation
        assert!(!requires_state_evaluation(
            ExistenceCheck::None,
            ItemCheck::All
        ));

        // NoneSatisfy item check with other existence checks needs evaluation
        assert!(requires_state_evaluation(
            ExistenceCheck::Any,
            ItemCheck::All
        ));
        assert!(!requires_state_evaluation(
            ExistenceCheck::Any,
            ItemCheck::NoneSatisfy
        ));
    }
}
