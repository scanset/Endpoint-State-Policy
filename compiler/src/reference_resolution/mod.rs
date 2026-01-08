//! Reference Validation
//!
//! Validates that all references point to existing symbols and
//! detects basic dependency cycles. Uses compile-time constants for security boundaries.

use crate::symbols::SymbolDiscoveryResult;
use common::config::runtime::ReferenceValidationPreferences;
use common::logging::codes;
use common::{log_debug, log_error, log_info, log_success, log_warning};
use std::collections::{HashMap, HashSet};

pub mod error;
pub mod types;

// Re-export main types
pub use error::{ReferenceValidationError, ValidationResult};
pub use types::{ReferenceValidationResult, SecurityComplianceInfo, ValidationStats};

/// Module constants
pub const VERSION: &str = "2.0.0";
pub const PASS_NUMBER: u8 = 4;

/// Main entry point for reference validation with SSDF-compliant security boundaries
pub fn validate_references_and_basic_dependencies(
    symbol_result: SymbolDiscoveryResult,
    preferences: &ReferenceValidationPreferences,
) -> ValidationResult<ReferenceValidationResult> {
    // SECURITY: Validate input against compile-time limits before processing
    validate_input_bounds(&symbol_result)?;

    log_info!("Starting Pass 4: Reference Validation",
        "relationships" => symbol_result.relationships.len(),
        "global_symbols" => symbol_result.global_symbols.total_count(),
        "local_tables" => symbol_result.local_symbol_tables.len(),
        "cycle_detection_enabled" => preferences.enable_cycle_detection
    );

    // Create result with security compliance tracking
    let mut result = ReferenceValidationResult::new_with_compliance();
    result.stats.total_relationships = symbol_result.relationships.len();

    // Validate each Pass 3 relationship against symbol tables
    let mut undefined_references = Vec::new();

    for relationship in &symbol_result.relationships {
        if validate_single_reference(&relationship.target, &symbol_result, preferences) {
            result.stats.validated_count += 1;

            if preferences.log_validation_details {
                log_debug!("Reference validated",
                    "source" => relationship.source.as_str(),
                    "target" => relationship.target.as_str(),
                    "type" => relationship.relationship_type.as_str()
                );
            }
        } else {
            result.stats.error_count += 1;
            undefined_references.push(relationship.clone());

            log_error!(codes::references::UNDEFINED_REFERENCE,
                "Undefined reference target",
                span = relationship.source_span,
                "source" => relationship.source.as_str(),
                "target" => relationship.target.as_str(),
                "type" => relationship.relationship_type.as_str()
            );

            // SECURITY: Stop processing if we exceed error collection limit
            if result.stats.error_count
                >= common::config::constants::compile_time::logging::MAX_ERROR_COLLECTION
            {
                log_error!(codes::system::INTERNAL_ERROR,
                    "Error collection limit exceeded, halting validation",
                    "max_errors" => common::config::constants::compile_time::logging::MAX_ERROR_COLLECTION,
                    "current_errors" => result.stats.error_count
                );
                break;
            }
        }
    }

    // Early exit if we have undefined references and user doesn't want to continue
    if !undefined_references.is_empty() && !preferences.continue_after_cycles {
        if let Some(first_ref) = undefined_references.first() {
            return Err(ReferenceValidationError::undefined_reference(
                &first_ref.target,
                &infer_symbol_type(&first_ref.relationship_type),
                first_ref.source_span,
            ));
        }
        // Handle the case where undefined_references is somehow empty
        return Err(ReferenceValidationError::internal_validation_error(
            "Undefined references exist but list is empty",
        ));
    }

    // Detect dependency cycles if enabled
    let cycles = if preferences.enable_cycle_detection {
        log_debug!("Starting cycle detection", "relationships" => symbol_result.relationships.len());
        detect_dependency_cycles(&symbol_result.relationships, preferences)?
    } else {
        log_debug!("Cycle detection disabled by user preference");
        Vec::new()
    };

    result.cycles = cycles;
    result.stats.cycle_count = result.cycles.len();

    if !result.cycles.is_empty() {
        log_warning!("Dependency cycles detected", "cycles" => result.cycles.len());

        if preferences.include_cycle_descriptions {
            for (i, cycle) in result
                .cycles
                .iter()
                .enumerate()
                .take(common::config::compile_time::references::MAX_REPORTED_CYCLES)
            {
                log_info!("Cycle detected",
                    "cycle_id" => i + 1,
                    "cycle_path" => cycle.join(" -> "),
                    "cycle_length" => cycle.len()
                );
            }
        }
    }

    result.is_successful = undefined_references.is_empty()
        && (result.cycles.is_empty() || preferences.continue_after_cycles);

    // Update security compliance with actual values
    result.update_security_compliance(
        result.stats.total_relationships,
        result.stats.max_reference_depth,
    );

    log_success!(codes::success::REFERENCE_RESOLUTION_COMPLETE,
        "Reference validation completed",
        "validated" => result.stats.validated_count,
        "errors" => result.stats.error_count,
        "cycles" => result.cycles.len(),
        "success_rate" => format!("{:.1}%", result.success_rate() * 100.0)
    );

    Ok(result)
}

/// SECURITY: Validate input against compile-time security boundaries
fn validate_input_bounds(symbol_result: &SymbolDiscoveryResult) -> ValidationResult<()> {
    // Check relationship count limit
    if symbol_result.relationships.len()
        > common::config::compile_time::references::MAX_RELATIONSHIPS_PER_PASS
    {
        return Err(ReferenceValidationError::internal_validation_error(
            &format!(
                "Relationship count {} exceeds security limit of {}",
                symbol_result.relationships.len(),
                common::config::compile_time::references::MAX_RELATIONSHIPS_PER_PASS
            ),
        ));
    }

    // Check global symbol count limit
    if symbol_result.global_symbols.total_count()
        > common::config::constants::compile_time::symbols::MAX_GLOBAL_SYMBOLS
    {
        return Err(ReferenceValidationError::internal_validation_error(
            &format!(
                "Global symbol count {} exceeds security limit of {}",
                symbol_result.global_symbols.total_count(),
                common::config::constants::compile_time::symbols::MAX_GLOBAL_SYMBOLS
            ),
        ));
    }

    // Check local symbol table count
    if symbol_result.local_symbol_tables.len()
        > common::config::constants::compile_time::symbols::MAX_CTN_SCOPES
    {
        return Err(ReferenceValidationError::internal_validation_error(
            &format!(
                "Local symbol table count {} exceeds security limit of {}",
                symbol_result.local_symbol_tables.len(),
                common::config::constants::compile_time::symbols::MAX_CTN_SCOPES
            ),
        ));
    }

    Ok(())
}

/// Validate that a single reference target exists in Pass 3 symbol tables
fn validate_single_reference(
    target: &str,
    symbol_result: &SymbolDiscoveryResult,
    preferences: &ReferenceValidationPreferences,
) -> bool {
    // SECURITY: Validate target identifier length
    if target.len() > common::config::constants::compile_time::symbols::MAX_SYMBOL_IDENTIFIER_LENGTH
    {
        if preferences.log_validation_details {
            log_warning!("Reference target identifier too long",
                "target" => target,
                "length" => target.len(),
                "max_length" => common::config::constants::compile_time::symbols::MAX_SYMBOL_IDENTIFIER_LENGTH
            );
        }
        return false;
    }

    // Check global symbols
    if symbol_result.global_symbols.variables.contains_key(target)
        || symbol_result.global_symbols.states.contains_key(target)
        || symbol_result.global_symbols.objects.contains_key(target)
        || symbol_result.global_symbols.sets.contains_key(target)
    {
        return true;
    }

    // Check local symbols
    for local_table in &symbol_result.local_symbol_tables {
        if local_table.states.contains_key(target) {
            return true;
        }
        if let Some(obj) = &local_table.object {
            if obj.identifier == target {
                return true;
            }
        }
    }

    false
}

/// Detect dependency cycles with SSDF-compliant security boundaries
fn detect_dependency_cycles(
    relationships: &[crate::symbols::table::SymbolRelationship],
    preferences: &ReferenceValidationPreferences,
) -> ValidationResult<Vec<Vec<String>>> {
    use crate::symbols::table::RelationshipType;

    // Build adjacency list for dependency-creating relationships only
    let mut adjacency = HashMap::<String, Vec<String>>::new();
    let mut nodes = HashSet::new();

    for relationship in relationships {
        // Only include relationships that create dependencies
        let creates_dependency = matches!(
            relationship.relationship_type,
            RelationshipType::VariableInitialization
                | RelationshipType::RunOperationInput
                | RelationshipType::SetReference
        );

        if creates_dependency {
            let entry = adjacency.entry(relationship.source.clone()).or_default();

            // SECURITY: Limit references per symbol
            if entry.len() >= common::config::compile_time::references::MAX_REFERENCES_PER_SYMBOL {
                return Err(ReferenceValidationError::internal_validation_error(
                    &format!(
                        "Symbol '{}' exceeds maximum reference limit of {}",
                        relationship.source,
                        common::config::compile_time::references::MAX_REFERENCES_PER_SYMBOL
                    ),
                ));
            }

            entry.push(relationship.target.clone());
            nodes.insert(relationship.source.clone());
            nodes.insert(relationship.target.clone());
        }
    }

    if nodes.is_empty() {
        log_debug!("No dependency-creating relationships found");
        return Ok(Vec::new());
    }

    // SECURITY: Validate node count against compile-time limit
    if nodes.len() > common::config::compile_time::references::MAX_DEPENDENCY_NODES {
        return Err(ReferenceValidationError::internal_validation_error(
            &format!(
                "Dependency graph too large: {} nodes exceeds limit of {}",
                nodes.len(),
                common::config::compile_time::references::MAX_DEPENDENCY_NODES
            ),
        ));
    }

    log_debug!("Cycle detection graph",
        "nodes" => nodes.len(),
        "dependency_edges" => adjacency.values().map(|v| v.len()).sum::<usize>()
    );

    // DFS cycle detection with depth protection
    let mut cycles = Vec::new();
    let mut visited = HashSet::new();
    let mut rec_stack = HashSet::new();

    for node in &nodes {
        if !visited.contains(node) {
            find_cycles_dfs(
                node,
                &adjacency,
                &mut visited,
                &mut rec_stack,
                &mut cycles,
                &mut Vec::new(),
                0, // depth tracking
            )?;
        }
    }

    // SECURITY: Limit reported cycles to prevent log spam
    if cycles.len() > common::config::compile_time::references::MAX_REPORTED_CYCLES {
        if preferences.log_validation_details {
            log_warning!("Many cycles detected, limiting report",
                "total_cycles" => cycles.len(),
                "reported_cycles" => common::config::compile_time::references::MAX_REPORTED_CYCLES
            );
        }
        cycles.truncate(common::config::compile_time::references::MAX_REPORTED_CYCLES);
    }

    Ok(cycles)
}

/// DFS helper for cycle detection with security boundaries
fn find_cycles_dfs(
    node: &str,
    adjacency: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    rec_stack: &mut HashSet<String>,
    cycles: &mut Vec<Vec<String>>,
    path: &mut Vec<String>,
    depth: usize,
) -> ValidationResult<()> {
    // SECURITY: Prevent deep recursion attacks
    if depth > common::config::compile_time::references::MAX_REFERENCE_DEPTH {
        return Ok(()); // Skip deep paths without error
    }

    // SECURITY: Prevent excessively long cycles
    if path.len() > common::config::compile_time::references::MAX_CYCLE_LENGTH {
        return Ok(()); // Skip long cycles without error
    }

    visited.insert(node.to_string());
    rec_stack.insert(node.to_string());
    path.push(node.to_string());

    if let Some(neighbors) = adjacency.get(node) {
        for neighbor in neighbors {
            if !visited.contains(neighbor) {
                find_cycles_dfs(
                    neighbor,
                    adjacency,
                    visited,
                    rec_stack,
                    cycles,
                    path,
                    depth + 1,
                )?;
            } else if rec_stack.contains(neighbor) {
                // Found cycle - extract cycle portion
                if let Some(cycle_start) = path.iter().position(|n| n == neighbor) {
                    let cycle = path
                        .get(cycle_start..)
                        .map(|s| s.to_vec())
                        .unwrap_or_default();

                    // SECURITY: Only record cycles within length limit
                    if cycle.len() <= common::config::compile_time::references::MAX_CYCLE_LENGTH {
                        cycles.push(cycle);
                    }
                }
            }
        }
    }

    rec_stack.remove(node);
    path.pop();
    Ok(())
}

/// Infer symbol type from relationship type for error reporting
fn infer_symbol_type(relationship_type: &crate::symbols::table::RelationshipType) -> String {
    use crate::symbols::table::RelationshipType;

    match relationship_type {
        RelationshipType::VariableInitialization
        | RelationshipType::VariableUsage
        | RelationshipType::RunOperationInput
        | RelationshipType::RunOperationTarget => "variable".to_string(), // ADD THIS
        RelationshipType::StateReference | RelationshipType::FilterDependency => {
            "state".to_string()
        }
        RelationshipType::ObjectReference | RelationshipType::ObjectFieldExtraction => {
            "object".to_string()
        }
        RelationshipType::SetReference => "set".to_string(),
    }
}

/// Initialize reference validation with security boundary validation
pub fn init_reference_validation() -> ValidationResult<()> {
    log_debug!("Reference validation module initialized",
        "max_relationships" => common::config::compile_time::references::MAX_RELATIONSHIPS_PER_PASS,
        "max_dependency_nodes" => common::config::compile_time::references::MAX_DEPENDENCY_NODES,
        "max_reference_depth" => common::config::compile_time::references::MAX_REFERENCE_DEPTH,
        "max_cycle_length" => common::config::compile_time::references::MAX_CYCLE_LENGTH
    );
    Ok(())
}

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::table::{GlobalSymbolTable, RelationshipType, SymbolRelationship};
    use common::utils::{Position, Span};

    fn create_test_symbol_result() -> SymbolDiscoveryResult {
        let mut symbol_result = SymbolDiscoveryResult::new();
        symbol_result.global_symbols = GlobalSymbolTable::new();

        // Add test relationship
        let relationship = SymbolRelationship::new(
            "var1".to_string(),
            "var2".to_string(),
            RelationshipType::VariableInitialization,
            Span::new(Position::start(), Position::start()),
        );
        symbol_result.relationships.push(relationship);

        symbol_result
    }

    fn create_test_preferences() -> ReferenceValidationPreferences {
        ReferenceValidationPreferences::default()
    }

    #[test]
    fn test_validate_single_reference_missing() {
        let symbol_result = create_test_symbol_result();
        let preferences = create_test_preferences();
        assert!(!validate_single_reference(
            "nonexistent",
            &symbol_result,
            &preferences
        ));
    }

    #[test]
    fn test_empty_cycle_detection() {
        let preferences = create_test_preferences();
        let cycles = detect_dependency_cycles(&[], &preferences).unwrap();
        assert!(cycles.is_empty());
    }

    #[test]
    fn test_infer_symbol_type() {
        assert_eq!(
            infer_symbol_type(&RelationshipType::VariableInitialization),
            "variable"
        );
        assert_eq!(
            infer_symbol_type(&RelationshipType::StateReference),
            "state"
        );
    }

    #[test]
    fn test_input_bounds_validation() {
        let mut symbol_result = create_test_symbol_result();

        // Test relationship count limit
        for i in
            0..common::config::constants::compile_time::references::MAX_RELATIONSHIPS_PER_PASS + 1
        {
            let relationship = SymbolRelationship::new(
                format!("var{}", i),
                format!("target{}", i),
                RelationshipType::VariableInitialization,
                Span::new(Position::start(), Position::start()),
            );
            symbol_result.relationships.push(relationship);
        }

        let result = validate_input_bounds(&symbol_result);
        assert!(result.is_err());
    }
}
