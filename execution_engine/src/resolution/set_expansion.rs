//! SET expansion for ESP execution - Declaration-level expansion
//!
//! This module provides functions to expand SET_REF elements during the resolution phase,
//! working directly on CriterionDeclaration structures before ExecutionContext creation.

use crate::resolution::ResolutionError;
use crate::types::criteria::CriteriaTree;
use crate::types::criterion::CriterionDeclaration;
use crate::types::object::ObjectDeclaration;
use crate::types::resolution_context::ResolutionContext;
use crate::types::set::{ResolvedSetOperand, ResolvedSetOperation};
use common::ast::nodes::ObjectRef;
use common::logging::codes;
use common::{log_debug, log_error, log_info};
use std::collections::{HashMap, HashSet};

/// Main entry point for SET expansion during resolution phase
/// Call this AFTER resolve_dag() and BEFORE ExecutionContext creation
pub fn expand_sets_in_resolution_context(
    context: &mut ResolutionContext,
) -> Result<(), ResolutionError> {
    log_info!(
        "Starting SET expansion in resolution context",
        "total_sets" => context.resolved_sets.len()
    );

    // Validate SET structures first (check for circular dependencies)
    validate_set_expansions(context)?;

    // Expand SET_REF in all criteria trees
    // CRITICAL FIX: We need to separate the mutable borrow from the immutable read
    // Solution: Clone the data we need from context for read-only access during expansion
    let resolved_sets = context.resolved_sets.clone();
    let resolved_global_objects = context.resolved_global_objects.clone();

    let mut total_expanded = 0;
    for tree in &mut context.criteria_root.trees {
        total_expanded += expand_set_refs_in_criteria_tree_helper(
            tree,
            &resolved_sets,
            &resolved_global_objects,
        )?;
    }

    log_info!(
        "SET expansion completed",
        "criteria_expanded" => total_expanded,
        "total_sets" => context.resolved_sets.len()
    );

    Ok(())
}

/// Helper function that takes cloned data instead of full context
/// This avoids borrow checker issues
fn expand_set_refs_in_criteria_tree_helper(
    tree: &mut CriteriaTree,
    resolved_sets: &HashMap<String, ResolvedSetOperation>,
    resolved_global_objects: &HashMap<String, crate::types::object::ResolvedObject>,
) -> Result<usize, ResolutionError> {
    match tree {
        CriteriaTree::Criterion {
            declaration,
            node_id: _,
        } => {
            let expanded = expand_set_ref_in_declaration_helper(
                declaration,
                resolved_sets,
                resolved_global_objects,
            )?;
            Ok(if expanded { 1 } else { 0 })
        }
        CriteriaTree::Block { children, .. } => {
            let mut total = 0;
            for child in children {
                total += expand_set_refs_in_criteria_tree_helper(
                    child,
                    resolved_sets,
                    resolved_global_objects,
                )?;
            }
            Ok(total)
        }
    }
}

/// Expand SET_REF in a single CriterionDeclaration
/// Helper version that takes separate parameters instead of full context
fn expand_set_ref_in_declaration_helper(
    declaration: &mut CriterionDeclaration,
    resolved_sets: &HashMap<String, ResolvedSetOperation>,
    resolved_global_objects: &HashMap<String, crate::types::object::ResolvedObject>,
) -> Result<bool, ResolutionError> {
    let mut was_expanded = false;
    let mut new_object_refs = Vec::new();

    // Phase 0: Direct CTN-level SET_REFs (the
    // `criterion_node.set_refs` AST field). Resolve each into the
    // underlying OBJECT_REFs and append to object_refs. Per EBNF
    // ctn_content allows SET_REFs alongside OBJECT_REFs; the parser
    // gating was relaxed in the same change that added this branch.
    if !declaration.set_refs.is_empty() {
        let set_refs_drained: Vec<_> = declaration.set_refs.drain(..).collect();
        for set_ref in set_refs_drained {
            let expanded = expand_set_ref_to_object_refs(
                &set_ref.set_id,
                &set_ref.set_id, // No bag object id; use set_id for tracing
                &declaration.criterion_type,
                resolved_sets,
            )?;
            new_object_refs.extend(expanded);
            was_expanded = true;
        }
    }

    // Phase 1: Check local object for SET_REF
    if let Some(local_obj) = &declaration.local_object {
        if let Some(set_id) = extract_set_ref_from_declaration_object(local_obj) {
            // Expand the SET_REF into object references
            let expanded_refs = expand_set_ref_to_object_refs(
                &set_id,
                &local_obj.identifier,
                &declaration.criterion_type,
                resolved_sets,
            )?;

            new_object_refs.extend(expanded_refs);
            was_expanded = true;

            // Clear local object since we've expanded it
            declaration.local_object = None;
        }
    }

    // Phase 2: Check global object references for SET_REF
    let mut refs_to_remove = HashSet::new();
    for obj_ref in &declaration.object_refs {
        // Look up the global object
        if let Some(global_obj) = resolved_global_objects.get(&obj_ref.object_id) {
            // Check if this resolved object contains SET_REF
            if contains_set_ref_in_resolved_object(global_obj) {
                let set_id = extract_set_ref_from_resolved_object(global_obj).ok_or_else(|| {
                    ResolutionError::InvalidInput {
                        message: format!(
                            "Expected SET_REF in object '{}' but not found",
                            obj_ref.object_id
                        ),
                    }
                })?;

                // Expand this SET_REF
                let expanded_refs = expand_set_ref_to_object_refs(
                    &set_id,
                    &obj_ref.object_id,
                    &declaration.criterion_type,
                    resolved_sets,
                )?;

                new_object_refs.extend(expanded_refs);
                was_expanded = true;

                // Mark this reference for removal (it was just a container for SET_REF)
                refs_to_remove.insert(obj_ref.object_id.clone());
            }
        }
    }

    // Phase 3: Update declaration with expanded references
    if was_expanded {
        // Remove old SET_REF container references
        declaration
            .object_refs
            .retain(|r| !refs_to_remove.contains(&r.object_id));

        // Add new expanded references
        declaration.object_refs.extend(new_object_refs);

        // Deduplicate
        let mut seen = HashSet::new();
        declaration
            .object_refs
            .retain(|r| seen.insert(r.object_id.clone()));
    }

    Ok(was_expanded)
}

/// Extract SET_REF from ObjectDeclaration (unresolved)
fn extract_set_ref_from_declaration_object(object: &ObjectDeclaration) -> Option<String> {
    for element in &object.elements {
        // FIXED: ObjectElement comes from compiler, use it directly
        if let common::ast::nodes::ObjectElement::SetRef { set_id, .. } = element {
            return Some(set_id.clone());
        }
    }
    None
}

/// Check if a ResolvedObject contains SET_REF
fn contains_set_ref_in_resolved_object(object: &crate::types::object::ResolvedObject) -> bool {
    use crate::types::object::ResolvedObjectElement;
    object
        .resolved_elements
        .iter()
        .any(|elem| matches!(elem, ResolvedObjectElement::SetRef { .. }))
}

/// Extract SET_REF from ResolvedObject
fn extract_set_ref_from_resolved_object(
    object: &crate::types::object::ResolvedObject,
) -> Option<String> {
    use crate::types::object::ResolvedObjectElement;
    for element in &object.resolved_elements {
        if let ResolvedObjectElement::SetRef { set_id } = element {
            return Some(set_id.clone());
        }
    }
    None
}

/// Expand a SET_REF into a list of ObjectRef
fn expand_set_ref_to_object_refs(
    set_id: &str,
    _object_id: &str,
    _criterion_type: &str,
    resolved_sets: &HashMap<String, ResolvedSetOperation>,
) -> Result<Vec<ObjectRef>, ResolutionError> {
    let resolved_set = resolved_sets.get(set_id).ok_or_else(|| {
        log_error!(
            codes::file_processing::INVALID_EXTENSION,
            &format!("SET_REF '{}' not found in resolved sets", set_id),
            "set_id" => set_id
        );

        ResolutionError::UndefinedSet {
            name: set_id.to_string(),
            context: format!("SET expansion in criterion '{}'", _criterion_type),
        }
    })?;

    let mut object_refs = Vec::new();

    // FIXED: Use correct field name "operands"
    for operand in &resolved_set.operands {
        match operand {
            ResolvedSetOperand::ObjectRef(obj_id) => {
                object_refs.push(ObjectRef {
                    object_id: obj_id.clone(),
                    span: None,
                });
            }
            // FIXED: InlineObject is a struct variant
            ResolvedSetOperand::InlineObject { identifier } => {
                object_refs.push(ObjectRef {
                    object_id: identifier.clone(),
                    span: None,
                });
            }
            ResolvedSetOperand::SetRef(nested_set_id) => {
                // Recursively expand nested SET_REF
                let nested_refs = expand_set_ref_to_object_refs(
                    nested_set_id,
                    _object_id,
                    _criterion_type,
                    resolved_sets,
                )?;
                object_refs.extend(nested_refs);
            }
            ResolvedSetOperand::FilteredObjectRef {
                object_id,
                filter: _,
            } => {
                // Add filtered object reference to results
                object_refs.push(ObjectRef {
                    object_id: object_id.clone(),
                    span: None,
                });
            }
        }
    }

    // Apply filter if present
    // FIXED: Use correct field name "filter"
    if let Some(filter) = &resolved_set.filter {
        log_debug!(
            "SET_REF has filter",
            "set_id" => set_id,
            "state_refs_count" => filter.state_refs.len()
        );

        // For now, we don't filter during expansion - filters will be applied during execution
        // This is because we don't have collected data yet
        // The executor will use the filter when validating objects
    }

    Ok(object_refs)
}

/// Validate that all SET_REF expansions are resolvable
/// Checks for circular dependencies in SET references
pub fn validate_set_expansions(context: &ResolutionContext) -> Result<(), ResolutionError> {
    // Check for circular SET_REF dependencies
    for (set_id, resolved_set) in &context.resolved_sets {
        let mut visited = HashSet::new();
        let mut path = Vec::new();

        if let Err(cycle) = check_circular_set_ref(
            set_id,
            resolved_set,
            &context.resolved_sets,
            &mut visited,
            &mut path,
        ) {
            log_error!(
                codes::file_processing::INVALID_EXTENSION,
                &format!("Circular SET_REF dependency detected: {}", cycle.join(" -> ")),
                "set_id" => set_id
            );
            return Err(ResolutionError::CircularDependency { cycle });
        }
    }

    Ok(())
}

/// Check for circular SET_REF dependencies using DFS
fn check_circular_set_ref(
    set_id: &str,
    resolved_set: &ResolvedSetOperation,
    resolved_sets: &HashMap<String, ResolvedSetOperation>,
    visited: &mut HashSet<String>,
    path: &mut Vec<String>,
) -> Result<(), Vec<String>> {
    // Check if we've seen this set_id in the current path (cycle detected)
    if path.contains(&set_id.to_string()) {
        let mut cycle = path.clone();
        cycle.push(set_id.to_string());
        return Err(cycle);
    }

    // Check if we've already validated this set in a previous path
    if visited.contains(set_id) {
        return Ok(());
    }

    visited.insert(set_id.to_string());
    path.push(set_id.to_string());

    // FIXED: Use correct field name "operands" and remove & from pattern
    for operand in &resolved_set.operands {
        if let ResolvedSetOperand::SetRef(nested_set_id) = operand {
            // FIXED: Add & for HashMap::get
            if let Some(nested_set) = resolved_sets.get(nested_set_id) {
                check_circular_set_ref(nested_set_id, nested_set, resolved_sets, visited, path)?;
            }
        }
    }

    path.pop();
    Ok(())
}
