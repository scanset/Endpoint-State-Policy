//! SET operation execution for ESP SET blocks
//! Handles union, intersection, and complement operations in definition order

use super::error::ResolutionError;
use crate::types::object::{ObjectDeclaration, ResolvedObject, ResolvedObjectElement};
use crate::types::resolution_context::ResolutionContext;
use crate::types::set::{
    ResolvedSetOperand, ResolvedSetOperation, SetOperand, SetOperation, SetOperationType,
};
use common::log_error;
use common::logging::codes;
use std::collections::HashSet;

/// Execute a SET operation and store result in resolution context
pub fn execute_set_operation(
    set_operation: &SetOperation,
    context: &mut ResolutionContext,
) -> Result<ResolvedSetOperation, ResolutionError> {
    // Validate operand count (already done by parser, but double-check)
    if let Err(validation_error) = set_operation
        .operation
        .validate_operand_count(set_operation.operands.len())
    {
        log_error!(
            codes::file_processing::INVALID_EXTENSION,
            &format!(
                "SET operation '{}' validation failed: {}",
                set_operation.set_id, validation_error
            ),
            "set_id" => &set_operation.set_id
        );
        return Err(ResolutionError::SetOperationFailed {
            set_id: set_operation.set_id.clone(),
            reason: validation_error,
        });
    }

    // Resolve all operands to concrete objects
    let mut resolved_operands = Vec::new();
    let mut operand_object_lists = Vec::new();

    for (operand_index, operand) in set_operation.operands.iter().enumerate() {
        let (resolved_operand, objects) =
            resolve_set_operand(operand, &set_operation.set_id, operand_index, context)?;

        resolved_operands.push(resolved_operand);
        operand_object_lists.push(objects);
    }

    // Execute the specific SET operation to validate the logic
    match set_operation.operation {
        SetOperationType::Union => execute_union(&operand_object_lists, &set_operation.set_id)?,
        SetOperationType::Intersection => {
            execute_intersection(&operand_object_lists, &set_operation.set_id)?
        }
        SetOperationType::Complement => {
            execute_complement(&operand_object_lists, &set_operation.set_id)?
        }
    };

    // Resolve filter if present (using existing filter resolution logic)
    let resolved_filter = if let Some(filter) = &set_operation.filter {
        // Validate that all state references exist in global states
        for state_ref in &filter.state_refs {
            if !context
                .global_states
                .iter()
                .any(|s| s.identifier == state_ref.state_id)
            {
                log_error!(
                    codes::file_processing::INVALID_EXTENSION,
                    &format!(
                        "SET filter references undefined global state '{}' in set '{}'",
                        state_ref.state_id, set_operation.set_id
                    ),
                    "set_id" => &set_operation.set_id,
                    "state_ref" => &state_ref.state_id
                );
                return Err(ResolutionError::UndefinedGlobalState {
                    name: state_ref.state_id.clone(),
                    context: format!("SET filter in set '{}'", set_operation.set_id),
                });
            }
        }

        Some(crate::types::filter::ResolvedFilterSpec::new(
            filter.action,
            filter
                .state_refs
                .iter()
                .map(|sr| sr.state_id.clone())
                .collect(),
        ))
    } else {
        None
    };

    // FIXED: Use correct field names
    let resolved_set = ResolvedSetOperation {
        set_id: set_operation.set_id.clone(),
        operation: set_operation.operation,
        operands: resolved_operands, // Not "resolved_operands"
        filter: resolved_filter,     // Not "resolved_filter"
    };

    Ok(resolved_set)
}

/// Resolve a single SET operand to concrete objects
fn resolve_set_operand(
    operand: &SetOperand,
    _set_id: &str,
    _operand_index: usize,
    context: &ResolutionContext,
) -> Result<(ResolvedSetOperand, Vec<ResolvedObject>), ResolutionError> {
    match operand {
        SetOperand::FilteredObjectRef { object_id, filter } => {
            // Convert filter to resolved filter
            let resolved_filter = crate::types::filter::ResolvedFilterSpec::new(
                filter.action,
                filter
                    .state_refs
                    .iter()
                    .map(|sr| sr.state_id.clone())
                    .collect(),
            );

            // Return the resolved operand and empty vec (no static objects yet)
            Ok((
                ResolvedSetOperand::FilteredObjectRef {
                    object_id: object_id.clone(),
                    filter: resolved_filter,
                },
                vec![],
            ))
        }
        SetOperand::ObjectRef(object_id) => {
            // FIXED: Add & for HashMap::get
            if let Some(resolved_object) = context.resolved_global_objects.get(object_id) {
                Ok((
                    ResolvedSetOperand::ObjectRef(object_id.clone()),
                    vec![resolved_object.clone()],
                ))
            } else {
                log_error!(
                    codes::file_processing::INVALID_EXTENSION,
                    &format!(
                        "OBJECT_REF '{}' in SET '{}' not found in resolved global objects",
                        object_id, _set_id
                    ),
                    "object_id" => object_id,
                    "set_id" => _set_id
                );

                Err(ResolutionError::UndefinedGlobalObject {
                    name: object_id.clone(),
                    context: format!("SET operand in set '{}'", _set_id),
                })
            }
        }

        SetOperand::SetRef(referenced_set_id) => {
            // Look for set in resolved sets (must be resolved before this set)
            if let Some(resolved_set) = context.resolved_sets.get(referenced_set_id) {
                // Extract objects from the resolved set's operands
                let mut objects = Vec::new();
                // FIXED: Use correct field name "operands"
                for resolved_operand in &resolved_set.operands {
                    match resolved_operand {
                        ResolvedSetOperand::ObjectRef(obj_id) => {
                            // FIXED: Add & for HashMap::get
                            if let Some(resolved_obj) = context.resolved_global_objects.get(obj_id)
                            {
                                objects.push(resolved_obj.clone());
                            }
                        }
                        // FIXED: InlineObject is a struct variant
                        ResolvedSetOperand::InlineObject { identifier } => {
                            // Try to find the object by identifier
                            if let Some(resolved_obj) =
                                context.resolved_global_objects.get(identifier)
                            {
                                objects.push(resolved_obj.clone());
                            }
                        }
                        ResolvedSetOperand::SetRef(_) => {
                            // Nested set reference - this would require recursive resolution
                            // For now, log a warning and skip
                        }
                        ResolvedSetOperand::FilteredObjectRef {
                            object_id,
                            filter: _,
                        } => {
                            // Include the object
                            if let Some(resolved_obj) =
                                context.resolved_global_objects.get(object_id)
                            {
                                objects.push(resolved_obj.clone());
                            }
                        }
                    }
                }

                Ok((
                    ResolvedSetOperand::SetRef(referenced_set_id.clone()),
                    objects,
                ))
            } else {
                log_error!(
                    codes::file_processing::INVALID_EXTENSION,
                    &format!(
                        "SET_REF '{}' in SET '{}' not found in resolved sets",
                        referenced_set_id, _set_id
                    ),
                    "referenced_set_id" => referenced_set_id,
                    "set_id" => _set_id
                );

                Err(ResolutionError::UndefinedSet {
                    name: referenced_set_id.clone(),
                    context: format!("SET operand in set '{}'", _set_id),
                })
            }
        }

        SetOperand::InlineObject(object_decl) => {
            // Resolve inline object using existing object resolution logic
            let scanner_obj = ObjectDeclaration::from_ast_node(object_decl);
            let resolved_object = resolve_inline_object(&scanner_obj, context)?;

            // FIXED: Use struct variant syntax
            Ok((
                ResolvedSetOperand::InlineObject {
                    identifier: resolved_object.identifier.clone(),
                },
                vec![resolved_object],
            ))
        }
    }
}

/// Resolve inline object using existing field resolution patterns
fn resolve_inline_object(
    object_decl: &crate::types::object::ObjectDeclaration,
    context: &ResolutionContext,
) -> Result<ResolvedObject, ResolutionError> {
    let mut resolved_elements = Vec::new();

    // For now, only handle Field elements (follow existing patterns)
    for element in &object_decl.elements {
        // FIXED: ObjectElement::Field is a tuple variant in the compiler
        if let common::ast::nodes::ObjectElement::Field(field) = element {
            // Resolve the field value using existing field resolver logic
            let resolved_value = match &field.value {
                common::ast::nodes::Value::String(s) => {
                    crate::types::common::ResolvedValue::String(s.clone())
                }
                // FIXED: Don't dereference Copy types
                common::ast::nodes::Value::Integer(i) => {
                    crate::types::common::ResolvedValue::Integer(*i)
                }
                common::ast::nodes::Value::Float(f) => {
                    crate::types::common::ResolvedValue::Float(*f)
                }
                common::ast::nodes::Value::Boolean(b) => {
                    crate::types::common::ResolvedValue::Boolean(*b)
                }
                common::ast::nodes::Value::Variable(var_name) => {
                    // FIXED: Add & for HashMap::get
                    if let Some(resolved_var) = context.resolved_variables.get(var_name) {
                        resolved_var.value.clone()
                    } else {
                        return Err(ResolutionError::UndefinedVariable {
                            name: var_name.clone(),
                            context: "Inline object in SET".to_string(),
                        });
                    }
                }
            };

            resolved_elements.push(ResolvedObjectElement::Field {
                name: field.name.clone(),
                value: resolved_value,
            });
        }
        // Handle other element types as needed
    }

    Ok(ResolvedObject {
        identifier: object_decl.identifier.clone(),
        resolved_elements,
        is_global: object_decl.is_global,
    })
}

/// Execute UNION operation - all objects from all operands (no duplicates)
fn execute_union(
    object_lists: &[Vec<ResolvedObject>],
    _set_id: &str,
) -> Result<Vec<ResolvedObject>, ResolutionError> {
    let mut result_objects = Vec::new();
    let mut seen_identifiers = HashSet::new();

    // Combine all objects, maintaining uniqueness by identifier
    for object_list in object_lists {
        for object in object_list {
            if !seen_identifiers.contains(&object.identifier) {
                seen_identifiers.insert(object.identifier.clone());
                result_objects.push(object.clone());
            }
        }
    }

    Ok(result_objects)
}

/// Execute INTERSECTION operation - objects present in ALL operands
fn execute_intersection(
    object_lists: &[Vec<ResolvedObject>],
    _set_id: &str,
) -> Result<Vec<ResolvedObject>, ResolutionError> {
    if object_lists.is_empty() {
        return Ok(Vec::new());
    }

    if object_lists.len() == 1 {
        return Ok(object_lists[0].clone());
    }

    // Start with first operand's objects
    let mut result_objects = Vec::new();
    let first_list = &object_lists[0];

    for object in first_list {
        // Check if this object exists in ALL other operands
        let exists_in_all = object_lists[1..].iter().all(|other_list| {
            other_list
                .iter()
                .any(|other_obj| other_obj.identifier == object.identifier)
        });

        if exists_in_all {
            result_objects.push(object.clone());
        }
    }

    Ok(result_objects)
}

/// Execute COMPLEMENT operation - objects in first but not in second (A - B)
fn execute_complement(
    object_lists: &[Vec<ResolvedObject>],
    _set_id: &str,
) -> Result<Vec<ResolvedObject>, ResolutionError> {
    if object_lists.len() != 2 {
        return Err(ResolutionError::SetOperationFailed {
            set_id: _set_id.to_string(),
            reason: format!(
                "COMPLEMENT requires exactly 2 operands, got {}",
                object_lists.len()
            ),
        });
    }

    let first_list = &object_lists[0];
    let second_list = &object_lists[1];

    // Build set of identifiers from second operand
    let second_identifiers: HashSet<String> = second_list
        .iter()
        .map(|obj| obj.identifier.clone())
        .collect();

    // Keep objects from first operand that are NOT in second operand
    let mut result_objects = Vec::new();

    for object in first_list {
        if !second_identifiers.contains(&object.identifier) {
            result_objects.push(object.clone());
        }
    }

    Ok(result_objects)
}

/// Execute all SET operations in definition order
pub fn resolve_set_operations(context: &mut ResolutionContext) -> Result<(), ResolutionError> {
    // Clone set operations to avoid borrow checker issues
    let set_operations = context.set_operations.clone();

    for set_operation in set_operations.iter() {
        // Execute the SET operation
        let resolved_set = execute_set_operation(set_operation, context)?;

        // Store resolved set in context for subsequent SET_REF resolution
        context
            .resolved_sets
            .insert(set_operation.set_id.clone(), resolved_set);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_union_operation() {
        // Create test objects
        let obj1 = ResolvedObject {
            identifier: "obj1".to_string(),
            resolved_elements: vec![],
            is_global: true,
        };
        let obj2 = ResolvedObject {
            identifier: "obj2".to_string(),
            resolved_elements: vec![],
            is_global: true,
        };
        let obj3 = ResolvedObject {
            identifier: "obj1".to_string(), // Duplicate ID
            resolved_elements: vec![],
            is_global: true,
        };

        let object_lists = vec![
            vec![obj1.clone()],
            vec![obj2.clone(), obj3], // obj3 should be deduplicated
        ];

        let result = execute_union(&object_lists, "test_union").unwrap();

        assert_eq!(result.len(), 2); // Should have obj1 and obj2, no duplicates
        assert!(result.iter().any(|obj| obj.identifier == "obj1"));
        assert!(result.iter().any(|obj| obj.identifier == "obj2"));
    }

    #[test]
    fn test_intersection_operation() {
        // Create test objects
        let obj1 = ResolvedObject {
            identifier: "obj1".to_string(),
            resolved_elements: vec![],
            is_global: true,
        };
        let obj2 = ResolvedObject {
            identifier: "obj2".to_string(),
            resolved_elements: vec![],
            is_global: true,
        };
        let obj1_copy = ResolvedObject {
            identifier: "obj1".to_string(),
            resolved_elements: vec![],
            is_global: true,
        };

        let object_lists = vec![
            vec![obj1.clone(), obj2.clone()],
            vec![
                obj1_copy,
                ResolvedObject {
                    identifier: "obj3".to_string(),
                    resolved_elements: vec![],
                    is_global: true,
                },
            ],
        ];

        let result = execute_intersection(&object_lists, "test_intersection").unwrap();

        assert_eq!(result.len(), 1); // Only obj1 is in both lists
        assert_eq!(result[0].identifier, "obj1");
    }

    #[test]
    fn test_complement_operation() {
        // Create test objects
        let obj1 = ResolvedObject {
            identifier: "obj1".to_string(),
            resolved_elements: vec![],
            is_global: true,
        };
        let obj2 = ResolvedObject {
            identifier: "obj2".to_string(),
            resolved_elements: vec![],
            is_global: true,
        };
        let obj1_copy = ResolvedObject {
            identifier: "obj1".to_string(),
            resolved_elements: vec![],
            is_global: true,
        };

        let object_lists = vec![
            vec![obj1.clone(), obj2.clone()], // First operand: obj1, obj2
            vec![obj1_copy],                  // Second operand: obj1
        ];

        let result = execute_complement(&object_lists, "test_complement").unwrap();

        assert_eq!(result.len(), 1); // obj2 should remain (obj1 is removed)
        assert_eq!(result[0].identifier, "obj2");
    }

    #[test]
    fn test_complement_wrong_operand_count() {
        let object_lists = vec![
            vec![ResolvedObject {
                identifier: "obj1".to_string(),
                resolved_elements: vec![],
                is_global: true,
            }],
            // Only one operand (complement needs 2)
        ];

        let result = execute_complement(&object_lists, "test_bad_complement");
        assert!(result.is_err());
    }
}
