//! AST to Scanner Types Conversion
//!
//! Converts ESP compiler AST (EspFile) to scanner-base types for execution.
//! This module bridges the compiler output with the scanner engine.

use crate::types::*;
use ::common::ast::nodes as ast;
use ::common::metadata::MetaDataBlock;

/// Result type for conversion operations
pub type ConversionResult<T> = Result<T, ConversionError>;

/// Error type for conversion failures
#[derive(Debug, Clone)]
pub enum ConversionError {
    /// Invalid AST structure
    InvalidAst(String),
    /// Missing required field
    MissingField(String),
    /// Unsupported feature
    UnsupportedFeature(String),
}

impl std::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConversionError::InvalidAst(msg) => write!(f, "Invalid AST: {}", msg),
            ConversionError::MissingField(field) => write!(f, "Missing field: {}", field),
            ConversionError::UnsupportedFeature(feature) => {
                write!(f, "Unsupported feature: {}", feature)
            }
        }
    }
}

impl std::error::Error for ConversionError {}

/// Convert compiler AST to scanner types
///
/// Takes an `EspFile` from the compiler and returns all the scanner-base types
/// needed to create an execution context.
///
/// # Arguments
/// * `ast` - The compiled ESP file AST
///
/// # Returns
/// A tuple of:
/// - Variables
/// - States
/// - Objects
/// - Runtime operations
/// - Set operations
/// - Criteria root (tree structure)
/// - Metadata block
///
/// # Example
/// ```ignore
/// use agent_core::conversion::convert_ast_to_scanner_types;
///
/// let ast = compiler::compile_file("policy.esp")?;
/// let (variables, states, objects, runtime_ops, sets, criteria, metadata) =
///     convert_ast_to_scanner_types(&ast)?;
/// ```
#[allow(clippy::type_complexity)]
pub fn convert_ast_to_scanner_types(
    ast: &ast::EspFile,
) -> ConversionResult<(
    Vec<VariableDeclaration>,
    Vec<StateDeclaration>,
    Vec<ObjectDeclaration>,
    Vec<RuntimeOperation>,
    Vec<SetOperation>,
    CriteriaRoot,
    MetaDataBlock,
)> {
    // Metadata
    let metadata = convert_metadata(&ast.metadata);

    // Variables
    let variables = convert_variables(&ast.definition.variables);

    // States
    let states = convert_states(&ast.definition.states);

    // Objects
    let objects = convert_objects(&ast.definition.objects);

    // Runtime operations
    let runtime_operations = convert_runtime_operations(&ast.definition.runtime_operations);

    // Set operations
    let sets = convert_set_operations(&ast.definition.set_operations);

    // Build CriteriaRoot tree structure
    let mut node_id_counter = 1;
    let criteria_root =
        build_criteria_root_from_ast(&ast.definition.criteria, &mut node_id_counter)?;

    Ok((
        variables,
        states,
        objects,
        runtime_operations,
        sets,
        criteria_root,
        metadata,
    ))
}

/// Convert metadata block from AST
fn convert_metadata(meta: &Option<ast::MetadataBlock>) -> MetaDataBlock {
    if let Some(meta) = meta {
        let mut fields = std::collections::HashMap::new();
        for field in &meta.fields {
            fields.insert(field.name.clone(), field.value.clone());
        }
        MetaDataBlock { fields }
    } else {
        MetaDataBlock::default()
    }
}

/// Convert variable declarations from AST
fn convert_variables(ast_variables: &[ast::VariableDeclaration]) -> Vec<VariableDeclaration> {
    ast_variables
        .iter()
        .map(|v| VariableDeclaration {
            name: v.name.clone(),
            data_type: v.data_type,
            initial_value: v.initial_value.clone(),
        })
        .collect()
}

/// Convert state declarations from AST
fn convert_states(ast_states: &[ast::StateDefinition]) -> Vec<StateDeclaration> {
    ast_states
        .iter()
        .map(|s| {
            let fields: Vec<StateField> = s
                .fields
                .iter()
                .map(|f| StateField {
                    name: f.name.clone(),
                    data_type: f.data_type,
                    operation: f.operation,
                    value: f.value.clone(),
                    entity_check: f.entity_check,
                })
                .collect();

            StateDeclaration {
                identifier: s.id.clone(),
                fields,
                record_checks: s.record_checks.clone(),
                is_global: s.is_global,
            }
        })
        .collect()
}

/// Convert object declarations from AST
fn convert_objects(ast_objects: &[ast::ObjectDefinition]) -> Vec<ObjectDeclaration> {
    ast_objects
        .iter()
        .map(|o| ObjectDeclaration {
            identifier: o.id.clone(),
            elements: o.elements.clone(),
            is_global: o.is_global,
        })
        .collect()
}

/// Convert runtime operations from AST
fn convert_runtime_operations(ast_operations: &[ast::RuntimeOperation]) -> Vec<RuntimeOperation> {
    ast_operations
        .iter()
        .map(|r| RuntimeOperation {
            target_variable: r.target_variable.clone(),
            operation_type: r.operation_type,
            parameters: r.parameters.clone(),
        })
        .collect()
}

/// Convert set operations from AST
fn convert_set_operations(ast_sets: &[ast::SetOperation]) -> Vec<SetOperation> {
    ast_sets
        .iter()
        .map(|s| SetOperation {
            set_id: s.set_id.clone(),
            operation: s.operation,
            operands: s.operands.clone(),
            filter: s.filter.clone(),
        })
        .collect()
}

/// Build CriteriaRoot tree structure from compiler AST
fn build_criteria_root_from_ast(
    criteria_nodes: &[ast::CriteriaNode],
    node_id_counter: &mut usize,
) -> ConversionResult<CriteriaRoot> {
    let mut trees = Vec::new();

    for cri_node in criteria_nodes {
        let tree = convert_criteria_node_to_tree(cri_node, node_id_counter)?;
        trees.push(tree);
    }

    Ok(CriteriaRoot {
        trees,
        root_logical_op: LogicalOp::And,
    })
}

/// Convert a compiler CriteriaNode to scanner CriteriaTree
fn convert_criteria_node_to_tree(
    cri_node: &ast::CriteriaNode,
    node_id_counter: &mut usize,
) -> ConversionResult<CriteriaTree> {
    let mut children = Vec::new();

    for content in &cri_node.content {
        match content {
            ast::CriteriaContent::Criterion(ctn_node) => {
                let node_id = *node_id_counter;
                *node_id_counter += 1;

                let mut declaration = convert_ctn_to_declaration(ctn_node)?;
                declaration.ctn_node_id = Some(node_id);

                children.push(CriteriaTree::Criterion {
                    declaration,
                    node_id,
                });
            }
            ast::CriteriaContent::Criteria(nested_cri) => {
                let nested_tree = convert_criteria_node_to_tree(nested_cri, node_id_counter)?;
                children.push(nested_tree);
            }
        }
    }

    // If only one child, unwrap it
    if children.len() == 1 {
        return children
            .into_iter()
            .next()
            .ok_or_else(|| ConversionError::InvalidAst("Expected at least one child".to_string()));
    }

    // Create Block node with proper logical operator
    let logical_op = match cri_node.logical_op {
        ast::LogicalOp::And => LogicalOp::And,
        ast::LogicalOp::Or => LogicalOp::Or,
    };

    Ok(CriteriaTree::Block {
        logical_op,
        negate: cri_node.negate,
        children,
    })
}

/// Convert compiler CriterionNode to scanner CriterionDeclaration
fn convert_ctn_to_declaration(
    ctn_node: &ast::CriterionNode,
) -> ConversionResult<CriterionDeclaration> {
    // Convert local states
    let local_states: Vec<StateDeclaration> = ctn_node
        .local_states
        .iter()
        .map(|ls| {
            let fields: Vec<StateField> = ls
                .fields
                .iter()
                .map(|f| StateField {
                    name: f.name.clone(),
                    data_type: f.data_type,
                    operation: f.operation,
                    value: f.value.clone(),
                    entity_check: f.entity_check,
                })
                .collect();

            StateDeclaration {
                identifier: ls.id.clone(),
                fields,
                record_checks: ls.record_checks.clone(),
                is_global: false,
            }
        })
        .collect();

    // Convert local object
    let local_object = ctn_node.local_object.as_ref().map(|lo| ObjectDeclaration {
        identifier: lo.id.clone(),
        elements: lo.elements.clone(),
        is_global: false,
    });

    Ok(CriterionDeclaration {
        criterion_type: ctn_node.criterion_type.clone(),
        test: ctn_node.test.clone(),
        state_refs: ctn_node.state_refs.clone(),
        object_refs: ctn_node.object_refs.clone(),
        set_refs: ctn_node.set_refs.clone(),
        local_states,
        local_object,
        ctn_node_id: None,
    })
}
