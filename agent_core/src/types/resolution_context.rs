use crate::types::{
    criteria::CriteriaRoot,
    criterion::CriterionDeclaration,
    object::{ObjectDeclaration, ResolvedObject},
    runtime_operation::RuntimeOperation,
    set::{ResolvedSetOperation, SetOperation},
    state::{ResolvedState, StateDeclaration},
    variable::{ResolvedVariable, VariableDeclaration},
    CtnNodeId,
};
use common::metadata::MetaDataBlock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Context for resolution phase
///
/// This context starts with unresolved declarations (input)
/// and accumulates resolved results during resolution (output).
///
/// Resolution Flow:
/// 1. Create ResolutionContext from AST (populate input fields)
/// 2. ResolutionEngine processes and populates output fields
/// 3. ExecutionContext is built from the resolved output fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolutionContext {
    // ========================================================================
    // INPUT - Unresolved declarations from AST
    // ========================================================================
    /// Unresolved variable declarations
    pub variables: Vec<VariableDeclaration>,

    /// Unresolved state declarations
    pub states: Vec<StateDeclaration>,

    /// Unresolved object declarations
    pub objects: Vec<ObjectDeclaration>,

    /// Unresolved runtime operations (RUN blocks)
    pub runtime_operations: Vec<RuntimeOperation>,

    /// Unresolved set operations (SET blocks)
    pub sets: Vec<SetOperation>,

    /// DEPRECATED: Unresolved criteria declarations (CTN blocks) - kept for compatibility
    /// Use criteria_root instead
    pub criteria: Vec<CriterionDeclaration>,

    // ========================================================================
    // OUTPUT - Resolved results (populated during resolution)
    // ========================================================================
    /// Resolved variables (after DAG ordering and substitution)
    #[serde(default)]
    pub resolved_variables: HashMap<String, ResolvedVariable>,

    /// Resolved global states (after variable substitution)
    #[serde(default)]
    pub resolved_global_states: HashMap<String, ResolvedState>,

    /// Resolved global objects (after variable substitution)
    #[serde(default)]
    pub resolved_global_objects: HashMap<String, ResolvedObject>,

    /// Resolved set operations (after expansion and filtering)
    #[serde(default)]
    pub resolved_sets: HashMap<String, ResolvedSetOperation>,

    /// Resolved local states per CTN (CTN-specific states)
    #[serde(default)]
    pub resolved_local_states: HashMap<CtnNodeId, Vec<ResolvedState>>,

    /// Resolved local objects per CTN (CTN-specific objects)
    #[serde(default)]
    pub resolved_local_objects: HashMap<CtnNodeId, ResolvedObject>,

    /// FIXED: Criteria tree structure (organized CTN hierarchy)
    /// This is the properly structured tree that preserves CRI OR/AND semantics
    #[serde(default)]
    pub criteria_root: CriteriaRoot,

    /// Deferred operations to execute at scan time
    #[serde(default)]
    pub scan_time_operations: Vec<DeferredOperation>,

    /// Metadata from ESP definition
    #[serde(default)]
    pub metadata: MetaDataBlock,

    // ========================================================================
    // WORKING DATA - Temporary data during resolution
    // ========================================================================
    /// Global states (subset of `states` marked as global)
    #[serde(skip)]
    pub global_states: Vec<StateDeclaration>,

    /// Global objects (subset of `objects` marked as global)
    #[serde(skip)]
    pub global_objects: Vec<ObjectDeclaration>,

    /// Set operations (alias for `sets`, used by some code)
    #[serde(skip)]
    pub set_operations: Vec<SetOperation>,

    /// CTN-local objects (temporary storage during resolution)
    #[serde(skip)]
    pub ctn_local_objects: HashMap<CtnNodeId, ObjectDeclaration>,

    /// CTN-local states (temporary storage during resolution)
    #[serde(skip)]
    pub ctn_local_states: HashMap<CtnNodeId, Vec<StateDeclaration>>,

    /// Relationships between symbols (for DAG construction)
    #[serde(skip)]
    pub relationships: Vec<SymbolRelationship>,
}

/// Deferred operation to execute at scan time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredOperation {
    pub target_variable: String,
    pub operation: RuntimeOperation,
    pub dependencies: Vec<String>,
}

/// Symbol relationship for dependency tracking
#[derive(Debug, Clone)]
pub struct SymbolRelationship {
    pub from: String,
    pub to: String,
    pub relationship_type: RelationshipType,
}

#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
pub enum RelationshipType {
    VariableReference,
    StateReference,
    ObjectReference,
    SetReference,
}

impl ResolutionContext {
    /// Create a new resolution context from unresolved declarations
    /// DEPRECATED: Use from_ast_with_criteria_root instead
    pub fn new(
        variables: Vec<VariableDeclaration>,
        states: Vec<StateDeclaration>,
        objects: Vec<ObjectDeclaration>,
        runtime_operations: Vec<RuntimeOperation>,
        sets: Vec<SetOperation>,
        criteria: Vec<CriterionDeclaration>,
    ) -> Self {
        // Separate global vs local
        let global_states: Vec<_> = states.iter().filter(|s| s.is_global).cloned().collect();
        let global_objects: Vec<_> = objects.iter().filter(|o| o.is_global).cloned().collect();

        Self {
            variables,
            states,
            objects,
            runtime_operations: runtime_operations.clone(),
            sets: sets.clone(),
            criteria,

            // Initialize empty output fields
            resolved_variables: HashMap::new(),
            resolved_global_states: HashMap::new(),
            resolved_global_objects: HashMap::new(),
            resolved_sets: HashMap::new(),
            resolved_local_states: HashMap::new(),
            resolved_local_objects: HashMap::new(),
            criteria_root: CriteriaRoot::default(),
            scan_time_operations: Vec::new(),
            metadata: MetaDataBlock::default(),

            // Initialize working data
            global_states,
            global_objects,
            set_operations: sets,
            ctn_local_objects: HashMap::new(),
            ctn_local_states: HashMap::new(),
            relationships: Vec::new(),
        }
    }

    /// FIXED: Create from AST nodes with proper CriteriaRoot structure
    /// This is the correct constructor that preserves the hierarchical CRI/CTN structure
    pub fn from_ast_with_criteria_root(
        variables: Vec<VariableDeclaration>,
        states: Vec<StateDeclaration>,
        objects: Vec<ObjectDeclaration>,
        runtime_operations: Vec<RuntimeOperation>,
        sets: Vec<SetOperation>,
        criteria_root: CriteriaRoot,
        metadata: MetaDataBlock,
    ) -> Self {
        // Separate global vs local
        let global_states: Vec<_> = states.iter().filter(|s| s.is_global).cloned().collect();
        let global_objects: Vec<_> = objects.iter().filter(|o| o.is_global).cloned().collect();

        // Extract flat criteria list for compatibility (some code may still use it)
        let criteria = criteria_root
            .get_all_criteria()
            .into_iter()
            .cloned()
            .collect();

        Self {
            variables,
            states,
            objects,
            runtime_operations: runtime_operations.clone(),
            sets: sets.clone(),
            criteria,

            // Initialize empty output fields
            resolved_variables: HashMap::new(),
            resolved_global_states: HashMap::new(),
            resolved_global_objects: HashMap::new(),
            resolved_sets: HashMap::new(),
            resolved_local_states: HashMap::new(),
            resolved_local_objects: HashMap::new(),

            // FIXED: Initialize with the actual CriteriaRoot from AST
            criteria_root,

            scan_time_operations: Vec::new(),
            metadata,

            // Initialize working data
            global_states,
            global_objects,
            set_operations: sets,
            ctn_local_objects: HashMap::new(),
            ctn_local_states: HashMap::new(),
            relationships: Vec::new(),
        }
    }

    /// DEPRECATED: Create from AST nodes (for compatibility)
    /// This version builds a default flat criteria structure - use from_ast_with_criteria_root instead
    pub fn from_ast(
        variables: Vec<VariableDeclaration>,
        states: Vec<StateDeclaration>,
        objects: Vec<ObjectDeclaration>,
        runtime_operations: Vec<RuntimeOperation>,
        sets: Vec<SetOperation>,
        criteria: Vec<CriterionDeclaration>,
        metadata: MetaDataBlock,
    ) -> Self {
        let mut context = Self::new(
            variables,
            states,
            objects,
            runtime_operations,
            sets,
            criteria.clone(),
        );
        context.metadata = metadata;

        // Build a simple flat CriteriaRoot from the criteria list
        // This preserves backward compatibility but loses hierarchical structure
        use crate::types::common::LogicalOp;
        let mut node_id = 1;
        let trees: Vec<_> = criteria
            .iter()
            .map(|c| {
                let id = node_id;
                node_id += 1;
                crate::types::criteria::CriteriaTree::Criterion {
                    declaration: c.clone(),
                    node_id: id,
                }
            })
            .collect();

        context.criteria_root = CriteriaRoot {
            trees,
            root_logical_op: LogicalOp::And,
        };

        context
    }
}

impl Default for CriteriaRoot {
    fn default() -> Self {
        Self {
            trees: Vec::new(),
            root_logical_op: crate::types::common::LogicalOp::And,
        }
    }
}
