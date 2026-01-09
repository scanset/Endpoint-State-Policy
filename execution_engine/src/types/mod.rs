// ============================================================================
// SCANNER TYPE MODULES - Complete and Corrected
// ============================================================================

// Core type definitions
pub mod common;
pub mod error;

// Declaration types
pub mod filter;
pub mod object;
pub mod runtime_operation;
pub mod set;
pub mod state;
pub mod variable;

// Criteria types
pub mod criteria;
pub mod criterion;

// Context types
pub mod execution_context;
pub mod resolution_context;

// Record traits (may be redundant with state.rs extensions)
pub mod record_traits;

// Field path extensions
pub mod field_path_extensions;
pub use field_path_extensions::*;

// Execution manifest types (new)
pub mod manifest;

// ============================================================================
// RE-EXPORTS FROM COMMON CRATE - Types scanner uses directly
// ============================================================================
// Note: Use ::common to reference the external crate (not types::common local module)

// Test specification types (used in CTN execution)
pub use ::common::{ExistenceCheck, ItemCheck, StateJoinOp, TestSpecification};

// Entity check types (used in state field validation)
pub use ::common::EntityCheck;

// Record types (used in state definitions)
pub use ::common::{RecordCheck, RecordContent, RecordField};

// Filter and object types
pub use ::common::FilterAction;
pub use ::common::FilterSpec;
pub use ::common::ObjectElement;
pub use ::common::ObjectField;
pub use ::common::ObjectRef;

// Module field type (for module specifications)
pub use ::common::FieldPath;
pub use ::common::ModuleField;

// ============================================================================
// RE-EXPORTS - Import what you need from types::*
// ============================================================================

// Core types and traits from local common module
pub use self::common::*; // DataType, ResolvedValue, RecordData, DataTypeExt, ValueExt, etc.
pub use error::*; // FieldResolutionError

// Variable types
pub use variable::*; // VariableDeclaration, ResolvedVariable

// State types
pub use state::*; // StateDeclaration, ResolvedState, RecordCheck traits

// Object types
pub use object::*; // ObjectDeclaration, ResolvedObject, ObjectElementExt

// Filter types
pub use filter::*; // FilterSpecExt, ResolvedFilterSpec, FilterResult

// Runtime operation types
pub use runtime_operation::*; // RuntimeOperation, RunParameterExt

// Set types
pub use set::*; // SetOperation, ResolvedSetOperation, SetOperandExt

// Criteria types - be specific to avoid ambiguous glob re-exports
pub use criteria::{CriteriaRoot, CriteriaTree}; // NOT ExecutableCriteriaTree - that's in execution_context
pub use criterion::*; // CriterionDeclaration, ResolvedCriterion

// Context types
pub use execution_context::*; // ExecutionContext, ExecutableCriteriaTree (the actual one we want)
pub use resolution_context::*; // ResolutionContext

// Record traits
pub use record_traits::*;

// Manifest types (new)
pub use manifest::{CtnResult, ExecutionManifest, TreeResult, TreeStats};

// ============================================================================
// TYPE ALIASES
// ============================================================================

/// Node ID for criteria tree traversal
pub type CtnNodeId = usize;
