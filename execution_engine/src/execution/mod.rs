pub mod behavior;
pub mod comparisons;
pub mod deferred_ops;
pub mod engine;
pub mod entity_check;
pub mod filter_evaluation;
pub mod helpers;
pub mod module_version;
pub mod record_validation;
pub mod structured_params;

pub use filter_evaluation::FilterEvaluator;

// Export engine-specific types
// Note: CtnResult, TreeResult, ExecutionManifest are in crate::types::manifest
pub use engine::{ExecutionEngine, ExecutionError, PolicyExecutionResult};

// Export behavior utilities
pub use behavior::{extract_behavior_hints, BehaviorHints};

// Helper functions for executors
pub use helpers::{
    evaluate_entity_check, evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
};

// Comparison utilities
pub use comparisons::{binary, collection, evr, string, ComparisonExt};
pub use record_validation::{validate_record_checks, RecordValidationResult};
pub use structured_params::parse_parameters;
