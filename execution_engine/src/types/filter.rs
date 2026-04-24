use common::ast::nodes::{FilterAction, FilterSpec};
use serde::{Deserialize, Serialize};

// Re-export compiler types for convenience
pub use common::ast::nodes::FilterAction as FilterActionType;
pub use common::ast::nodes::FilterSpec as FilterSpecType;

/// Resolved filter specification with validated state references
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedFilterSpec {
    /// Filter action (include/exclude)
    pub action: FilterAction,
    /// Validated state references (guaranteed to exist as global states)
    pub state_refs: Vec<String>,
}

impl ResolvedFilterSpec {
    /// Create a new resolved filter specification
    pub fn new(action: FilterAction, state_refs: Vec<String>) -> Self {
        Self { action, state_refs }
    }

    /// Check if this filter should include items that satisfy the states
    pub fn should_include_on_satisfaction(&self) -> bool {
        matches!(self.action, FilterAction::Include)
    }

    /// Check if this filter should exclude items that satisfy the states
    pub fn should_exclude_on_satisfaction(&self) -> bool {
        matches!(self.action, FilterAction::Exclude)
    }
}

/// Filter application context for execution (scanner-specific)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FilterContext {
    /// Filter applied to object collection
    ObjectFilter,
    /// Filter applied to set operands
    SetFilter,
}

/// Filter evaluation result (scanner-specific)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FilterResult {
    /// Item should be included
    Include,
    /// Item should be excluded
    Exclude,
    /// Cannot determine (e.g., state evaluation failed)
    Unknown,
}

impl FilterResult {
    /// Check if this result allows the item to be included
    pub fn allows_inclusion(&self) -> bool {
        matches!(self, Self::Include)
    }

    /// Check if this result requires exclusion
    pub fn requires_exclusion(&self) -> bool {
        matches!(self, Self::Exclude)
    }

    /// Check if the result is indeterminate
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

// ============================================================================
// EXTENSION TRAITS - For compiler types used in scanner
// ============================================================================

/// Extension trait for compiler's FilterSpec to add scanner-specific helpers
pub trait FilterSpecExt {
    fn has_state_references(&self) -> bool;
    fn state_reference_count(&self) -> usize;
    fn references_state(&self, state_id: &str) -> bool;
    fn get_state_dependencies(&self) -> Vec<String>;
    fn validate(&self) -> Result<(), String>;
    fn evaluate(&self, states_satisfied: bool) -> FilterResult;
    fn default_result(&self) -> FilterResult;
}

impl FilterSpecExt for FilterSpec {
    fn has_state_references(&self) -> bool {
        !self.state_refs.is_empty()
    }

    fn state_reference_count(&self) -> usize {
        self.state_refs.len()
    }

    fn references_state(&self, state_id: &str) -> bool {
        self.state_refs.iter().any(|sr| sr.state_id == state_id)
    }

    fn get_state_dependencies(&self) -> Vec<String> {
        self.state_refs
            .iter()
            .map(|sr| sr.state_id.clone())
            .collect()
    }

    fn validate(&self) -> Result<(), String> {
        if self.state_refs.is_empty() {
            return Err("Filter must reference at least one state".to_string());
        }
        Ok(())
    }

    /// Determine filter result based on state satisfaction and action
    fn evaluate(&self, states_satisfied: bool) -> FilterResult {
        match (self.action, states_satisfied) {
            (FilterAction::Include, true) => FilterResult::Include,
            (FilterAction::Include, false) => FilterResult::Exclude,
            (FilterAction::Exclude, true) => FilterResult::Exclude,
            (FilterAction::Exclude, false) => FilterResult::Include,
        }
    }

    /// Get the default result when state evaluation is impossible
    fn default_result(&self) -> FilterResult {
        match self.action {
            FilterAction::Include => FilterResult::Exclude, // Conservative: exclude if unsure
            FilterAction::Exclude => FilterResult::Include, // Conservative: include if unsure
        }
    }
}

// ============================================================================
// DISPLAY IMPLEMENTATIONS
// ============================================================================

impl std::fmt::Display for FilterResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Include => write!(f, "include"),
            Self::Exclude => write!(f, "exclude"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl std::fmt::Display for ResolvedFilterSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Convert FilterAction to string inline since we can't implement Display for it
        let action_str = match self.action {
            FilterAction::Include => "include",
            FilterAction::Exclude => "exclude",
        };
        write!(f, "FILTER {} [{}]", action_str, self.state_refs.join(", "))
    }
}

// ============================================================================
// FILTER DEPENDENCY TRACKING
// ============================================================================

/// Filter dependency tracking for DAG construction (scanner-specific)
pub trait FilterDependencies {
    fn get_filter_dependencies(&self) -> Vec<String>;
}

impl FilterDependencies for FilterSpec {
    fn get_filter_dependencies(&self) -> Vec<String> {
        self.state_refs
            .iter()
            .map(|sr| sr.state_id.clone())
            .collect()
    }
}

impl FilterDependencies for Vec<FilterSpec> {
    fn get_filter_dependencies(&self) -> Vec<String> {
        let mut deps: Vec<String> = self
            .iter()
            .flat_map(|filter| filter.state_refs.iter().map(|sr| sr.state_id.clone()))
            .collect();
        deps.sort();
        deps.dedup();
        deps
    }
}
