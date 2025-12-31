use super::filter::ResolvedFilterSpec;
use common::ast::nodes::FilterSpec;
use serde::{Deserialize, Serialize};

// Re-export compiler types that we use directly
pub use common::ast::nodes::{SetOperand, SetOperationType};

/// Set operation declaration from ESP definition
/// EBNF: set_block ::= "SET" space identifier space operation_type statement_end set_operands set_filter? "SET_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetOperation {
    /// Set identifier
    pub set_id: String,
    /// Type of set operation (union, intersection, complement)
    pub operation: SetOperationType,
    /// Set operands (object refs, set refs, inline objects, filtered refs)
    pub operands: Vec<SetOperand>,
    /// Optional filter specification
    pub filter: Option<FilterSpec>,
}

/// Resolved set operation with all operands validated
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSetOperation {
    /// Set identifier
    pub set_id: String,
    /// Type of set operation
    pub operation: SetOperationType,
    /// Validated and resolved operands
    pub operands: Vec<ResolvedSetOperand>,
    /// Resolved filter if present
    pub filter: Option<ResolvedFilterSpec>,
}

/// Resolved set operand with validated references
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResolvedSetOperand {
    /// Reference to a validated global object
    ObjectRef(String),
    /// Reference to another validated set
    SetRef(String),
    /// Inline object (already resolved)
    InlineObject {
        identifier: String,
        // Full object data would be here
    },
    /// Filtered object reference with resolved filter
    FilteredObjectRef {
        object_id: String,
        filter: ResolvedFilterSpec,
    },
}

/// Set reference (used in objects and other sets)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetRef {
    pub set_id: String,
}

// ============================================================================
// IMPLEMENTATIONS
// ============================================================================

impl SetOperation {
    /// Convert from compiler AST node
    ///
    /// # Arguments
    /// * `node` - Set operation node from common AST
    ///
    /// # Example
    /// ```ignore
    /// use common::ast::nodes::SetOperation as AstSet;
    ///
    /// let ast_set = AstSet { ... };
    /// let scanner_set = SetOperation::from_ast_node(&ast_set);
    /// ```
    pub fn from_ast_node(node: &common::ast::nodes::SetOperation) -> Self {
        Self {
            set_id: node.set_id.clone(),
            operation: node.operation,
            operands: node.operands.clone(), // Already compiler type
            filter: node.filter.clone(),
        }
    }

    /// Create a new set operation
    pub fn new(
        set_id: String,
        operation: SetOperationType,
        operands: Vec<SetOperand>,
        filter: Option<FilterSpec>,
    ) -> Self {
        Self {
            set_id,
            operation,
            operands,
            filter,
        }
    }

    /// Check if this set operation has the correct number of operands for its type
    pub fn has_valid_operand_count(&self) -> bool {
        match self.operation {
            SetOperationType::Union => !self.operands.is_empty(),
            SetOperationType::Intersection => self.operands.len() >= 2,
            SetOperationType::Complement => self.operands.len() == 2,
        }
    }

    /// Get operand count
    pub fn operand_count(&self) -> usize {
        self.operands.len()
    }

    /// Check if this set has a filter
    pub fn has_filter(&self) -> bool {
        self.filter.is_some()
    }

    /// Get all object references from operands
    pub fn get_object_references(&self) -> Vec<String> {
        self.operands
            .iter()
            .filter_map(|op| op.get_object_reference())
            .collect()
    }

    /// Get all set references from operands
    pub fn get_set_references(&self) -> Vec<String> {
        self.operands
            .iter()
            .filter_map(|op| op.get_set_reference())
            .collect()
    }

    /// Get all filter state dependencies (from set filter and filtered operands)
    pub fn get_filter_dependencies(&self) -> Vec<String> {
        let mut deps = Vec::new();

        // From set-level filter
        if let Some(filter) = &self.filter {
            deps.extend(filter.state_refs.iter().map(|sr| sr.state_id.clone()));
        }

        // From filtered operands
        for operand in &self.operands {
            if let Some(filter_deps) = operand.get_filter_dependencies() {
                deps.extend(filter_deps);
            }
        }

        deps.sort();
        deps.dedup();
        deps
    }

    /// Check if this set references any inline objects
    pub fn has_inline_objects(&self) -> bool {
        self.operands
            .iter()
            .any(|op| matches!(op, SetOperand::InlineObject(_)))
    }

    /// Get count of inline objects
    pub fn inline_object_count(&self) -> usize {
        self.operands
            .iter()
            .filter(|op| matches!(op, SetOperand::InlineObject(_)))
            .count()
    }

    /// Check if this set has any external dependencies (objects, sets, filters)
    pub fn has_external_dependencies(&self) -> bool {
        !self.get_object_references().is_empty()
            || !self.get_set_references().is_empty()
            || !self.get_filter_dependencies().is_empty()
    }

    /// Validate set operation structure
    pub fn validate(&self) -> Result<(), String> {
        // Check operand count
        if !self.has_valid_operand_count() {
            return Err(format!(
                "Set '{}' has invalid operand count {} for operation {:?}",
                self.set_id,
                self.operands.len(),
                self.operation
            ));
        }

        // Complement requires exactly 2 operands
        if self.operation == SetOperationType::Complement && self.operands.len() != 2 {
            return Err(format!(
                "Set '{}': complement operation requires exactly 2 operands, got {}",
                self.set_id,
                self.operands.len()
            ));
        }

        // Union requires at least 1 operand
        if self.operation == SetOperationType::Union && self.operands.is_empty() {
            return Err(format!(
                "Set '{}': union operation requires at least 1 operand",
                self.set_id
            ));
        }

        // Intersection requires at least 2 operands
        if self.operation == SetOperationType::Intersection && self.operands.len() < 2 {
            return Err(format!(
                "Set '{}': intersection operation requires at least 2 operands, got {}",
                self.set_id,
                self.operands.len()
            ));
        }

        Ok(())
    }
}

impl ResolvedSetOperation {
    /// Create a new resolved set operation
    pub fn new(
        set_id: String,
        operation: SetOperationType,
        operands: Vec<ResolvedSetOperand>,
        filter: Option<ResolvedFilterSpec>,
    ) -> Self {
        Self {
            set_id,
            operation,
            operands,
            filter,
        }
    }

    /// Get operand count
    pub fn operand_count(&self) -> usize {
        self.operands.len()
    }

    /// Check if this resolved set is ready for execution
    pub fn is_execution_ready(&self) -> bool {
        // All references should be validated during resolution
        !self.operands.is_empty()
    }
}

// ============================================================================
// EXTENSION TRAITS - For compiler types used in scanner
// ============================================================================

/// Extension trait for compiler's SetOperand
pub trait SetOperandExt {
    fn get_object_reference(&self) -> Option<String>;
    fn get_set_reference(&self) -> Option<String>;
    fn get_filter_dependencies(&self) -> Option<Vec<String>>;
    fn operand_type_name(&self) -> &'static str;
    fn has_filter(&self) -> bool;
}

impl SetOperandExt for SetOperand {
    fn get_object_reference(&self) -> Option<String> {
        match self {
            SetOperand::ObjectRef(id) => Some(id.clone()),
            SetOperand::FilteredObjectRef { object_id, .. } => Some(object_id.clone()),
            _ => None,
        }
    }

    fn get_set_reference(&self) -> Option<String> {
        match self {
            SetOperand::SetRef(id) => Some(id.clone()),
            _ => None,
        }
    }

    fn get_filter_dependencies(&self) -> Option<Vec<String>> {
        match self {
            SetOperand::FilteredObjectRef { filter, .. } => Some(
                filter
                    .state_refs
                    .iter()
                    .map(|sr| sr.state_id.clone())
                    .collect(),
            ),
            _ => None,
        }
    }

    fn operand_type_name(&self) -> &'static str {
        match self {
            SetOperand::ObjectRef(_) => "ObjectRef",
            SetOperand::SetRef(_) => "SetRef",
            SetOperand::InlineObject(_) => "InlineObject",
            SetOperand::FilteredObjectRef { .. } => "FilteredObjectRef",
        }
    }

    fn has_filter(&self) -> bool {
        matches!(self, SetOperand::FilteredObjectRef { .. })
    }
}

// ============================================================================
// DISPLAY IMPLEMENTATIONS
// ============================================================================

impl std::fmt::Display for SetOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SET {} {} ({} operands)",
            self.set_id,
            self.operation.as_str(),
            self.operands.len()
        )?;
        if self.has_filter() {
            write!(f, " [filtered]")?;
        }
        Ok(())
    }
}

impl std::fmt::Display for ResolvedSetOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ResolvedSET {} {} ({} operands)",
            self.set_id,
            self.operation.as_str(),
            self.operands.len()
        )
    }
}

impl std::fmt::Display for SetRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SET_REF {}", self.set_id)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use common::ast::nodes::{
        SetOperand as AstOperand, SetOperation as AstSet, SetOperationType as AstSetType,
    };

    #[test]
    fn test_set_operation_ast_conversion_union() {
        // Create compiler AST node for union operation
        let ast_set = AstSet {
            set_id: "all_files".to_string(),
            operation: AstSetType::Union,
            operands: vec![
                AstOperand::ObjectRef("file1".to_string()),
                AstOperand::ObjectRef("file2".to_string()),
                AstOperand::ObjectRef("file3".to_string()),
            ],
            filter: None,
            span: None,
        };

        // Convert to scanner type
        let scanner_set = SetOperation::from_ast_node(&ast_set);

        // Verify
        assert_eq!(scanner_set.set_id, "all_files");
        assert_eq!(scanner_set.operation, AstSetType::Union);
        assert_eq!(scanner_set.operand_count(), 3);
        assert!(scanner_set.has_valid_operand_count());
        assert!(!scanner_set.has_filter());
        assert_eq!(scanner_set.validate(), Ok(()));
    }

    #[test]
    fn test_set_operation_ast_conversion_intersection() {
        // Create intersection operation
        let ast_set = AstSet {
            set_id: "common_files".to_string(),
            operation: AstSetType::Intersection,
            operands: vec![
                AstOperand::SetRef("set1".to_string()),
                AstOperand::SetRef("set2".to_string()),
            ],
            filter: None,
            span: None,
        };

        // Convert
        let scanner_set = SetOperation::from_ast_node(&ast_set);

        // Verify
        assert_eq!(scanner_set.set_id, "common_files");
        assert_eq!(scanner_set.operation, AstSetType::Intersection);
        assert_eq!(scanner_set.operand_count(), 2);
        assert!(scanner_set.has_valid_operand_count());
        assert_eq!(scanner_set.validate(), Ok(()));
    }

    #[test]
    fn test_set_operation_ast_conversion_complement() {
        // Create complement operation
        let ast_set = AstSet {
            set_id: "difference".to_string(),
            operation: AstSetType::Complement,
            operands: vec![
                AstOperand::ObjectRef("all".to_string()),
                AstOperand::ObjectRef("excluded".to_string()),
            ],
            filter: None,
            span: None,
        };

        // Convert
        let scanner_set = SetOperation::from_ast_node(&ast_set);

        // Verify
        assert_eq!(scanner_set.set_id, "difference");
        assert_eq!(scanner_set.operation, AstSetType::Complement);
        assert_eq!(scanner_set.operand_count(), 2);
        assert!(scanner_set.has_valid_operand_count());
        assert_eq!(scanner_set.validate(), Ok(()));
    }

    #[test]
    fn test_set_operation_with_mixed_operands() {
        // Create set with mixed operand types
        let ast_set = AstSet {
            set_id: "mixed_set".to_string(),
            operation: AstSetType::Union,
            operands: vec![
                AstOperand::ObjectRef("obj1".to_string()),
                AstOperand::SetRef("set1".to_string()),
            ],
            filter: None,
            span: None,
        };

        // Convert
        let scanner_set = SetOperation::from_ast_node(&ast_set);

        // Verify
        let obj_refs = scanner_set.get_object_references();
        let set_refs = scanner_set.get_set_references();
        assert_eq!(obj_refs.len(), 1);
        assert_eq!(set_refs.len(), 1);
        assert_eq!(obj_refs[0], "obj1");
        assert_eq!(set_refs[0], "set1");
    }

    #[test]
    fn test_set_operation_invalid_complement_operands() {
        // Create complement with wrong number of operands
        let ast_set = AstSet {
            set_id: "bad_complement".to_string(),
            operation: AstSetType::Complement,
            operands: vec![
                AstOperand::ObjectRef("obj1".to_string()),
                AstOperand::ObjectRef("obj2".to_string()),
                AstOperand::ObjectRef("obj3".to_string()),
            ],
            filter: None,
            span: None,
        };

        // Convert
        let scanner_set = SetOperation::from_ast_node(&ast_set);

        // Verify - should fail validation
        assert!(!scanner_set.has_valid_operand_count());
        assert!(scanner_set.validate().is_err());
    }

    #[test]
    fn test_set_operation_invalid_intersection_operands() {
        // Create intersection with only 1 operand
        let ast_set = AstSet {
            set_id: "bad_intersection".to_string(),
            operation: AstSetType::Intersection,
            operands: vec![AstOperand::ObjectRef("obj1".to_string())],
            filter: None,
            span: None,
        };

        // Convert
        let scanner_set = SetOperation::from_ast_node(&ast_set);

        // Verify - should fail validation
        assert!(!scanner_set.has_valid_operand_count());
        assert!(scanner_set.validate().is_err());
    }

    #[test]
    fn test_set_operand_extension_trait() {
        // Test extension trait methods
        let obj_operand = AstOperand::ObjectRef("test_obj".to_string());
        assert_eq!(
            obj_operand.get_object_reference(),
            Some("test_obj".to_string())
        );
        assert_eq!(obj_operand.get_set_reference(), None);
        assert_eq!(obj_operand.operand_type_name(), "ObjectRef");
        assert!(!obj_operand.has_filter());

        let set_operand = AstOperand::SetRef("test_set".to_string());
        assert_eq!(set_operand.get_object_reference(), None);
        assert_eq!(
            set_operand.get_set_reference(),
            Some("test_set".to_string())
        );
        assert_eq!(set_operand.operand_type_name(), "SetRef");
        assert!(!set_operand.has_filter());
    }

    #[test]
    fn test_set_operation_dependencies() {
        // Create set with various dependencies
        let ast_set = AstSet {
            set_id: "deps_set".to_string(),
            operation: AstSetType::Union,
            operands: vec![
                AstOperand::ObjectRef("obj1".to_string()),
                AstOperand::ObjectRef("obj2".to_string()),
                AstOperand::SetRef("set1".to_string()),
            ],
            filter: None,
            span: None,
        };

        // Convert
        let scanner_set = SetOperation::from_ast_node(&ast_set);

        // Verify dependencies
        assert!(scanner_set.has_external_dependencies());
        assert_eq!(scanner_set.get_object_references().len(), 2);
        assert_eq!(scanner_set.get_set_references().len(), 1);
    }
}
