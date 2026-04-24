use super::common::{DataType, ResolvedValue, Value, ValueExt};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Resolved variable with concrete value (scanner-specific output type)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedVariable {
    pub identifier: String,
    pub data_type: DataType,
    pub value: ResolvedValue,
}

/// Variable declaration from ESP definition (scanner working type)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VariableDeclaration {
    pub name: String,
    pub data_type: DataType,
    pub initial_value: Option<Value>,
}

impl ResolvedVariable {
    /// Create a new resolved variable
    pub fn new(identifier: String, data_type: DataType, value: ResolvedValue) -> Self {
        Self {
            identifier,
            data_type,
            value,
        }
    }

    /// Check if the resolved value matches the declared data type
    pub fn is_type_consistent(&self) -> bool {
        use super::common::DataTypeExt;
        self.data_type.matches_resolved_value(&self.value)
    }

    /// Get the variable name
    pub fn name(&self) -> &str {
        &self.identifier
    }

    /// Get the resolved value
    pub fn resolved_value(&self) -> &ResolvedValue {
        &self.value
    }

    /// Check if this was originally a computed variable
    pub fn was_computed(&self) -> bool {
        // This information should come from the original declaration
        // We'll need to track this during resolution
        false // Placeholder - will be set during resolution
    }

    /// Create a resolved variable from a computed variable (populated by RUN operation)
    pub fn from_computed(identifier: String, data_type: DataType, value: ResolvedValue) -> Self {
        // Could add a flag here to track that it was computed
        Self {
            identifier,
            data_type,
            value,
        }
    }
}

impl VariableDeclaration {
    /// Create a new variable declaration
    pub fn new(name: String, data_type: DataType, initial_value: Option<Value>) -> Self {
        Self {
            name,
            data_type,
            initial_value,
        }
    }

    /// Convert from compiler AST node
    ///
    /// # Arguments
    /// * `node` - Variable declaration node from common AST
    ///
    /// # Example
    /// ```ignore
    /// use common::ast::nodes::VariableDeclaration as AstVar;
    ///
    /// let ast_var = AstVar { ... };
    /// let scanner_var = VariableDeclaration::from_ast_node(&ast_var);
    /// ```
    pub fn from_ast_node(node: &common::ast::nodes::VariableDeclaration) -> Self {
        Self {
            name: node.name.clone(),
            data_type: node.data_type,
            initial_value: node.initial_value.clone(),
        }
    }

    /// Check if this variable has an initial value
    pub fn has_initial_value(&self) -> bool {
        self.initial_value.is_some()
    }

    /// Check if this is a computed variable (no initial value)
    pub fn is_computed(&self) -> bool {
        self.initial_value.is_none()
    }

    /// Check if this variable references another variable in its initial value
    pub fn has_variable_reference(&self) -> bool {
        match &self.initial_value {
            Some(value) => value.has_variable_reference(),
            None => false,
        }
    }

    /// Get the referenced variable name if this variable references another variable
    pub fn get_variable_reference(&self) -> Option<&str> {
        match &self.initial_value {
            Some(value) => value.get_variable_name(),
            None => None,
        }
    }

    /// Check if this variable is initialized with a literal value (not a reference)
    pub fn has_literal_initial_value(&self) -> bool {
        match &self.initial_value {
            Some(value) => !value.has_variable_reference(),
            None => false,
        }
    }

    /// Check if this variable is initialized with a variable reference
    pub fn has_variable_reference_initialization(&self) -> bool {
        self.has_variable_reference()
    }

    /// Get the initialization dependency (variable name this depends on)
    pub fn get_initialization_dependency(&self) -> Option<&str> {
        self.get_variable_reference()
    }
}

// ============================================================================
// DISPLAY IMPLEMENTATIONS
// ============================================================================

impl std::fmt::Display for ResolvedVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} = {:?}",
            self.identifier, self.data_type, self.value
        )
    }
}

impl std::fmt::Display for VariableDeclaration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.initial_value {
            Some(value) => write!(f, "VAR {} {} {:?}", self.name, self.data_type, value),
            None => write!(f, "VAR {} {}", self.name, self.data_type),
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use common::ast::nodes::{
        DataType as AstDataType, Value as AstValue, VariableDeclaration as AstVar,
    };

    #[test]
    fn test_variable_ast_conversion_with_literal() {
        // Create compiler AST node
        let ast_var = AstVar {
            name: "test_var".to_string(),
            data_type: AstDataType::String,
            initial_value: Some(AstValue::String("hello".to_string())),
            span: None,
        };

        // Convert to scanner type
        let scanner_var = VariableDeclaration::from_ast_node(&ast_var);

        // Verify
        assert_eq!(scanner_var.name, "test_var");
        assert_eq!(scanner_var.data_type, AstDataType::String);
        assert!(scanner_var.has_literal_initial_value());
        assert!(!scanner_var.is_computed());
        assert!(!scanner_var.has_variable_reference());
    }

    #[test]
    fn test_variable_ast_conversion_with_variable_reference() {
        // Create compiler AST node with variable reference
        let ast_var = AstVar {
            name: "derived_var".to_string(),
            data_type: AstDataType::Int,
            initial_value: Some(AstValue::Variable("source_var".to_string())),
            span: None,
        };

        // Convert to scanner type
        let scanner_var = VariableDeclaration::from_ast_node(&ast_var);

        // Verify
        assert_eq!(scanner_var.name, "derived_var");
        assert!(scanner_var.has_variable_reference());
        assert_eq!(scanner_var.get_variable_reference(), Some("source_var"));
        assert!(!scanner_var.has_literal_initial_value());
        assert!(!scanner_var.is_computed());
    }

    #[test]
    fn test_variable_ast_conversion_computed() {
        // Create compiler AST node with no initial value (computed)
        let ast_var = AstVar {
            name: "computed_var".to_string(),
            data_type: AstDataType::String,
            initial_value: None,
            span: None,
        };

        // Convert to scanner type
        let scanner_var = VariableDeclaration::from_ast_node(&ast_var);

        // Verify
        assert_eq!(scanner_var.name, "computed_var");
        assert!(scanner_var.is_computed());
        assert!(!scanner_var.has_initial_value());
        assert!(!scanner_var.has_variable_reference());
    }

    #[test]
    fn test_variable_categorization() {
        // Literal
        let literal =
            VariableDeclaration::new("lit".to_string(), DataType::Int, Some(Value::Integer(42)));
        assert!(literal.has_literal_initial_value());

        // Reference
        let reference = VariableDeclaration::new(
            "ref".to_string(),
            DataType::Int,
            Some(Value::Variable("other".to_string())),
        );
        assert!(reference.has_variable_reference());

        // Computed
        let computed = VariableDeclaration::new("comp".to_string(), DataType::String, None);
        assert!(computed.is_computed());
    }
}
