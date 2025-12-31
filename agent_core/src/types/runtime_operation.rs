use super::common::Value;
use serde::{Deserialize, Serialize};

// Re-export compiler types that we use directly
pub use common::ast::nodes::{ArithmeticOperator, RunParameter, RuntimeOperationType};

/// Runtime operation declaration from ESP definition
/// EBNF: run_block ::= "RUN" space variable_name space operation_type statement_end run_parameters "RUN_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeOperation {
    /// Variable to store result in
    pub target_variable: String,
    /// Type of operation
    pub operation_type: RuntimeOperationType,
    /// Operation parameters
    pub parameters: Vec<RunParameter>,
}

// ============================================================================
// IMPLEMENTATIONS
// ============================================================================

impl RuntimeOperation {
    /// Convert from compiler AST node
    ///
    /// # Arguments
    /// * `node` - Runtime operation node from common AST
    /// # Example
    /// ```ignore
    /// use common::ast::nodes::RuntimeOperation as AstRun;
    ///
    /// let ast_run = AstRun { ... };
    /// let scanner_run = RuntimeOperation::from_ast_node(&ast_run);
    /// ```
    pub fn from_ast_node(node: &common::ast::nodes::RuntimeOperation) -> Self {
        Self {
            target_variable: node.target_variable.clone(),
            operation_type: node.operation_type,
            parameters: node.parameters.clone(), // Already compiler type
        }
    }

    /// Create a new runtime operation
    pub fn new(
        target_variable: String,
        operation_type: RuntimeOperationType,
        parameters: Vec<RunParameter>,
    ) -> Self {
        Self {
            target_variable,
            operation_type,
            parameters,
        }
    }

    /// Check if this operation has any variable references in its parameters
    pub fn has_variable_references(&self) -> bool {
        self.parameters
            .iter()
            .any(|param| param.has_variable_references())
    }

    /// Get all variable references from parameters
    pub fn get_variable_references(&self) -> Vec<String> {
        let mut refs = Vec::new();
        for param in &self.parameters {
            refs.extend(param.get_variable_references());
        }
        refs.sort();
        refs.dedup();
        refs
    }

    /// Check if this operation depends on collected object data
    pub fn has_object_dependency(&self) -> bool {
        self.parameters
            .iter()
            .any(|p| matches!(p, RunParameter::ObjectExtraction { .. }))
    }

    /// Extract object ID if this operation has ObjectExtraction parameter
    pub fn extract_object_id(&self) -> Option<String> {
        self.parameters.iter().find_map(|p| {
            if let RunParameter::ObjectExtraction { object_id, .. } = p {
                Some(object_id.clone())
            } else {
                None
            }
        })
    }

    /// Get parameter count
    pub fn parameter_count(&self) -> usize {
        self.parameters.len()
    }
}

// ============================================================================
// EXTENSION TRAITS - For compiler types used in scanner
// ============================================================================

/// Extension trait for compiler's RunParameter
pub trait RunParameterExt {
    fn has_variable_references(&self) -> bool;
    fn get_variable_references(&self) -> Vec<String>;
    fn parameter_type_name(&self) -> &'static str;
}

impl RunParameterExt for RunParameter {
    fn has_variable_references(&self) -> bool {
        match self {
            RunParameter::Literal(value) => matches!(value, Value::Variable(_)),
            RunParameter::Variable(_) => true,
            RunParameter::ObjectExtraction { .. } => false,
            RunParameter::Pattern(_) => false,
            RunParameter::Delimiter(_) => false,
            RunParameter::Character(_) => false,
            RunParameter::StartPosition(_) => false,
            RunParameter::Length(_) => false,
            RunParameter::ArithmeticOp(_, value) => matches!(value, Value::Variable(_)),
        }
    }

    fn get_variable_references(&self) -> Vec<String> {
        match self {
            RunParameter::Literal(value) => {
                if let Value::Variable(var_name) = value {
                    vec![var_name.clone()]
                } else {
                    Vec::new()
                }
            }
            RunParameter::Variable(var_name) => vec![var_name.clone()],
            RunParameter::ObjectExtraction { .. } => Vec::new(),
            RunParameter::Pattern(_) => Vec::new(),
            RunParameter::Delimiter(_) => Vec::new(),
            RunParameter::Character(_) => Vec::new(),
            RunParameter::StartPosition(_) => Vec::new(),
            RunParameter::Length(_) => Vec::new(),
            RunParameter::ArithmeticOp(_, value) => {
                if let Value::Variable(var_name) = value {
                    vec![var_name.clone()]
                } else {
                    Vec::new()
                }
            }
        }
    }

    fn parameter_type_name(&self) -> &'static str {
        match self {
            RunParameter::Literal(_) => "Literal",
            RunParameter::Variable(_) => "Variable",
            RunParameter::ObjectExtraction { .. } => "ObjectExtraction",
            RunParameter::Pattern(_) => "Pattern",
            RunParameter::Delimiter(_) => "Delimiter",
            RunParameter::Character(_) => "Character",
            RunParameter::StartPosition(_) => "StartPosition",
            RunParameter::Length(_) => "Length",
            RunParameter::ArithmeticOp(_, _) => "ArithmeticOp",
        }
    }
}

// ============================================================================
// DISPLAY IMPLEMENTATIONS
// ============================================================================

impl std::fmt::Display for RuntimeOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RUN {} {} ({} parameters)",
            self.target_variable,
            self.operation_type,
            self.parameters.len()
        )
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use common::ast::nodes::{
        RunParameter as AstParam, RuntimeOperation as AstRun, RuntimeOperationType as AstRunType,
        Value as AstValue,
    };

    #[test]
    fn test_runtime_operation_ast_conversion() {
        // Create compiler AST node
        let ast_run = AstRun {
            target_variable: "result_var".to_string(),
            operation_type: AstRunType::Concat,
            parameters: vec![
                AstParam::Literal(AstValue::String("hello".to_string())),
                AstParam::Variable("input_var".to_string()),
            ],
            span: None,
        };

        // Convert to scanner type
        let scanner_run = RuntimeOperation::from_ast_node(&ast_run);

        // Verify
        assert_eq!(scanner_run.target_variable, "result_var");
        assert_eq!(scanner_run.operation_type, AstRunType::Concat);
        assert_eq!(scanner_run.parameters.len(), 2);
        assert_eq!(scanner_run.parameter_count(), 2);
    }

    #[test]
    fn test_runtime_operation_with_variable_references() {
        // Create RUN operation with variable references
        let ast_run = AstRun {
            target_variable: "output".to_string(),
            operation_type: AstRunType::Concat,
            parameters: vec![
                AstParam::Variable("var1".to_string()),
                AstParam::Literal(AstValue::String("_".to_string())),
                AstParam::Variable("var2".to_string()),
            ],
            span: None,
        };

        // Convert
        let scanner_run = RuntimeOperation::from_ast_node(&ast_run);

        // Verify
        assert!(scanner_run.has_variable_references());
        let refs = scanner_run.get_variable_references();
        assert_eq!(refs.len(), 2);
        assert!(refs.contains(&"var1".to_string()));
        assert!(refs.contains(&"var2".to_string()));
    }

    #[test]
    fn test_runtime_operation_with_object_extraction() {
        // Create RUN operation with object extraction
        let ast_run = AstRun {
            target_variable: "extracted".to_string(),
            operation_type: AstRunType::Extract,
            parameters: vec![AstParam::ObjectExtraction {
                object_id: "my_object".to_string(),
                field: "path".to_string(),
            }],
            span: None,
        };

        // Convert
        let scanner_run = RuntimeOperation::from_ast_node(&ast_run);

        // Verify
        assert!(scanner_run.has_object_dependency());
        assert_eq!(
            scanner_run.extract_object_id(),
            Some("my_object".to_string())
        );
        assert!(!scanner_run.has_variable_references());
    }

    #[test]
    fn test_runtime_operation_arithmetic() {
        // Create arithmetic RUN operation
        let ast_run = AstRun {
            target_variable: "sum".to_string(),
            operation_type: AstRunType::Arithmetic,
            parameters: vec![
                AstParam::Variable("x".to_string()),
                AstParam::ArithmeticOp(
                    common::ast::nodes::ArithmeticOperator::Add,
                    AstValue::Integer(10),
                ),
            ],
            span: None,
        };

        // Convert
        let scanner_run = RuntimeOperation::from_ast_node(&ast_run);

        // Verify
        assert_eq!(scanner_run.operation_type, AstRunType::Arithmetic);
        assert!(scanner_run.has_variable_references());
        assert_eq!(scanner_run.get_variable_references(), vec!["x"]);
    }

    #[test]
    fn test_run_parameter_extension_trait() {
        // Test extension trait methods
        let var_param = AstParam::Variable("test_var".to_string());
        assert!(var_param.has_variable_references());
        assert_eq!(var_param.get_variable_references(), vec!["test_var"]);
        assert_eq!(var_param.parameter_type_name(), "Variable");

        let literal_param = AstParam::Literal(AstValue::String("test".to_string()));
        assert!(!literal_param.has_variable_references());
        assert!(literal_param.get_variable_references().is_empty());
        assert_eq!(literal_param.parameter_type_name(), "Literal");

        let obj_param = AstParam::ObjectExtraction {
            object_id: "obj".to_string(),
            field: "field".to_string(),
        };
        assert!(!obj_param.has_variable_references());
        assert_eq!(obj_param.parameter_type_name(), "ObjectExtraction");
    }

    #[test]
    fn test_runtime_operation_no_parameters() {
        // Create RUN operation with no parameters (like COUNT)
        let ast_run = AstRun {
            target_variable: "count_result".to_string(),
            operation_type: AstRunType::Count,
            parameters: vec![],
            span: None,
        };

        // Convert
        let scanner_run = RuntimeOperation::from_ast_node(&ast_run);

        // Verify
        assert_eq!(scanner_run.parameter_count(), 0);
        assert!(!scanner_run.has_variable_references());
        assert!(!scanner_run.has_object_dependency());
    }
}
