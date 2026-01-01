use super::common::ResolvedValue;
use super::FieldPath;
use common::ast::nodes::{
    DataType, EntityCheck, Operation, RecordCheck, RecordContent, RecordField, Value,
};
use serde::{Deserialize, Serialize};

/// State declaration from ESP definition (scanner working type)
/// Can be either global (definition-level) or local (CTN-level)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateDeclaration {
    pub identifier: String,
    pub fields: Vec<StateField>,
    pub record_checks: Vec<RecordCheck>, // Using compiler's type
    pub is_global: bool,
}

/// Resolved state with all variable references substituted
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedState {
    pub identifier: String,
    pub resolved_fields: Vec<ResolvedStateField>,
    pub resolved_record_checks: Vec<ResolvedRecordCheck>,
    pub is_global: bool,
}

/// Individual field within a state definition (scanner working type)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateField {
    pub name: String,
    pub data_type: DataType,
    pub operation: Operation,
    pub value: Value,
    pub entity_check: Option<EntityCheck>,
}

/// Resolved state field with concrete value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedStateField {
    pub name: String,
    pub data_type: DataType,
    pub operation: Operation,
    pub value: ResolvedValue,
    pub entity_check: Option<EntityCheck>,
}

/// Resolved record check with concrete data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedRecordCheck {
    pub data_type: Option<DataType>,
    pub content: ResolvedRecordContent,
}

/// Resolved record content with concrete values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResolvedRecordContent {
    Direct {
        operation: Operation,
        value: ResolvedValue,
    },
    Nested {
        fields: Vec<ResolvedRecordField>,
    },
}

/// Resolved record field with concrete value
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedRecordField {
    pub path: FieldPath,
    pub data_type: DataType,
    pub operation: Operation,
    pub value: ResolvedValue,
    pub entity_check: Option<EntityCheck>,
}

// ============================================================================
// IMPLEMENTATIONS - Scanner working types
// ============================================================================

impl StateDeclaration {
    /// Check if this state has any variable references in its fields or record checks
    pub fn has_variable_references(&self) -> bool {
        self.fields
            .iter()
            .any(|field| field.has_variable_references())
            || self
                .record_checks
                .iter()
                .any(|record| record.has_variable_references())
    }

    /// Get all variable references used in this state
    pub fn get_variable_references(&self) -> Vec<String> {
        let mut refs = Vec::new();

        // Collect from fields
        for field in &self.fields {
            refs.extend(field.get_variable_references());
        }

        // Collect from record checks
        for record in &self.record_checks {
            refs.extend(record.get_variable_references());
        }

        refs.sort();
        refs.dedup();
        refs
    }

    /// Check if this is an empty state (no fields or record checks)
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty() && self.record_checks.is_empty()
    }

    /// Get total element count (for validation)
    pub fn element_count(&self) -> usize {
        self.fields.len() + self.record_checks.len()
    }

    /// Get all field names for this state
    pub fn get_field_names(&self) -> Vec<String> {
        self.fields.iter().map(|field| field.name.clone()).collect()
    }

    /// Check if this state has any entity checks
    pub fn has_entity_checks(&self) -> bool {
        self.fields.iter().any(|field| field.entity_check.is_some())
            || self
                .record_checks
                .iter()
                .any(|record| record.has_entity_checks())
    }

    /// Convert from compiler AST node
    pub fn from_ast_node(node: &common::ast::nodes::StateDefinition) -> Self {
        Self {
            identifier: node.id.clone(),
            fields: node.fields.iter().map(StateField::from_ast_field).collect(),
            record_checks: node.record_checks.clone(),
            is_global: node.is_global,
        }
    }
}

impl StateField {
    /// Check if this field has variable references
    pub fn has_variable_references(&self) -> bool {
        matches!(self.value, Value::Variable(_))
    }

    /// Get variable references from this field
    pub fn get_variable_references(&self) -> Vec<String> {
        if let Value::Variable(var_name) = &self.value {
            vec![var_name.clone()]
        } else {
            Vec::new()
        }
    }

    /// Check if this field has an entity check
    pub fn has_entity_check(&self) -> bool {
        self.entity_check.is_some()
    }

    /// Convert from compiler AST field
    pub fn from_ast_field(field: &common::ast::nodes::StateField) -> Self {
        Self {
            name: field.name.clone(),
            data_type: field.data_type,
            operation: field.operation,
            value: field.value.clone(),
            entity_check: field.entity_check,
        }
    }
}

// ============================================================================
// EXTENSION TRAITS - For compiler types used in scanner
// ============================================================================

/// Extension trait for compiler's RecordCheck to add scanner-specific helpers
pub trait RecordCheckExt {
    fn has_variable_references(&self) -> bool;
    fn get_variable_references(&self) -> Vec<String>;
    fn has_entity_checks(&self) -> bool;
}

impl RecordCheckExt for RecordCheck {
    fn has_variable_references(&self) -> bool {
        self.content.has_variable_references()
    }

    fn get_variable_references(&self) -> Vec<String> {
        self.content.get_variable_references()
    }

    fn has_entity_checks(&self) -> bool {
        self.content.has_entity_checks()
    }
}

/// Extension trait for compiler's RecordContent
pub trait RecordContentExt {
    fn has_variable_references(&self) -> bool;
    fn get_variable_references(&self) -> Vec<String>;
    fn has_entity_checks(&self) -> bool;
}

impl RecordContentExt for RecordContent {
    fn has_variable_references(&self) -> bool {
        match self {
            RecordContent::Direct { value, .. } => matches!(value, Value::Variable(_)),
            RecordContent::Nested { fields } => fields
                .iter()
                .any(|field| matches!(field.value, Value::Variable(_))),
        }
    }

    fn get_variable_references(&self) -> Vec<String> {
        match self {
            RecordContent::Direct { value, .. } => {
                if let Value::Variable(var_name) = value {
                    vec![var_name.clone()]
                } else {
                    Vec::new()
                }
            }
            RecordContent::Nested { fields } => {
                let mut refs = Vec::new();
                for field in fields {
                    if let Value::Variable(var_name) = &field.value {
                        refs.push(var_name.clone());
                    }
                }
                refs.sort();
                refs.dedup();
                refs
            }
        }
    }

    fn has_entity_checks(&self) -> bool {
        match self {
            RecordContent::Direct { .. } => false,
            RecordContent::Nested { fields } => {
                fields.iter().any(|field| field.entity_check.is_some())
            }
        }
    }
}

/// Extension trait for compiler's RecordField
pub trait RecordFieldExt {
    fn has_variable_references(&self) -> bool;
    fn get_variable_references(&self) -> Vec<String>;
    fn has_entity_check(&self) -> bool;
}

impl RecordFieldExt for RecordField {
    fn has_variable_references(&self) -> bool {
        matches!(self.value, Value::Variable(_))
    }

    fn get_variable_references(&self) -> Vec<String> {
        if let Value::Variable(var_name) = &self.value {
            vec![var_name.clone()]
        } else {
            Vec::new()
        }
    }

    fn has_entity_check(&self) -> bool {
        self.entity_check.is_some()
    }
}

// ============================================================================
// DISPLAY IMPLEMENTATIONS
// ============================================================================

impl std::fmt::Display for StateField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Helper to format the value
        let value_str = match &self.value {
            Value::String(s) => format!("`{}`", s),
            Value::Variable(v) => format!("VAR {}", v),
            Value::Integer(i) => i.to_string(),
            Value::Float(fl) => fl.to_string(),
            Value::Boolean(b) => b.to_string(),
        };

        // Format with or without entity check
        if let Some(entity_check) = &self.entity_check {
            // Convert EntityCheck to string inline (can't impl Display due to orphan rules)
            let entity_str = match entity_check {
                EntityCheck::All => "ALL",
                EntityCheck::AtLeastOne => "AT_LEAST_ONE",
                EntityCheck::None => "NONE",
                EntityCheck::OnlyOne => "ONLY_ONE",
            };

            write!(
                f,
                "{} {} {} {} {}",
                self.name, self.data_type, self.operation, value_str, entity_str
            )
        } else {
            write!(
                f,
                "{} {} {} {}",
                self.name, self.data_type, self.operation, value_str
            )
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
        DataType as AstDataType, Operation as AstOperation, StateDefinition as AstState,
        StateField as AstField, Value as AstValue,
    };

    #[test]
    fn test_state_ast_conversion_global() {
        // Create compiler AST node for global state
        let ast_state = AstState {
            id: "test_state".to_string(),
            fields: vec![AstField {
                name: "field1".to_string(),
                data_type: AstDataType::String,
                operation: AstOperation::Equals,
                value: AstValue::String("value1".to_string()),
                entity_check: None,
                span: None,
            }],
            record_checks: vec![],
            is_global: true,
            span: None,
        };

        // Convert to scanner type
        let scanner_state = StateDeclaration::from_ast_node(&ast_state);

        // Verify
        assert_eq!(scanner_state.identifier, "test_state");
        assert_eq!(scanner_state.fields.len(), 1);
        assert!(scanner_state.is_global);
        assert!(!scanner_state.is_empty());
    }

    #[test]
    fn test_state_ast_conversion_local() {
        // Create compiler AST node for local state (in CTN)
        let ast_state = AstState {
            id: "local_state".to_string(),
            fields: vec![AstField {
                name: "check_field".to_string(),
                data_type: AstDataType::Int,
                operation: AstOperation::GreaterThan,
                value: AstValue::Integer(100),
                entity_check: None,
                span: None,
            }],
            record_checks: vec![],
            is_global: false,
            span: None,
        };

        // Convert to scanner type
        let scanner_state = StateDeclaration::from_ast_node(&ast_state);

        // Verify
        assert_eq!(scanner_state.identifier, "local_state");
        assert!(!scanner_state.is_global);
    }

    #[test]
    fn test_state_field_conversion() {
        // Create compiler AST field
        let ast_field = AstField {
            name: "test_field".to_string(),
            data_type: AstDataType::Boolean,
            operation: AstOperation::Equals,
            value: AstValue::Boolean(true),
            entity_check: None,
            span: None,
        };

        // Convert to scanner type
        let scanner_field = StateField::from_ast_field(&ast_field);

        // Verify
        assert_eq!(scanner_field.name, "test_field");
        assert_eq!(scanner_field.data_type, AstDataType::Boolean);
        assert_eq!(scanner_field.operation, AstOperation::Equals);
        assert!(!scanner_field.has_variable_references());
    }

    #[test]
    fn test_state_with_variable_references() {
        // Create state with variable reference
        let ast_state = AstState {
            id: "var_state".to_string(),
            fields: vec![AstField {
                name: "dynamic_field".to_string(),
                data_type: AstDataType::String,
                operation: AstOperation::Equals,
                value: AstValue::Variable("some_var".to_string()),
                entity_check: None,
                span: None,
            }],
            record_checks: vec![],
            is_global: true,
            span: None,
        };

        // Convert
        let scanner_state = StateDeclaration::from_ast_node(&ast_state);

        // Verify
        assert!(scanner_state.has_variable_references());
        let refs = scanner_state.get_variable_references();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], "some_var");
    }

    #[test]
    fn test_state_multiple_fields() {
        // Create state with multiple fields
        let ast_state = AstState {
            id: "multi_field_state".to_string(),
            fields: vec![
                AstField {
                    name: "field1".to_string(),
                    data_type: AstDataType::String,
                    operation: AstOperation::Equals,
                    value: AstValue::String("test".to_string()),
                    entity_check: None,
                    span: None,
                },
                AstField {
                    name: "field2".to_string(),
                    data_type: AstDataType::Int,
                    operation: AstOperation::GreaterThan,
                    value: AstValue::Integer(42),
                    entity_check: None,
                    span: None,
                },
            ],
            record_checks: vec![],
            is_global: true,
            span: None,
        };

        // Convert
        let scanner_state = StateDeclaration::from_ast_node(&ast_state);

        // Verify
        assert_eq!(scanner_state.fields.len(), 2);
        assert_eq!(scanner_state.element_count(), 2);

        let field_names = scanner_state.get_field_names();
        assert!(field_names.contains(&"field1".to_string()));
        assert!(field_names.contains(&"field2".to_string()));
    }
}
