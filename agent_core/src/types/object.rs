use super::common::{RecordData, ResolvedValue};
use super::filter::ResolvedFilterSpec;
use common::ast::nodes::{DataType, FilterSpec, ObjectElement, Value};
use serde::{Deserialize, Serialize};

/// Object declaration from ESP definition (scanner working type)
/// Can be either global (definition-level) or local (CTN-level)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectDeclaration {
    pub identifier: String,
    pub elements: Vec<ObjectElement>, // Using compiler's type directly
    pub is_global: bool,
}

/// Resolved object with all variable references substituted
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedObject {
    pub identifier: String,
    pub resolved_elements: Vec<ResolvedObjectElement>,
    pub is_global: bool,
}

/// Resolved object element with all variables substituted
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResolvedObjectElement {
    /// Module specification (unchanged during resolution)
    Module { field: String, value: String },

    /// Resolved parameters as structured data
    Parameter {
        data_type: DataType,
        data: RecordData,
    },

    /// Resolved select as structured data
    Select {
        data_type: DataType,
        data: RecordData,
    },

    /// Behavior specification (unchanged during resolution)
    Behavior { values: Vec<String> },

    /// Resolved filter with state validation
    Filter(ResolvedFilterSpec),

    /// Set reference (validated during resolution)
    SetRef { set_id: String },

    /// Resolved field with concrete value
    Field { name: String, value: ResolvedValue },
}

// ============================================================================
// IMPLEMENTATIONS - Scanner working types
// ============================================================================

impl ObjectDeclaration {
    /// Convert from compiler AST node
    ///
    /// # Arguments
    /// * `node` - Object definition node from common AST
    ///
    /// # Example
    /// ```ignore
    /// use common::ast::nodes::ObjectDefinition;
    ///
    /// let ast_obj = ObjectDefinition { ... };
    /// let scanner_obj = ObjectDeclaration::from_ast_node(&ast_obj);
    /// ```
    pub fn from_ast_node(node: &common::ast::nodes::ObjectDefinition) -> Self {
        Self {
            identifier: node.id.clone(),
            elements: node.elements.clone(), // Already compiler type
            is_global: node.is_global,
        }
    }

    /// Check if this object has any variable references in its elements
    pub fn has_variable_references(&self) -> bool {
        self.elements
            .iter()
            .any(|element| element.has_variable_references())
    }

    /// Get all variable references used in this object
    pub fn get_variable_references(&self) -> Vec<String> {
        let mut refs = Vec::new();
        for element in &self.elements {
            refs.extend(element.get_variable_references());
        }
        refs.sort();
        refs.dedup();
        refs
    }

    /// Check if this object has any filter elements
    pub fn has_filters(&self) -> bool {
        self.elements
            .iter()
            .any(|element| matches!(element, ObjectElement::Filter(_)))
    }

    /// Get all filter specifications from this object
    pub fn get_filters(&self) -> Vec<&FilterSpec> {
        self.elements
            .iter()
            .filter_map(|element| match element {
                ObjectElement::Filter(filter) => Some(filter),
                _ => None,
            })
            .collect()
    }

    /// Get all state dependencies from filters in this object
    pub fn get_filter_state_dependencies(&self) -> Vec<String> {
        let mut deps = Vec::new();
        for element in &self.elements {
            if let ObjectElement::Filter(filter) = element {
                deps.extend(filter.state_refs.iter().map(|sr| sr.state_id.clone()));
            }
        }
        deps.sort();
        deps.dedup();
        deps
    }

    /// Check if this is an empty object (no elements)
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Get element count (for validation)
    pub fn element_count(&self) -> usize {
        self.elements.len()
    }

    /// Get all set references from this object
    pub fn get_set_references(&self) -> Vec<String> {
        self.elements
            .iter()
            .filter_map(|element| match element {
                ObjectElement::SetRef { set_id, .. } => Some(set_id.clone()),
                _ => None,
            })
            .collect()
    }

    /// Check if this object references external symbols (sets, states via filters)
    pub fn has_external_references(&self) -> bool {
        self.elements
            .iter()
            .any(|element| element.has_external_references())
    }
}

// ============================================================================
// EXTENSION TRAITS - For compiler types used in scanner
// ============================================================================

/// Extension trait for compiler's ObjectElement to add scanner-specific helpers
pub trait ObjectElementExt {
    fn has_variable_references(&self) -> bool;
    fn get_variable_references(&self) -> Vec<String>;
    fn is_filter(&self) -> bool;
    fn as_filter(&self) -> Option<&FilterSpec>;
    fn has_external_references(&self) -> bool;
    fn element_type_name(&self) -> &'static str;
}

impl ObjectElementExt for ObjectElement {
    fn has_variable_references(&self) -> bool {
        match self {
            ObjectElement::Field(field) => matches!(field.value, Value::Variable(_)),
            _ => false,
        }
    }

    fn get_variable_references(&self) -> Vec<String> {
        match self {
            ObjectElement::Field(field) => {
                if let Value::Variable(var_name) = &field.value {
                    vec![var_name.clone()]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    fn is_filter(&self) -> bool {
        matches!(self, ObjectElement::Filter(_))
    }

    fn as_filter(&self) -> Option<&FilterSpec> {
        match self {
            ObjectElement::Filter(filter) => Some(filter),
            _ => None,
        }
    }

    fn has_external_references(&self) -> bool {
        matches!(
            self,
            ObjectElement::SetRef { .. } | ObjectElement::Filter(_)
        )
    }

    fn element_type_name(&self) -> &'static str {
        match self {
            ObjectElement::Module { .. } => "Module",
            ObjectElement::Parameter { .. } => "Parameter",
            ObjectElement::Select { .. } => "Select",
            ObjectElement::Behavior { .. } => "Behavior",
            ObjectElement::Filter(_) => "Filter",
            ObjectElement::SetRef { .. } => "SetRef",
            ObjectElement::Field(_) => "Field",
            ObjectElement::RecordCheck(_) => "RecordCheck",
            ObjectElement::InlineSet(_) => "InlineSet",
        }
    }
}

// ============================================================================
// DISPLAY IMPLEMENTATIONS
// ============================================================================

impl std::fmt::Display for ObjectDeclaration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "OBJECT {} ({} elements, global: {})",
            self.identifier,
            self.elements.len(),
            self.is_global
        )
    }
}

impl std::fmt::Display for ResolvedObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ResolvedOBJECT {} ({} elements)",
            self.identifier,
            self.resolved_elements.len()
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
        ObjectDefinition as AstObject, ObjectElement as AstElement, ObjectField as AstField,
        Value as AstValue,
    };

    #[test]
    fn test_object_ast_conversion_global() {
        // Create compiler AST node for global object
        let ast_obj = AstObject {
            id: "test_object".to_string(),
            elements: vec![
                AstElement::Field(AstField {
                    name: "path".to_string(),
                    value: AstValue::String("/tmp/test".to_string()),
                    span: None,
                }),
                AstElement::Module {
                    field: "type".to_string(),
                    value: "file".to_string(),
                },
            ],
            is_global: true,
            span: None,
        };

        // Convert to scanner type
        let scanner_obj = ObjectDeclaration::from_ast_node(&ast_obj);

        // Verify
        assert_eq!(scanner_obj.identifier, "test_object");
        assert_eq!(scanner_obj.elements.len(), 2);
        assert!(scanner_obj.is_global);
        assert!(!scanner_obj.is_empty());
    }

    #[test]
    fn test_object_ast_conversion_local() {
        // Create compiler AST node for local object (in CTN)
        let ast_obj = AstObject {
            id: "local_object".to_string(),
            elements: vec![AstElement::Field(AstField {
                name: "name".to_string(),
                value: AstValue::String("test".to_string()),
                span: None,
            })],
            is_global: false,
            span: None,
        };

        // Convert to scanner type
        let scanner_obj = ObjectDeclaration::from_ast_node(&ast_obj);

        // Verify
        assert_eq!(scanner_obj.identifier, "local_object");
        assert!(!scanner_obj.is_global);
        assert_eq!(scanner_obj.element_count(), 1);
    }

    #[test]
    fn test_object_with_variable_references() {
        // Create object with variable reference
        let ast_obj = AstObject {
            id: "var_object".to_string(),
            elements: vec![AstElement::Field(AstField {
                name: "dynamic_path".to_string(),
                value: AstValue::Variable("path_var".to_string()),
                span: None,
            })],
            is_global: true,
            span: None,
        };

        // Convert
        let scanner_obj = ObjectDeclaration::from_ast_node(&ast_obj);

        // Verify
        assert!(scanner_obj.has_variable_references());
        let refs = scanner_obj.get_variable_references();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0], "path_var");
    }

    #[test]
    fn test_object_with_multiple_element_types() {
        // Create object with various element types
        let ast_obj = AstObject {
            id: "complex_object".to_string(),
            elements: vec![
                AstElement::Module {
                    field: "type".to_string(),
                    value: "file".to_string(),
                },
                AstElement::Field(AstField {
                    name: "path".to_string(),
                    value: AstValue::String("/tmp".to_string()),
                    span: None,
                }),
                AstElement::Behavior {
                    values: vec!["read".to_string(), "write".to_string()],
                },
            ],
            is_global: true,
            span: None,
        };

        // Convert
        let scanner_obj = ObjectDeclaration::from_ast_node(&ast_obj);

        // Verify
        assert_eq!(scanner_obj.elements.len(), 3);
        assert_eq!(scanner_obj.element_count(), 3);

        // Check element types using extension trait
        assert_eq!(scanner_obj.elements[0].element_type_name(), "Module");
        assert_eq!(scanner_obj.elements[1].element_type_name(), "Field");
        assert_eq!(scanner_obj.elements[2].element_type_name(), "Behavior");
    }

    #[test]
    fn test_object_element_extension_trait() {
        // Test the extension trait methods
        let field_elem = AstElement::Field(AstField {
            name: "test".to_string(),
            value: AstValue::Variable("var".to_string()),
            span: None,
        });

        assert!(field_elem.has_variable_references());
        assert_eq!(field_elem.get_variable_references(), vec!["var"]);
        assert!(!field_elem.is_filter());

        let module_elem = AstElement::Module {
            field: "type".to_string(),
            value: "file".to_string(),
        };

        assert!(!module_elem.has_variable_references());
        assert!(module_elem.get_variable_references().is_empty());
    }
}
