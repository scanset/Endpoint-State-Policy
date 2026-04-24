//! Scanner-specific extensions for compiler's FieldPath
use common::ast::nodes::FieldPath;

/// Scanner-specific path component interpretation
#[derive(Debug, Clone, PartialEq)]
pub enum PathComponent {
    Field(String),
    Index(usize),
    Wildcard,
}

impl PathComponent {
    pub fn to_string_component(&self) -> String {
        match self {
            PathComponent::Field(name) => name.clone(),
            PathComponent::Index(idx) => idx.to_string(),
            PathComponent::Wildcard => "*".to_string(),
        }
    }
}

/// Extension trait for FieldPath with scanner-specific features
pub trait FieldPathExt {
    /// Parse components with scanner-specific logic (wildcards, indices)
    fn parse_components(&self) -> Vec<PathComponent>;

    /// Check if path contains wildcards
    fn has_wildcards(&self) -> bool;

    /// Convert to simple field names (for basic cases)
    fn to_field_names(&self) -> Vec<String>;
}

impl FieldPathExt for FieldPath {
    fn parse_components(&self) -> Vec<PathComponent> {
        self.components
            .iter()
            .map(|s| {
                // Parse each component
                if s == "*" {
                    PathComponent::Wildcard
                } else if let Ok(idx) = s.parse::<usize>() {
                    PathComponent::Index(idx)
                } else {
                    PathComponent::Field(s.clone())
                }
            })
            .collect()
    }

    fn has_wildcards(&self) -> bool {
        self.components.iter().any(|s| s == "*")
    }

    fn to_field_names(&self) -> Vec<String> {
        self.components.clone()
    }
}
