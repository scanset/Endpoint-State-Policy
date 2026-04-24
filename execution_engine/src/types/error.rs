/// Field resolution errors
#[derive(Debug)]
pub enum FieldResolutionError {
    UnsupportedFieldType {
        field_type: String,
        context: String,
    },
    VariableReferenceNotAllowed {
        variable_name: String,
        context: String,
    },
    TypeMismatch {
        expected: String,
        found: String,
        field: String,
    },
    MissingRequiredValue {
        field_name: String,
        context: String,
    },
}

impl std::fmt::Display for FieldResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldResolutionError::UnsupportedFieldType {
                field_type,
                context,
            } => {
                write!(f, "Unsupported field type '{}' in {}", field_type, context)
            }
            FieldResolutionError::VariableReferenceNotAllowed {
                variable_name,
                context,
            } => {
                write!(
                    f,
                    "Variable reference '{}' not allowed in {}",
                    variable_name, context
                )
            }
            FieldResolutionError::TypeMismatch {
                expected,
                found,
                field,
            } => {
                write!(
                    f,
                    "Type mismatch for field '{}': expected {}, found {}",
                    field, expected, found
                )
            }
            FieldResolutionError::MissingRequiredValue {
                field_name,
                context,
            } => {
                write!(
                    f,
                    "Missing required value for field '{}' in {}",
                    field_name, context
                )
            }
        }
    }
}

impl std::error::Error for FieldResolutionError {}
