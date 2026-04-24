use crate::types::common::{ResolvedValue, Value};
use crate::types::error::FieldResolutionError;
use crate::types::variable::ResolvedVariable;
use common::logging::codes;
use common::{log_debug, log_error};
use std::collections::HashMap;

pub struct FieldResolver;

impl FieldResolver {
    pub fn new() -> Self {
        Self
    }

    pub fn resolve_value(
        &self,
        value: &Value,
        context: &str,
        resolved_variables: &HashMap<String, ResolvedVariable>,
    ) -> Result<ResolvedValue, FieldResolutionError> {
        log_debug!(
            "Resolving field value with variable support",
            "context" => context,
            "value_type" => match value {
                Value::String(_) => "string",
                Value::Integer(_) => "integer",
                Value::Float(_) => "float",
                Value::Boolean(_) => "boolean",
                Value::Variable(_) => "variable",
            },
            "available_variables" => resolved_variables.len()
        );

        let result = match value {
            Value::String(s) => {
                log_debug!(
                    "Resolved string value",
                    "context" => context,
                    "length" => s.len()
                );
                Ok(ResolvedValue::String(s.clone()))
            }
            Value::Integer(i) => {
                log_debug!(
                    "Resolved integer value",
                    "context" => context,
                    "value" => i
                );
                Ok(ResolvedValue::Integer(*i))
            }
            Value::Float(f) => {
                log_debug!(
                    "Resolved float value",
                    "context" => context,
                    "value" => f
                );
                Ok(ResolvedValue::Float(*f))
            }
            Value::Boolean(b) => {
                log_debug!(
                    "Resolved boolean value",
                    "context" => context,
                    "value" => b
                );
                Ok(ResolvedValue::Boolean(*b))
            }
            Value::Variable(var_name) => {
                log_debug!(
                    "Resolving variable reference",
                    "variable_name" => var_name,
                    "context" => context,
                    "available_variables" => resolved_variables.keys().map(|k| k.as_str()).collect::<Vec<_>>().join(", ").as_str()
                );

                if let Some(resolved_var) = resolved_variables.get(var_name) {
                    log_debug!(
                        "Variable resolved successfully",
                        "variable_name" => var_name,
                        "resolved_type" => format!("{:?}", resolved_var.data_type).as_str(),
                        "context" => context
                    );
                    Ok(resolved_var.value.clone())
                } else {
                    log_error!(
                        codes::consumer::CONSUMER_PIPELINE_ERROR,
                        &format!(
                            "Variable reference '{}' could not be resolved in {}",
                            var_name, context
                        ),
                        "variable_name" => var_name,
                        "context" => context,
                        "available_variables" => resolved_variables.keys().map(|k| k.as_str()).collect::<Vec<_>>().join(", ").as_str()
                    );

                    // Provide helpful error message based on what variables are available
                    let error_context = if resolved_variables.is_empty() {
                        format!("{} - no variables have been resolved yet", context)
                    } else {
                        format!(
                            "{} - variable '{}' not found (available: {})",
                            context,
                            var_name,
                            resolved_variables
                                .keys()
                                .map(|k| k.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    };

                    Err(FieldResolutionError::VariableReferenceNotAllowed {
                        variable_name: var_name.clone(),
                        context: error_context,
                    })
                }
            }
        };

        if result.is_err() {
            log_debug!("Field resolution failed", "context" => context);
        } else {
            log_debug!("Field resolution completed successfully", "context" => context);
        }

        result
    }

    /// Convenience method for resolving values without variable support (legacy compatibility)
    pub fn resolve_value_direct(
        &self,
        value: &Value,
        context: &str,
    ) -> Result<ResolvedValue, FieldResolutionError> {
        let empty_variables = HashMap::new();
        self.resolve_value(value, context, &empty_variables)
    }
}

impl Default for FieldResolver {
    fn default() -> Self {
        Self::new()
    }
}
