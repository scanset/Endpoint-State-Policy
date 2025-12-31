// src/strategies/validation.rs
//! CTN contract validation logic
//!
//! Provides comprehensive validation for CTN contracts, field mappings,
//! and criterion compatibility with contract specifications.

use crate::strategies::ctn_contract::{CtnContract, DataTypeCompatible};
use crate::strategies::errors::{
    CtnContractError, ValidationErrorType, ValidationReport, ValidationWarningType,
};
use crate::types::execution_context::{ExecutableCriterion, ExecutableObject, ExecutableState};
use std::collections::{HashMap, HashSet};

/// Comprehensive CTN contract validator
pub struct CtnContractValidator;

impl CtnContractValidator {
    /// Validate a complete CTN contract for internal consistency
    pub fn validate_contract(contract: &CtnContract) -> Result<(), CtnContractError> {
        // Validate field mapping consistency
        Self::validate_field_mappings(contract)?;

        // Validate collection strategy
        Self::validate_collection_strategy(contract)?;

        // Validate computed field dependencies
        Self::validate_computed_fields(contract)?;

        // Validate requirement completeness
        Self::validate_requirement_completeness(contract)?;

        Ok(())
    }

    /// Validate a criterion against a CTN contract
    pub fn validate_criterion_against_contract(
        criterion: &ExecutableCriterion,
        contract: &CtnContract,
    ) -> ValidationReport {
        let mut report = ValidationReport::new(contract.ctn_type.clone());

        // Validate objects
        for object in &criterion.objects {
            Self::validate_object_against_contract(object, contract, &mut report);
        }

        // Validate states
        for state in &criterion.states {
            Self::validate_state_against_contract(state, contract, &mut report);
        }

        // Validate test specification compatibility
        Self::validate_test_specification(criterion, contract, &mut report);

        // Validate overall criterion structure
        Self::validate_criterion_structure(criterion, contract, &mut report);

        report
    }

    /// Validate field mappings for consistency
    fn validate_field_mappings(contract: &CtnContract) -> Result<(), CtnContractError> {
        let field_mappings = &contract.field_mappings;

        // Validate that all required object fields have collection mappings
        for req_field in &contract.object_requirements.required_fields {
            if !field_mappings
                .collection_mappings
                .object_to_collection
                .contains_key(&req_field.name)
            {
                return Err(CtnContractError::CollectionMappingError {
                    ctn_type: contract.ctn_type.clone(),
                    reason: format!(
                        "Required object field '{}' has no collection mapping",
                        req_field.name
                    ),
                });
            }
        }

        // Validate that all required state fields have validation mappings
        for req_field in &contract.state_requirements.required_fields {
            let has_direct_mapping = field_mappings
                .validation_mappings
                .state_to_data
                .contains_key(&req_field.name);
            let has_computed_mapping = field_mappings
                .validation_mappings
                .computed_mappings
                .contains_key(&req_field.name);

            if !has_direct_mapping && !has_computed_mapping {
                return Err(CtnContractError::ValidationMappingError {
                    ctn_type: contract.ctn_type.clone(),
                    reason: format!(
                        "Required state field '{}' has no validation mapping",
                        req_field.name
                    ),
                });
            }
        }

        // Validate that validation mappings point to collectible fields
        for (state_field, data_field) in &field_mappings.validation_mappings.state_to_data {
            let is_required = field_mappings
                .collection_mappings
                .required_data_fields
                .contains(data_field);
            let is_optional = field_mappings
                .collection_mappings
                .optional_data_fields
                .contains(data_field);

            if !is_required && !is_optional {
                return Err(CtnContractError::InconsistentFieldMappings {
                    collection_field: "unknown".to_string(),
                    validation_field: data_field.clone(),
                    expected_field: state_field.clone(),
                });
            }
        }

        Ok(())
    }

    /// Validate collection strategy
    fn validate_collection_strategy(contract: &CtnContract) -> Result<(), CtnContractError> {
        let strategy = &contract.collection_strategy;

        if strategy.collector_type.is_empty() {
            return Err(CtnContractError::CollectionStrategyError {
                reason: "Collector type cannot be empty".to_string(),
            });
        }

        // Validate capabilities
        for capability in &strategy.required_capabilities {
            if capability.is_empty() {
                return Err(CtnContractError::MissingRequiredCapability {
                    capability: "empty capability".to_string(),
                });
            }
        }

        // Validate performance hints consistency
        let hints = &strategy.performance_hints;
        if hints.requires_elevated_privileges && strategy.required_capabilities.is_empty() {
            return Err(CtnContractError::CollectionStrategyError {
                reason: "Strategy requires elevated privileges but no capabilities specified"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Validate computed field dependencies
    fn validate_computed_fields(contract: &CtnContract) -> Result<(), CtnContractError> {
        let computed_fields = &contract
            .field_mappings
            .validation_mappings
            .computed_mappings;
        let available_fields: HashSet<String> = contract
            .field_mappings
            .collection_mappings
            .required_data_fields
            .iter()
            .chain(
                contract
                    .field_mappings
                    .collection_mappings
                    .optional_data_fields
                    .iter(),
            )
            .cloned()
            .collect();

        // Check that all source fields for computed fields are available
        for (field_name, computed_field) in computed_fields {
            for source_field in &computed_field.source_fields {
                if !available_fields.contains(source_field)
                    && !computed_fields.contains_key(source_field)
                {
                    return Err(CtnContractError::ComputedFieldError {
                        field: field_name.clone(),
                        reason: format!(
                            "Source field '{}' not available for computation",
                            source_field
                        ),
                    });
                }
            }
        }

        // Check for circular dependencies using DFS
        for field_name in computed_fields.keys() {
            let mut visited = HashSet::new();
            let mut path = Vec::new();

            if let Some(cycle) = Self::detect_computed_field_cycle(
                field_name,
                &mut visited,
                &mut path,
                computed_fields,
            ) {
                return Err(CtnContractError::CircularComputedFieldDependency { cycle });
            }
        }

        Ok(())
    }

    /// Detect circular dependencies in computed fields
    fn detect_computed_field_cycle(
        field_name: &str,
        visited: &mut HashSet<String>,
        path: &mut Vec<String>,
        computed_fields: &HashMap<String, crate::strategies::ctn_contract::ComputedField>,
    ) -> Option<Vec<String>> {
        if path.contains(&field_name.to_string()) {
            // Found cycle
            let cycle_start = path.iter().position(|f| f == field_name).unwrap();
            let mut cycle = path[cycle_start..].to_vec();
            cycle.push(field_name.to_string());
            return Some(cycle);
        }

        if visited.contains(field_name) {
            return None; // Already processed
        }

        visited.insert(field_name.to_string());
        path.push(field_name.to_string());

        if let Some(computed_field) = computed_fields.get(field_name) {
            for source_field in &computed_field.source_fields {
                if computed_fields.contains_key(source_field) {
                    if let Some(cycle) = Self::detect_computed_field_cycle(
                        source_field,
                        visited,
                        path,
                        computed_fields,
                    ) {
                        return Some(cycle);
                    }
                }
            }
        }

        path.pop();
        None
    }

    /// Validate requirement completeness
    fn validate_requirement_completeness(contract: &CtnContract) -> Result<(), CtnContractError> {
        // Check that contract has at least one requirement
        if contract.object_requirements.required_fields.is_empty()
            && contract.object_requirements.optional_fields.is_empty()
        {
            return Err(CtnContractError::ContractValidationFailed {
                ctn_type: contract.ctn_type.clone(),
                reason: "Contract must specify at least one object field".to_string(),
            });
        }

        if contract.state_requirements.required_fields.is_empty()
            && contract.state_requirements.optional_fields.is_empty()
        {
            return Err(CtnContractError::ContractValidationFailed {
                ctn_type: contract.ctn_type.clone(),
                reason: "Contract must specify at least one state field".to_string(),
            });
        }

        // Check that collection strategy produces required fields
        let required_data_fields: HashSet<String> = contract
            .field_mappings
            .collection_mappings
            .required_data_fields
            .iter()
            .cloned()
            .collect();

        if required_data_fields.is_empty() {
            return Err(CtnContractError::CollectionMappingError {
                ctn_type: contract.ctn_type.clone(),
                reason: "Collection strategy must specify at least one required data field"
                    .to_string(),
            });
        }

        Ok(())
    }

    /// Validate object against contract
    fn validate_object_against_contract(
        object: &ExecutableObject,
        contract: &CtnContract,
        report: &mut ValidationReport,
    ) {
        // Check required fields
        for req_field in &contract.object_requirements.required_fields {
            if !object.has_field(&req_field.name) {
                report.add_error(
                    ValidationErrorType::MissingRequiredField,
                    format!(
                        "Object '{}' missing required field '{}'",
                        object.identifier, req_field.name
                    ),
                    Some(format!(
                        "CTN type '{}' requires this field",
                        contract.ctn_type
                    )),
                );
            }
        }

        // Check field types and validate them
        for field_info in object.get_all_fields() {
            if let Some(spec) = contract
                .object_requirements
                .get_field_spec(&field_info.name)
            {
                if !field_info.data_type.is_compatible_with(&spec.data_type) {
                    report.add_error(
                        ValidationErrorType::InvalidFieldType,
                        format!(
                            "Object '{}' field '{}' has incompatible type",
                            object.identifier, field_info.name
                        ),
                        Some(format!(
                            "Expected {:?}, got {:?}",
                            spec.data_type, field_info.data_type
                        )),
                    );
                }
            } else {
                report.add_warning(
                    ValidationWarningType::UnrecognizedField,
                    format!(
                        "Object '{}' has unrecognized field '{}'",
                        object.identifier, field_info.name
                    ),
                    Some("This field may be ignored during collection".to_string()),
                );
            }
        }

        // Validate collection mappings exist for object fields
        for field_info in object.get_all_fields() {
            if contract
                .object_requirements
                .is_field_required(&field_info.name)
                && !contract
                    .field_mappings
                    .collection_mappings
                    .object_to_collection
                    .contains_key(&field_info.name)
            {
                report.add_error(
                    ValidationErrorType::FieldMappingError,
                    format!(
                        "Required object field '{}' has no collection mapping",
                        field_info.name
                    ),
                    Some("Collection mapping required for field validation".to_string()),
                );
            }
        }
    }

    /// Validate state against contract
    fn validate_state_against_contract(
        state: &ExecutableState,
        contract: &CtnContract,
        report: &mut ValidationReport,
    ) {
        for field in &state.fields {
            if let Some(spec) = contract.state_requirements.get_field_spec(&field.name) {
                // Check operation support
                if !spec.allowed_operations.contains(&field.operation) {
                    report.add_error(
                        ValidationErrorType::UnsupportedOperation,
                        format!(
                            "State '{}' field '{}' uses unsupported operation {:?}",
                            state.identifier, field.name, field.operation
                        ),
                        Some(format!("Allowed operations: {:?}", spec.allowed_operations)),
                    );
                }

                // Check data type compatibility
                if !field.data_type.is_compatible_with(&spec.data_type) {
                    report.add_error(
                        ValidationErrorType::InvalidFieldType,
                        format!(
                            "State '{}' field '{}' has incompatible type",
                            state.identifier, field.name
                        ),
                        Some(format!(
                            "Expected {:?}, got {:?}",
                            spec.data_type, field.data_type
                        )),
                    );
                }
            } else {
                report.add_warning(
                    ValidationWarningType::UnrecognizedField,
                    format!(
                        "State '{}' has unrecognized field '{}'",
                        state.identifier, field.name
                    ),
                    Some("This field may not be validated".to_string()),
                );
            }

            // Check validation mapping exists
            let has_direct_mapping = contract
                .field_mappings
                .validation_mappings
                .state_to_data
                .contains_key(&field.name);
            let has_computed_mapping = contract
                .field_mappings
                .validation_mappings
                .computed_mappings
                .contains_key(&field.name);

            if !has_direct_mapping && !has_computed_mapping {
                report.add_error(
                    ValidationErrorType::FieldMappingError,
                    format!("State field '{}' has no validation mapping", field.name),
                    Some(
                        "Validation mapping required to compare against collected data".to_string(),
                    ),
                );
            }
        }
    }

    /// Validate test specification compatibility
    fn validate_test_specification(
        criterion: &ExecutableCriterion,
        _contract: &CtnContract,
        report: &mut ValidationReport,
    ) {
        use self::TestComponentValidation; // Bring trait into scope
        let test_spec = &criterion.test;

        // Validate that test specification makes sense for this CTN type
        if criterion.objects.is_empty()
            && !matches!(
                test_spec.existence_check,
                crate::types::ExistenceCheck::None
            )
        {
            report.add_error(
                ValidationErrorType::ContractViolation,
                "TEST specification expects objects but criterion has no objects".to_string(),
                Some("Consider using 'none' existence check or adding objects".to_string()),
            );
        }

        if criterion.states.is_empty() && test_spec.item_check.expects_satisfaction() {
            report.add_error(
                ValidationErrorType::ContractViolation,
                "TEST specification expects state validation but criterion has no states"
                    .to_string(),
                Some("Consider using 'none_satisfy' item check or adding states".to_string()),
            );
        }

        // Validate state operator usage
        if let Some(state_operator) = test_spec.state_operator {
            if criterion.states.len() < 2 {
                report.add_warning(
                    ValidationWarningType::SuboptimalConfiguration,
                    format!(
                        "State operator '{}' specified but only {} states present",
                        state_operator.as_str(),
                        criterion.states.len()
                    ),
                    Some("State operator is only meaningful with multiple states".to_string()),
                );
            }
        } else if criterion.states.len() > 1 {
            report.add_warning(
                ValidationWarningType::SuboptimalConfiguration,
                format!(
                    "Multiple states ({}) present but no state operator specified",
                    criterion.states.len()
                ),
                Some("Consider adding AND, OR, or ONE state operator".to_string()),
            );
        }
    }

    /// Validate overall criterion structure
    fn validate_criterion_structure(
        criterion: &ExecutableCriterion,
        contract: &CtnContract,
        report: &mut ValidationReport,
    ) {
        // Check for performance implications
        if criterion.objects.len() > 10 {
            report.add_warning(
                ValidationWarningType::PerformanceImpact,
                format!(
                    "Criterion has {} objects which may impact performance",
                    criterion.objects.len()
                ),
                Some("Consider breaking into multiple criteria or using filters".to_string()),
            );
        }

        if criterion.states.len() > 5 {
            report.add_warning(
                ValidationWarningType::PerformanceImpact,
                format!(
                    "Criterion has {} states which may impact performance",
                    criterion.states.len()
                ),
                Some("Consider consolidating related fields into fewer states".to_string()),
            );
        }

        // Check for configuration anti-patterns
        if criterion.objects.len() == 1 && criterion.states.len() == 1 {
            let test = &criterion.test;
            if matches!(test.existence_check, crate::types::ExistenceCheck::All)
                && matches!(test.item_check, crate::types::ItemCheck::All)
            {
                report.add_warning(
                    ValidationWarningType::SuboptimalConfiguration,
                    "Simple 1:1 object:state relationship uses complex TEST specification"
                        .to_string(),
                    Some("Consider using 'any all' for simpler semantics".to_string()),
                );
            }
        }

        // Validate that CTN type matches expected pattern
        if !contract
            .ctn_type
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_')
        {
            report.add_warning(
                ValidationWarningType::DeprecatedUsage,
                format!(
                    "CTN type '{}' contains non-standard characters",
                    contract.ctn_type
                ),
                Some("Use alphanumeric and underscore characters only".to_string()),
            );
        }
    }
}

/// Contract compatibility checker
pub struct CtnCompatibilityChecker;

impl CtnCompatibilityChecker {
    /// Check if two contracts are compatible (for inheritance/extension)
    pub fn are_contracts_compatible(
        base_contract: &CtnContract,
        derived_contract: &CtnContract,
    ) -> Result<bool, CtnContractError> {
        // Check that derived contract satisfies base requirements
        Self::check_object_requirements_compatibility(
            &base_contract.object_requirements,
            &derived_contract.object_requirements,
        )?;

        Self::check_state_requirements_compatibility(
            &base_contract.state_requirements,
            &derived_contract.state_requirements,
        )?;

        Ok(true)
    }

    fn check_object_requirements_compatibility(
        base: &crate::strategies::ctn_contract::ObjectRequirements,
        derived: &crate::strategies::ctn_contract::ObjectRequirements,
    ) -> Result<(), CtnContractError> {
        // All base required fields must be present in derived
        for base_field in &base.required_fields {
            if !derived
                .required_fields
                .iter()
                .any(|f| f.name == base_field.name)
                && !derived
                    .optional_fields
                    .iter()
                    .any(|f| f.name == base_field.name)
            {
                return Err(CtnContractError::ContractValidationFailed {
                    ctn_type: "derived".to_string(),
                    reason: format!(
                        "Derived contract missing required field '{}'",
                        base_field.name
                    ),
                });
            }
        }

        Ok(())
    }

    fn check_state_requirements_compatibility(
        base: &crate::strategies::ctn_contract::StateRequirements,
        derived: &crate::strategies::ctn_contract::StateRequirements,
    ) -> Result<(), CtnContractError> {
        // All base required fields must be present in derived
        for base_field in &base.required_fields {
            if let Some(derived_field) = derived
                .required_fields
                .iter()
                .chain(derived.optional_fields.iter())
                .find(|f| f.name == base_field.name)
            {
                // Check that operations are compatible (derived should support at least base operations)
                for base_op in &base_field.allowed_operations {
                    if !derived_field.allowed_operations.contains(base_op) {
                        return Err(CtnContractError::UnsupportedFieldOperation {
                            ctn_type: "derived".to_string(),
                            field: base_field.name.clone(),
                            operation: *base_op,
                        });
                    }
                }
            } else {
                return Err(CtnContractError::ContractValidationFailed {
                    ctn_type: "derived".to_string(),
                    reason: format!(
                        "Derived contract missing required state field '{}'",
                        base_field.name
                    ),
                });
            }
        }

        Ok(())
    }
}

// ============================================================================
// Helper traits for validation
// ============================================================================

/// Extension trait for test components
trait TestComponentValidation {
    fn expects_satisfaction(&self) -> bool;
}

impl TestComponentValidation for crate::types::ItemCheck {
    fn expects_satisfaction(&self) -> bool {
        !matches!(self, crate::types::ItemCheck::NoneSatisfy)
    }
}
