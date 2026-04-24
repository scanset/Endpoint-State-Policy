use crate::resolution::dag::{DependencyGraph, SymbolType};
use crate::resolution::error::ResolutionError;
use crate::resolution::field_resolver::FieldResolver;
use crate::types::execution_context::ExecutionContext;
use crate::types::object::ObjectDeclaration;
use crate::types::resolution_context::{DeferredOperation, ResolutionContext};
use crate::types::set::SetOperand;
use crate::types::state::{ResolvedState, StateDeclaration};
use crate::types::variable::{ResolvedVariable, VariableDeclaration};
use crate::types::{
    RecordCheck, RecordContent, ResolvedRecordCheck, ResolvedRecordContent, ResolvedRecordField,
};
use common::ast::nodes::{ObjectElement, RunParameter};
use common::{log_debug, log_info};
use std::collections::HashMap;

pub struct ResolutionEngine {
    field_resolver: FieldResolver,
}

impl ResolutionEngine {
    pub fn new() -> Self {
        log_debug!("Creating DAG-based Resolution Engine");
        Self {
            field_resolver: FieldResolver::new(),
        }
    }

    pub fn resolve_context(
        &mut self,
        context: &mut ResolutionContext,
    ) -> Result<ExecutionContext, ResolutionError> {
        log_info!(
            "Starting DAG resolution pipeline",
            "variables" => context.variables.len(),
            "states" => context.states.len(),
            "objects" => context.objects.len()
        );

        // Perform DAG-based resolution
        self.resolve_dag(context)?;

        // Expand sets in resolution context
        crate::resolution::set_expansion::expand_sets_in_resolution_context(context)?;

        // Create ExecutionContext
        let execution_context = ExecutionContext::from_resolution_context(context)
            .map_err(|e| ResolutionError::ContextError(e.to_string()))?;

        execution_context
            .validate()
            .map_err(|e| ResolutionError::ContextError(e.to_string()))?;

        log_info!(
            "DAG resolution pipeline completed",
            "criteria_count" => execution_context.criteria_tree.count_criteria(),
            "variables_count" => execution_context.global_variables.len(),
            "deferred_operations" => execution_context.deferred_operations.len()
        );

        Ok(execution_context)
    }

    /// Main DAG resolution method
    fn resolve_dag(&mut self, context: &mut ResolutionContext) -> Result<(), ResolutionError> {
        log_info!(
            "Starting DAG resolution",
            "symbols" => self.count_symbols(context),
            "relationships" => context.relationships.len()
        );

        // Build dependency graph (only includes resolution-time operations)
        let graph = self.build_dependency_graph(context)?;

        // Get resolution order via topological sort
        let resolution_order = graph.topological_sort()?;

        log_debug!(
            "Topological sort completed",
            "resolution_order_length" => resolution_order.len()
        );

        // Resolve symbols in dependency order
        self.resolve_symbols_in_order(&resolution_order, context)?;

        log_info!(
            "Before resolving local symbols",
            "resolved_variables_count" => context.resolved_variables.len()
        );

        // Resolve local symbols (CTN-scoped)
        self.resolve_local_symbols(context)?;

        log_info!(
            "DAG resolution completed",
            "resolved_variables" => context.resolved_variables.len(),
            "resolved_sets" => context.resolved_sets.len(),
            "deferred_operations" => context.scan_time_operations.len()
        );

        Ok(())
    }

    /// Build dependency graph with runtime operation categorization
    fn build_dependency_graph(
        &self,
        context: &ResolutionContext,
    ) -> Result<DependencyGraph, ResolutionError> {
        log_debug!("Building dependency graph with operation categorization");

        let mut graph = DependencyGraph::new();

        // Step 1: Add all declared variables as nodes
        for variable in &context.variables {
            graph.add_node(variable.name.clone(), SymbolType::Variable)?;
        }

        // Step 2: Add RUN operation target variables as nodes (computed variables)
        for runtime_op in &context.runtime_operations {
            if !graph.nodes.contains_key(&runtime_op.target_variable) {
                graph.add_node(runtime_op.target_variable.clone(), SymbolType::Variable)?;

                log_debug!(
                    "Added computed variable node to DAG",
                    "variable" => runtime_op.target_variable.as_str(),
                    "operation" => format!("{:?}", runtime_op.operation_type).as_str()
                );
            }
        }

        // Step 3: Add states, objects, sets as nodes
        for state in &context.global_states {
            graph.add_node(state.identifier.clone(), SymbolType::GlobalState)?;
        }

        for object in &context.global_objects {
            graph.add_node(object.identifier.clone(), SymbolType::GlobalObject)?;
        }

        for set_op in &context.set_operations {
            graph.add_node(set_op.set_id.clone(), SymbolType::SetOperation)?;
        }

        // Step 4: Add edges from parsed relationships
        for relationship in &context.relationships {
            graph.add_dependency(&relationship.from, &relationship.to)?;
        }

        // Step 5: Add runtime operation dependencies (resolution-time only)
        for runtime_op in &context.runtime_operations {
            // Check if operation has object dependency
            let has_object_dep = runtime_op.has_object_dependency();

            if !has_object_dep {
                // Resolution-time operation - add to DAG
                for param in &runtime_op.parameters {
                    if let Some(var_name) = Self::extract_variable_from_param(param) {
                        graph.add_dependency(&runtime_op.target_variable, &var_name)?;
                    }
                }

                log_debug!(
                    "Added resolution-time RUN operation to DAG",
                    "target" => runtime_op.target_variable.as_str()
                );
            } else {
                log_debug!(
                    "Runtime operation deferred to scan-time (not in DAG)",
                    "target" => runtime_op.target_variable.as_str()
                );
            }
        }

        // Step 6: Add variable initialization dependencies
        for variable in &context.variables {
            if let Some(var_ref) = variable.get_variable_reference() {
                graph.add_dependency(&variable.name, var_ref)?;
            }
        }

        // Step 7: Add cross-type dependencies (states, objects, sets)
        self.add_cross_type_dependencies(&mut graph, context)?;

        // Step 8: Validate graph integrity
        graph.validate()?;

        let stats = graph.get_stats();
        log_debug!(
            "Dependency graph built successfully",
            "nodes" => stats.total_nodes,
            "edges" => stats.total_edges
        );

        Ok(graph)
    }

    /// Extract variable name from RunParameter
    fn extract_variable_from_param(param: &RunParameter) -> Option<String> {
        match param {
            RunParameter::Variable(var_name) => Some(var_name.clone()),
            RunParameter::Literal(value) => {
                use crate::types::common::ValueExt;
                value.get_variable_name().map(|s| s.to_string())
            }
            RunParameter::ArithmeticOp(_, value) => {
                use crate::types::common::ValueExt;
                value.get_variable_name().map(|s| s.to_string())
            }
            _ => None,
        }
    }

    /// Add cross-type dependencies (SET operations, states, objects)
    fn add_cross_type_dependencies(
        &self,
        graph: &mut DependencyGraph,
        context: &ResolutionContext,
    ) -> Result<(), ResolutionError> {
        // SET operations depending on variables/objects
        for set_op in &context.set_operations {
            for operand in &set_op.operands {
                match operand {
                    SetOperand::ObjectRef(obj_id) => {
                        graph.add_dependency(&set_op.set_id, obj_id)?;
                    }
                    SetOperand::SetRef(other_set_id) => {
                        graph.add_dependency(&set_op.set_id, other_set_id)?;
                    }
                    SetOperand::InlineObject(obj) => {
                        // Get variable references from the inline object definition
                        let scanner_obj = crate::types::ObjectDeclaration::from_ast_node(obj);
                        for var_ref in scanner_obj.get_variable_references() {
                            graph.add_dependency(&set_op.set_id, &var_ref)?;
                        }
                    }
                    SetOperand::FilteredObjectRef {
                        object_id,
                        filter: _,
                    } => {
                        // Add dependency on the referenced object
                        graph.add_dependency(&set_op.set_id, object_id)?;
                        // Filter dependencies would be handled separately
                    }
                }
            }

            // SET filter dependencies
            if let Some(filter) = &set_op.filter {
                for state_ref in &filter.state_refs {
                    graph.add_dependency(&set_op.set_id, &state_ref.state_id)?;
                }
            }
        }

        // State dependencies on variables
        for state in &context.global_states {
            for field in &state.fields {
                use crate::types::common::ValueExt;
                if let Some(var_name) = field.value.get_variable_name() {
                    graph.add_dependency(&state.identifier, var_name)?;
                }
            }
        }

        for object in &context.global_objects {
            for var_ref in object.get_variable_references() {
                graph.add_dependency(&object.identifier, &var_ref)?;
            }
        }

        Ok(())
    }

    /// Resolve symbols in topological order
    fn resolve_symbols_in_order(
        &mut self,
        resolution_order: &[String],
        context: &mut ResolutionContext,
    ) -> Result<(), ResolutionError> {
        log_debug!("Resolution order", "order" => resolution_order.join(" -> ").as_str());

        for symbol_id in resolution_order {
            let symbol_type = self.determine_symbol_type(symbol_id, context);

            match symbol_type {
                Some(SymbolType::Variable) => {
                    self.resolve_variable(symbol_id, context)?;
                }
                Some(SymbolType::GlobalState) => {
                    self.resolve_global_state(symbol_id, context)?;
                }
                Some(SymbolType::GlobalObject) => {
                    self.resolve_global_object(symbol_id, context)?;
                }
                Some(SymbolType::SetOperation) => {
                    self.resolve_set_operation(symbol_id, context)?;
                }
                _ => {
                    log_debug!("Skipping unknown symbol", "id" => symbol_id);
                }
            }
        }
        Ok(())
    }

    /// Resolve variable (handles both initialized and computed variables)
    fn resolve_variable(
        &mut self,
        variable_name: &str,
        context: &mut ResolutionContext,
    ) -> Result<(), ResolutionError> {
        // Try to find declared variable
        let variable = context
            .variables
            .iter()
            .find(|v| v.name == variable_name)
            .cloned();

        if let Some(var) = variable {
            // CASE 1: Variable is declared
            if var.has_initial_value() {
                let resolved = self.resolve_variable_with_initial_value(&var, context)?;
                context
                    .resolved_variables
                    .insert(variable_name.to_string(), resolved);
            } else {
                // Declared computed variable (no initial value)
                if let Some(run_op) = context
                    .runtime_operations
                    .iter()
                    .find(|op| op.target_variable == variable_name)
                {
                    let has_object_dep = run_op.has_object_dependency();

                    if !has_object_dep {
                        // Resolution-time
                        let result =
                            crate::resolution::runtime_operations::execute_runtime_operation(
                                run_op,
                                &context.resolved_variables,
                            )?;

                        let resolved_var = ResolvedVariable {
                            identifier: variable_name.to_string(),
                            data_type: var.data_type,
                            value: result.clone(),
                        };

                        context
                            .resolved_variables
                            .insert(variable_name.to_string(), resolved_var);
                    } else {
                        // Scan-time - defer
                        let deferred = DeferredOperation {
                            target_variable: variable_name.to_string(),
                            operation: run_op.clone(),
                            dependencies: run_op.get_variable_references(),
                        };

                        context.scan_time_operations.push(deferred);
                    }
                } else {
                    return Err(ResolutionError::UndefinedVariable {
                        name: variable_name.to_string(),
                        context: "Computed variable has no RUN operation".to_string(),
                    });
                }
            }
        } else {
            // CASE 2: Variable is NOT declared - check RUN operations
            if let Some(run_op) = context
                .runtime_operations
                .iter()
                .find(|op| op.target_variable == variable_name)
            {
                let has_object_dep = run_op.has_object_dependency();

                if !has_object_dep {
                    // Resolution-time
                    let result = crate::resolution::runtime_operations::execute_runtime_operation(
                        run_op,
                        &context.resolved_variables,
                    )?;

                    let resolved_var = ResolvedVariable {
                        identifier: variable_name.to_string(),
                        data_type: crate::types::common::DataType::String, // Default
                        value: result.clone(),
                    };

                    context
                        .resolved_variables
                        .insert(variable_name.to_string(), resolved_var);
                } else {
                    // Scan-time - defer
                    let deferred = DeferredOperation {
                        target_variable: variable_name.to_string(),
                        operation: run_op.clone(),
                        dependencies: run_op.get_variable_references(),
                    };

                    context.scan_time_operations.push(deferred);
                }
            } else {
                return Err(ResolutionError::UndefinedVariable {
                    name: variable_name.to_string(),
                    context: "Variable not declared and has no RUN operation".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Resolve variable with initial value
    fn resolve_variable_with_initial_value(
        &self,
        variable: &VariableDeclaration,
        context: &ResolutionContext,
    ) -> Result<ResolvedVariable, ResolutionError> {
        let initial_value =
            variable
                .initial_value
                .as_ref()
                .ok_or_else(|| ResolutionError::UndefinedVariable {
                    name: variable.name.clone(),
                    context: "Variable missing initial value".to_string(),
                })?;

        let resolved_value = self.field_resolver.resolve_value(
            initial_value,
            &format!("variable '{}'", variable.name),
            &context.resolved_variables,
        )?;

        Ok(ResolvedVariable {
            identifier: variable.name.clone(),
            data_type: variable.data_type,
            value: resolved_value,
        })
    }

    /// Resolve global state
    fn resolve_global_state(
        &mut self,
        state_id: &str,
        context: &mut ResolutionContext,
    ) -> Result<(), ResolutionError> {
        let state = context
            .global_states
            .iter()
            .find(|s| s.identifier == state_id)
            .ok_or_else(|| ResolutionError::UndefinedGlobalState {
                name: state_id.to_string(),
                context: "DAG resolution".to_string(),
            })?
            .clone();

        let resolved_state = self.resolve_state_fields(&state, &context.resolved_variables)?;
        context
            .resolved_global_states
            .insert(state_id.to_string(), resolved_state);
        Ok(())
    }

    /// Resolve global object
    fn resolve_global_object(
        &mut self,
        object_id: &str,
        context: &mut ResolutionContext,
    ) -> Result<(), ResolutionError> {
        let object = context
            .global_objects
            .iter()
            .find(|o| o.identifier == object_id)
            .ok_or_else(|| ResolutionError::UndefinedGlobalObject {
                name: object_id.to_string(),
                context: "DAG resolution".to_string(),
            })?
            .clone();

        let resolved_object = self.resolve_object_fields(&object, &context.resolved_variables)?;
        context
            .resolved_global_objects
            .insert(object_id.to_string(), resolved_object);
        Ok(())
    }

    /// Resolve set operation
    fn resolve_set_operation(
        &mut self,
        set_id: &str,
        context: &mut ResolutionContext,
    ) -> Result<(), ResolutionError> {
        let set_operation = context
            .set_operations
            .iter()
            .find(|s| s.set_id == set_id)
            .ok_or_else(|| ResolutionError::SetOperationFailed {
                set_id: set_id.to_string(),
                reason: "Set operation not found".to_string(),
            })?
            .clone();

        let resolved_set =
            crate::resolution::set_operations::execute_set_operation(&set_operation, context)?;

        context
            .resolved_sets
            .insert(set_id.to_string(), resolved_set);
        Ok(())
    }

    /// Resolve local symbols (CTN-scoped states and objects)
    fn resolve_local_symbols(
        &mut self,
        context: &mut ResolutionContext,
    ) -> Result<(), ResolutionError> {
        // Resolve local objects
        for (ctn_id, local_object) in context.ctn_local_objects.clone() {
            let resolved_object =
                self.resolve_object_fields(&local_object, &context.resolved_variables)?;
            context
                .resolved_local_objects
                .insert(ctn_id, resolved_object);
        }

        // Resolve local states
        for (ctn_id, local_states) in context.ctn_local_states.clone() {
            let mut resolved_states = Vec::new();
            for state in local_states {
                let resolved_state =
                    self.resolve_state_fields(&state, &context.resolved_variables)?;
                resolved_states.push(resolved_state);
            }
            context
                .resolved_local_states
                .insert(ctn_id, resolved_states);
        }

        Ok(())
    }

    // ========== Helper Methods ==========

    fn determine_symbol_type(
        &self,
        symbol_id: &str,
        context: &ResolutionContext,
    ) -> Option<SymbolType> {
        // Check variables first (includes computed variables)
        if context.variables.iter().any(|v| v.name == symbol_id) {
            return Some(SymbolType::Variable);
        }

        if context
            .runtime_operations
            .iter()
            .any(|op| op.target_variable == symbol_id)
        {
            return Some(SymbolType::Variable);
        }

        if context.set_operations.iter().any(|s| s.set_id == symbol_id) {
            return Some(SymbolType::SetOperation);
        }

        if context
            .global_states
            .iter()
            .any(|s| s.identifier == symbol_id)
        {
            return Some(SymbolType::GlobalState);
        }

        if context
            .global_objects
            .iter()
            .any(|o| o.identifier == symbol_id)
        {
            return Some(SymbolType::GlobalObject);
        }

        None
    }

    fn count_symbols(&self, context: &ResolutionContext) -> usize {
        context.variables.len()
            + context.runtime_operations.len()
            + context.set_operations.len()
            + context.global_states.len()
            + context.global_objects.len()
    }

    fn resolve_state_fields(
        &self,
        state: &StateDeclaration,
        resolved_variables: &HashMap<String, ResolvedVariable>,
    ) -> Result<ResolvedState, ResolutionError> {
        let mut resolved_fields = Vec::new();
        let mut resolved_record_checks = Vec::new();

        for field in &state.fields {
            let resolved_field = self.resolve_single_state_field(field, resolved_variables)?;
            resolved_fields.push(resolved_field);
        }

        for record_check in &state.record_checks {
            let resolved_record_check =
                self.resolve_record_check(record_check, resolved_variables)?;
            resolved_record_checks.push(resolved_record_check);
        }

        Ok(ResolvedState {
            identifier: state.identifier.clone(),
            resolved_fields,
            resolved_record_checks,
            is_global: state.is_global,
        })
    }

    fn resolve_single_state_field(
        &self,
        field: &crate::types::state::StateField,
        resolved_variables: &HashMap<String, ResolvedVariable>,
    ) -> Result<crate::types::state::ResolvedStateField, ResolutionError> {
        let resolved_value = self.field_resolver.resolve_value(
            &field.value,
            &format!("state field '{}'", field.name),
            resolved_variables,
        )?;

        Ok(crate::types::state::ResolvedStateField {
            name: field.name.clone(),
            data_type: field.data_type,
            operation: field.operation,
            value: resolved_value,
            entity_check: field.entity_check,
        })
    }

    fn resolve_record_check(
        &self,
        record_check: &RecordCheck,
        resolved_variables: &HashMap<String, ResolvedVariable>,
    ) -> Result<ResolvedRecordCheck, ResolutionError> {
        let resolved_content = match &record_check.content {
            RecordContent::Direct { operation, value } => {
                let resolved_value = self.field_resolver.resolve_value(
                    value,
                    "record direct operation",
                    resolved_variables,
                )?;
                ResolvedRecordContent::Direct {
                    operation: *operation,
                    value: resolved_value,
                }
            }
            RecordContent::Nested { fields } => {
                let mut resolved_fields = Vec::new();
                for field in fields {
                    let resolved_value = self.field_resolver.resolve_value(
                        &field.value,
                        &format!("record field '{}'", field.path.to_dot_notation()),
                        resolved_variables,
                    )?;

                    resolved_fields.push(ResolvedRecordField {
                        path: field.path.clone(),
                        data_type: field.data_type,
                        operation: field.operation,
                        value: resolved_value,
                        entity_check: field.entity_check,
                    });
                }
                ResolvedRecordContent::Nested {
                    fields: resolved_fields,
                }
            }
        };

        Ok(ResolvedRecordCheck {
            data_type: record_check.data_type,
            content: resolved_content,
        })
    }

    fn resolve_object_fields(
        &self,
        object: &ObjectDeclaration,
        resolved_variables: &HashMap<String, ResolvedVariable>,
    ) -> Result<crate::types::object::ResolvedObject, ResolutionError> {
        let mut resolved_elements = Vec::new();

        for element in &object.elements {
            let resolved_element = match element {
                ObjectElement::Field(field) => {
                    let resolved_value = self.field_resolver.resolve_value(
                        &field.value,
                        &format!("object field '{}'", field.name),
                        resolved_variables,
                    )?;
                    crate::types::object::ResolvedObjectElement::Field {
                        name: field.name.clone(),
                        value: resolved_value,
                    }
                }
                ObjectElement::SetRef { set_id, .. } => {
                    crate::types::object::ResolvedObjectElement::SetRef {
                        set_id: set_id.clone(),
                    }
                }
                ObjectElement::Filter(filter_spec) => {
                    crate::types::object::ResolvedObjectElement::Filter(
                        crate::types::filter::ResolvedFilterSpec::new(
                            filter_spec.action,
                            filter_spec
                                .state_refs
                                .iter()
                                .map(|sr| sr.state_id.clone())
                                .collect(),
                        ),
                    )
                }
                ObjectElement::Module { field, value } => {
                    crate::types::object::ResolvedObjectElement::Module {
                        field: field.clone(),
                        value: value.clone(),
                    }
                }
                ObjectElement::Parameter { data_type, fields } => {
                    let fields_owned: Vec<(String, String)> =
                        fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                    let record = crate::types::common::RecordData::from_string_pairs(fields_owned);
                    crate::types::object::ResolvedObjectElement::Parameter {
                        data_type: *data_type,
                        data: record,
                    }
                }
                ObjectElement::Select { data_type, fields } => {
                    let fields_owned: Vec<(String, String)> =
                        fields.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                    let record = crate::types::common::RecordData::from_string_pairs(fields_owned);
                    crate::types::object::ResolvedObjectElement::Select {
                        data_type: *data_type,
                        data: record,
                    }
                }
                ObjectElement::Behavior { values } => {
                    crate::types::object::ResolvedObjectElement::Behavior {
                        values: values.clone(),
                    }
                }
                _ => {
                    // Handle other element types that might exist
                    continue;
                }
            };
            resolved_elements.push(resolved_element);
        }

        Ok(crate::types::object::ResolvedObject {
            identifier: object.identifier.clone(),
            resolved_elements,
            is_global: object.is_global,
        })
    }
}

impl Default for ResolutionEngine {
    fn default() -> Self {
        Self::new()
    }
}
