//! Symbol Collection with Global Logging Integration
//!
//! Clean symbol collection using global logging macros without service injection

use crate::grammar::keywords::is_reserved_keyword;
use crate::symbols::{
    table::{RelationshipType, SymbolTableBuilder},
    SymbolDiscoveryError, SymbolDiscoveryResult,
};
use common::ast::nodes::{
    CriteriaContent, CriteriaNode, CriterionNode, DefinitionNode, EspFile, ObjectDefinition,
    ObjectElement, ObjectRef, RunParameter, RuntimeOperation, SetOperand, SetOperation, SetRef,
    StateDefinition, StateRef, Value, VariableDeclaration,
};
use common::config::constants::compile_time::symbols::*;
use common::config::runtime::SymbolPreferences;
use common::logging::codes;
use common::utils::{Position, Span};
use common::{log_debug, log_error, log_info, log_success, log_warning};

/// Symbol scope for tracking global vs local symbols
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolScope {
    Global,
    Local(String), // CTN identifier
}

/// AST Visitor trait for symbol discovery
pub trait AstVisitor {
    type Error;

    // Symbol declaration visits
    fn visit_variable(&mut self, var: &VariableDeclaration) -> Result<(), Self::Error>;
    fn visit_runtime_operation(&mut self, runtime_op: &RuntimeOperation)
        -> Result<(), Self::Error>;
    fn visit_state(
        &mut self,
        state: &StateDefinition,
        scope: SymbolScope,
    ) -> Result<(), Self::Error>;
    fn visit_object(
        &mut self,
        object: &ObjectDefinition,
        scope: SymbolScope,
    ) -> Result<(), Self::Error>;
    fn visit_set(&mut self, set: &SetOperation) -> Result<(), Self::Error>;

    // Reference visits for relationship tracking
    fn visit_state_ref(&mut self, state_ref: &StateRef) -> Result<(), Self::Error>;
    fn visit_object_ref(&mut self, object_ref: &ObjectRef) -> Result<(), Self::Error>;
    fn visit_set_ref(&mut self, set_ref: &SetRef) -> Result<(), Self::Error>;
    fn visit_variable_ref(&mut self, var_name: &str, span: Span) -> Result<(), Self::Error>;

    // Scope management
    fn enter_definition(&mut self, def: &DefinitionNode) -> Result<(), Self::Error>;
    fn exit_definition(&mut self, def: &DefinitionNode) -> Result<(), Self::Error>;
    fn enter_criterion(&mut self, ctn: &CriterionNode) -> Result<(), Self::Error>;
    fn exit_criterion(&mut self, ctn: &CriterionNode) -> Result<(), Self::Error>;
}

/// Symbol Collector with Global Logging Integration and Runtime Preferences
pub struct SymbolCollector {
    builder: SymbolTableBuilder,
    current_scope: SymbolScope,
    context_stack: Vec<String>,
    preferences: SymbolPreferences,
    // Statistics for reporting
    processed_variables: usize,
    processed_states: usize,
    processed_objects: usize,
    processed_sets: usize,
    processed_relationships: usize,
    // Enhanced metrics (when enabled)
    cross_references: std::collections::HashMap<String, Vec<String>>,
    dependency_chains: Vec<Vec<String>>,
    naming_violations: Vec<String>,
}

/// Parsed runtime parameter for dependency analysis
#[derive(Debug, Clone)]
enum ParsedParameter {
    Variable(String),
    ObjectExtraction(String),
    Literal,
}

impl SymbolCollector {
    /// Create new symbol collector with default preferences
    pub fn new() -> Self {
        Self::with_preferences(SymbolPreferences::default())
    }

    /// Create new symbol collector with specific preferences
    pub fn with_preferences(preferences: SymbolPreferences) -> Self {
        Self {
            builder: SymbolTableBuilder::new(),
            current_scope: SymbolScope::Global,
            context_stack: Vec::new(),
            preferences,
            processed_variables: 0,
            processed_states: 0,
            processed_objects: 0,
            processed_sets: 0,
            processed_relationships: 0,
            cross_references: std::collections::HashMap::new(),
            dependency_chains: Vec::new(),
            naming_violations: Vec::new(),
        }
    }

    /// Main symbol collection entry point
    pub fn collect_symbols(
        &mut self,
        ast: &EspFile,
    ) -> Result<SymbolDiscoveryResult, SymbolDiscoveryError> {
        log_info!("Starting symbol collection",
            "variables" => ast.definition.variables.len(),
            "states" => ast.definition.states.len(),
            "objects" => ast.definition.objects.len(),
            "sets" => ast.definition.set_operations.len(),
            "criteria" => ast.definition.criteria.len(),
            "detailed_relationships" => self.preferences.detailed_relationships,
            "track_cross_references" => self.preferences.track_cross_references
        );

        let result = self.visit_esp_file(ast);

        match result {
            Ok(()) => {
                let mut final_result = std::mem::take(&mut self.builder).finalize();

                // Add enhanced metrics if enabled
                if self.preferences.include_usage_metrics {
                    self.add_usage_metrics_to_result(&mut final_result);
                }

                if self.preferences.analyze_dependency_chains {
                    self.analyze_and_log_dependency_chains(&final_result);
                }

                log_success!(codes::success::SYMBOL_DISCOVERY_COMPLETE,
                    "Symbol collection completed successfully",
                    "total_symbols" => final_result.total_symbol_count(),
                    "relationships" => final_result.relationship_count(),
                    "variables_processed" => self.processed_variables,
                    "states_processed" => self.processed_states,
                    "objects_processed" => self.processed_objects,
                    "sets_processed" => self.processed_sets,
                    "relationships_processed" => self.processed_relationships,
                    "cross_references_tracked" => self.cross_references.len(),
                    "naming_violations" => self.naming_violations.len()
                );

                Ok(final_result)
            }
            Err(error) => {
                log_error!(error.error_code(), "Symbol collection failed",
                    span = error.span().unwrap_or_else(|| Span::new(Position::start(), Position::start())),
                    "error" => error.to_string(),
                    "context" => self.current_context()
                );
                Err(error)
            }
        }
    }

    // Manual AST traversal methods - matches your actual AST structure
    fn visit_esp_file(&mut self, esp_file: &EspFile) -> Result<(), SymbolDiscoveryError> {
        self.visit_definition(&esp_file.definition)
    }

    fn visit_definition(&mut self, def: &DefinitionNode) -> Result<(), SymbolDiscoveryError> {
        self.enter_definition(def)?;

        if self.preferences.detailed_relationships {
            log_debug!("Processing definition block with detailed analysis",
                "variables" => def.variables.len(),
                "runtime_operations" => def.runtime_operations.len(),
                "states" => def.states.len(),
                "objects" => def.objects.len(),
                "sets" => def.set_operations.len(),
                "criteria" => def.criteria.len()
            );
        }

        // Visit global symbols in dependency order
        for var in &def.variables {
            self.visit_variable_declaration(var)?;
        }

        for runtime_op in &def.runtime_operations {
            self.visit_runtime_operation_node(runtime_op)?;
        }

        for state in &def.states {
            self.visit_state_definition(state, SymbolScope::Global)?;
        }

        for object in &def.objects {
            self.visit_object_definition(object, SymbolScope::Global)?;
        }

        for set in &def.set_operations {
            self.visit_set_operation(set)?;
        }

        // Finally visit criteria blocks
        for criteria in &def.criteria {
            self.visit_criteria_node(criteria)?;
        }

        self.exit_definition(def)
    }

    fn visit_variable_declaration(
        &mut self,
        var: &VariableDeclaration,
    ) -> Result<(), SymbolDiscoveryError> {
        if self.preferences.detailed_relationships {
            log_debug!("Processing variable declaration with detailed analysis",
                "name" => var.name.as_str(),
                "type" => format!("{:?}", var.data_type),
                "has_initial_value" => var.initial_value.is_some()
            );
        }

        self.visit_variable(var)?;

        // Visit variable reference in initial value if present
        if let Some(Value::Variable(var_name)) = &var.initial_value {
            let span = var
                .span
                .unwrap_or_else(|| Span::new(Position::start(), Position::start()));
            self.visit_variable_ref(var_name, span)?;
        }

        Ok(())
    }

    fn visit_runtime_operation_node(
        &mut self,
        runtime_op: &RuntimeOperation,
    ) -> Result<(), SymbolDiscoveryError> {
        if self.preferences.detailed_relationships {
            log_debug!("Processing runtime operation with detailed analysis",
                "target" => runtime_op.target_variable.as_str(),
                "operation" => format!("{:?}", runtime_op.operation_type),
                "parameters" => runtime_op.parameters.len()
            );
        }

        self.visit_runtime_operation(runtime_op)?;

        let span = runtime_op
            .span
            .unwrap_or_else(|| Span::new(Position::start(), Position::start()));

        // Process RunParameter dependencies
        for param in &runtime_op.parameters {
            if let Some(dependency) = self.parse_run_parameter(param) {
                match dependency {
                    ParsedParameter::Variable(var_name) => {
                        self.add_relationship_with_preferences(
                            runtime_op.target_variable.clone(),
                            var_name.clone(),
                            RelationshipType::RunOperationInput,
                            span,
                            "run_operation_input",
                        )?;
                    }
                    ParsedParameter::ObjectExtraction(object_id) => {
                        self.add_relationship_with_preferences(
                            runtime_op.target_variable.clone(),
                            object_id.clone(),
                            RelationshipType::ObjectFieldExtraction,
                            span,
                            "object_field_extraction",
                        )?;
                    }
                    ParsedParameter::Literal => {
                        // Literals don't create dependencies
                    }
                }
            }
        }

        self.add_relationship_with_preferences(
            runtime_op.target_variable.clone(),
            runtime_op.target_variable.clone(), // Same identifier, but references the RuntimeOperationSymbol
            RelationshipType::RunOperationTarget,
            span,
            "run_operation_target",
        )?;
        self.pop_context();
        Ok(())
    }

    fn visit_state_definition(
        &mut self,
        state: &StateDefinition,
        scope: SymbolScope,
    ) -> Result<(), SymbolDiscoveryError> {
        let scope_str = match &scope {
            SymbolScope::Global => "global",
            SymbolScope::Local(ctn_type) => ctn_type,
        };

        if self.preferences.detailed_relationships {
            log_debug!("Processing state definition with detailed analysis",
                "id" => state.id.as_str(),
                "scope" => scope_str,
                "fields" => state.fields.len(),
                "record_checks" => state.record_checks.len()
            );
        }

        self.visit_state(state, scope)?;

        // Visit variable references in state fields
        for field in &state.fields {
            if let Value::Variable(var_name) = &field.value {
                let span = field
                    .span
                    .unwrap_or_else(|| Span::new(Position::start(), Position::start()));
                self.visit_variable_ref(var_name, span)?;
            }
        }

        // Visit variable references in record checks
        for record_check in &state.record_checks {
            self.visit_record_check_references(record_check)?;
        }

        self.pop_context();
        Ok(())
    }

    fn visit_record_check_references(
        &mut self,
        record_check: &common::ast::nodes::RecordCheck,
    ) -> Result<(), SymbolDiscoveryError> {
        match &record_check.content {
            common::ast::nodes::RecordContent::Direct { value, .. } => {
                if let Value::Variable(var_name) = value {
                    let span = record_check
                        .span
                        .unwrap_or_else(|| Span::new(Position::start(), Position::start()));
                    self.visit_variable_ref(var_name, span)?;
                }
            }
            common::ast::nodes::RecordContent::Nested { fields } => {
                for field in fields {
                    if let Value::Variable(var_name) = &field.value {
                        let span = field
                            .span
                            .unwrap_or_else(|| Span::new(Position::start(), Position::start()));
                        self.visit_variable_ref(var_name, span)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn visit_object_definition(
        &mut self,
        object: &ObjectDefinition,
        scope: SymbolScope,
    ) -> Result<(), SymbolDiscoveryError> {
        let scope_str = match &scope {
            SymbolScope::Global => "global",
            SymbolScope::Local(ctn_type) => ctn_type,
        };

        if self.preferences.detailed_relationships {
            log_debug!("Processing object definition with detailed analysis",
                "id" => object.id.as_str(),
                "scope" => scope_str,
                "elements" => object.elements.len()
            );
        }

        self.visit_object(object, scope)?;

        // Visit references in object elements
        for element in &object.elements {
            match element {
                ObjectElement::Field(field) => {
                    if let Value::Variable(var_name) = &field.value {
                        let span = field
                            .span
                            .unwrap_or_else(|| Span::new(Position::start(), Position::start()));
                        self.visit_variable_ref(var_name, span)?;
                    }
                }
                ObjectElement::Filter(filter) => {
                    for state_ref in &filter.state_refs {
                        self.visit_state_ref(state_ref)?;
                    }
                }
                ObjectElement::SetRef { set_id, span } => {
                    let set_ref = SetRef {
                        set_id: set_id.clone(),
                        span: *span,
                    };
                    self.visit_set_ref(&set_ref)?;
                }
                // Handle all other ObjectElement variants that don't contain references
                ObjectElement::Module { .. }
                | ObjectElement::Parameter { .. }
                | ObjectElement::Select { .. }
                | ObjectElement::Behavior { .. }
                | ObjectElement::RecordCheck(_)
                | ObjectElement::InlineSet(_) => {
                    // These don't contain symbol references we need to track
                }
            }
        }

        self.pop_context();
        Ok(())
    }

    fn visit_set_operation(&mut self, set: &SetOperation) -> Result<(), SymbolDiscoveryError> {
        if self.preferences.detailed_relationships {
            log_debug!("Processing set operation with detailed analysis",
                "id" => set.set_id.as_str(),
                "operation" => set.operation.as_str(),
                "operands" => set.operands.len(),
                "has_filter" => set.filter.is_some()
            );
        }

        self.visit_set(set)?;

        // Visit operand references
        for operand in &set.operands {
            match operand {
                SetOperand::ObjectRef(obj_id) => {
                    let obj_ref = ObjectRef {
                        object_id: obj_id.clone(),
                        span: set.span,
                    };
                    self.visit_object_ref(&obj_ref)?;
                }
                SetOperand::SetRef(set_id) => {
                    let set_ref = SetRef {
                        set_id: set_id.clone(),
                        span: set.span,
                    };
                    self.visit_set_ref(&set_ref)?;
                }
                SetOperand::InlineObject(inline_obj) => {
                    self.visit_object_definition(inline_obj, SymbolScope::Global)?;
                }
                SetOperand::FilteredObjectRef { object_id, filter } => {
                    // Handle filtered object references
                    let obj_ref = ObjectRef {
                        object_id: object_id.clone(),
                        span: set.span,
                    };
                    self.visit_object_ref(&obj_ref)?;

                    // Process filter state references
                    for state_ref in &filter.state_refs {
                        self.visit_state_ref(state_ref)?;
                    }
                }
            }
        }

        // Visit set-level filter references if present
        if let Some(filter) = &set.filter {
            for state_ref in &filter.state_refs {
                self.visit_state_ref(state_ref)?;
            }
        }

        self.pop_context();
        Ok(())
    }

    fn visit_criteria_node(&mut self, criteria: &CriteriaNode) -> Result<(), SymbolDiscoveryError> {
        if self.preferences.detailed_relationships {
            log_debug!("Processing criteria node with detailed analysis",
                "content_blocks" => criteria.content.len()
            );
        }

        for content in &criteria.content {
            match content {
                CriteriaContent::Criteria(nested_criteria) => {
                    self.visit_criteria_node(nested_criteria)?;
                }
                CriteriaContent::Criterion(criterion) => {
                    self.visit_criterion_node(criterion)?;
                }
            }
        }
        Ok(())
    }

    fn visit_criterion_node(&mut self, ctn: &CriterionNode) -> Result<(), SymbolDiscoveryError> {
        if self.preferences.detailed_relationships {
            log_debug!("Processing criterion node with detailed analysis",
                "type" => ctn.criterion_type.as_str(),
                "state_refs" => ctn.state_refs.len(),
                "object_refs" => ctn.object_refs.len(),
                "local_states" => ctn.local_states.len(),
                "has_local_object" => ctn.local_object.is_some()
            );
        }

        self.enter_criterion(ctn)?;

        // Visit references (global symbols referenced from local context)
        for state_ref in &ctn.state_refs {
            self.visit_state_ref(state_ref)?;
        }

        for object_ref in &ctn.object_refs {
            self.visit_object_ref(object_ref)?;
        }

        for set_ref in &ctn.set_refs {
            self.visit_set_ref(set_ref)?;
        }

        // Visit local symbols (CTN-scoped)
        let local_scope = SymbolScope::Local(ctn.criterion_type.clone());

        for local_state in &ctn.local_states {
            self.visit_state_definition(local_state, local_scope.clone())?;
        }

        if let Some(local_object) = &ctn.local_object {
            self.visit_object_definition(local_object, local_scope)?;
        }

        self.exit_criterion(ctn)
    }

    // Runtime parameter parsing
    fn parse_run_parameter(&self, param: &RunParameter) -> Option<ParsedParameter> {
        match param {
            RunParameter::Variable(var_name) => Some(ParsedParameter::Variable(var_name.clone())),
            RunParameter::ObjectExtraction { object_id, .. } => {
                Some(ParsedParameter::ObjectExtraction(object_id.clone()))
            }
            RunParameter::Literal(_)
            | RunParameter::Pattern(_)
            | RunParameter::Delimiter(_)
            | RunParameter::Character(_)
            | RunParameter::StartPosition(_)
            | RunParameter::Length(_)
            | RunParameter::ArithmeticOp(_, _) => Some(ParsedParameter::Literal),
        }
    }

    // Enhanced relationship handling with preferences
    fn add_relationship_with_preferences(
        &mut self,
        source: String,
        target: String,
        relationship_type: RelationshipType,
        span: Span,
        type_name: &str,
    ) -> Result<(), SymbolDiscoveryError> {
        match self
            .builder
            .add_relationship(source.clone(), target.clone(), relationship_type, span)
        {
            Ok(()) => {
                if self.preferences.detailed_relationships {
                    log_debug!("Added relationship with detailed tracking",
                        "from" => source.as_str(),
                        "to" => target.as_str(),
                        "type" => type_name
                    );
                }

                // Track cross-references if enabled
                if self.preferences.track_cross_references {
                    self.cross_references
                        .entry(source.clone())
                        .or_default()
                        .push(target.clone());
                }

                self.processed_relationships += 1;
                Ok(())
            }
            Err(err) => {
                if self.preferences.log_relationship_warnings {
                    log_warning!("Failed to add relationship",
                        "error" => err.to_string(),
                        "from" => source.as_str(),
                        "to" => target.as_str(),
                        "type" => type_name
                    );
                }
                // Continue processing instead of failing completely
                Ok(())
            }
        }
    }

    // Enhanced metrics collection
    fn add_usage_metrics_to_result(&self, _result: &mut SymbolDiscoveryResult) {
        if self.preferences.include_usage_metrics {
            log_info!("Adding usage metrics to symbol discovery result",
                "cross_references" => self.cross_references.len(),
                "dependency_chains" => self.dependency_chains.len(),
                "naming_violations" => self.naming_violations.len()
            );
            // Note: In a full implementation, you would add the metrics to the result
            // For now, we just log the availability of the metrics
        }
    }

    fn analyze_and_log_dependency_chains(&self, result: &SymbolDiscoveryResult) {
        if self.preferences.analyze_dependency_chains {
            log_debug!("Analyzing dependency chains",
                "total_relationships" => result.relationships.len()
            );

            // Simple cycle detection
            let mut cycles_found = 0;
            for relationship in &result.relationships {
                if relationship.source == relationship.target {
                    cycles_found += 1;
                }
            }

            if cycles_found > 0 {
                log_warning!("Detected self-referential dependencies",
                    "cycles_found" => cycles_found
                );
            }
        }
    }

    // Validation and utility methods with runtime preferences
    fn validate_identifier(
        &self,
        identifier: &str,
        span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        // Check identifier length limit
        if identifier.len() > MAX_SYMBOL_IDENTIFIER_LENGTH {
            let error = SymbolDiscoveryError::internal_symbol_error(&format!(
                "Identifier '{}' exceeds maximum length: {} > {}",
                identifier,
                identifier.len(),
                MAX_SYMBOL_IDENTIFIER_LENGTH
            ));
            log_error!(error.error_code(), "Identifier too long",
                span = span,
                "identifier" => identifier,
                "length" => identifier.len(),
                "max_length" => MAX_SYMBOL_IDENTIFIER_LENGTH
            );
            return Err(error);
        }

        // Enhanced naming convention validation if enabled
        if self.preferences.validate_naming_conventions {
            self.validate_naming_conventions(identifier, span)?;
        }

        if is_reserved_keyword(identifier) {
            let error = SymbolDiscoveryError::reserved_symbol_name(identifier, span);

            log_error!(error.error_code(), "Reserved keyword used as identifier",
                "identifier" => identifier
            );

            return Err(error);
        }
        Ok(())
    }

    fn validate_naming_conventions(
        &self,
        identifier: &str,
        _span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        let mut violations = Vec::new();

        // Check for snake_case convention
        if !identifier
            .chars()
            .all(|c| c.is_lowercase() || c.is_ascii_digit() || c == '_')
        {
            violations.push("should use snake_case");
        }

        // Check for leading/trailing underscores
        if identifier.starts_with('_') || identifier.ends_with('_') {
            violations.push("should not start or end with underscore");
        }

        // Check for consecutive underscores
        if identifier.contains("__") {
            violations.push("should not contain consecutive underscores");
        }

        // Check minimum length
        if identifier.len() < 2 {
            violations.push("should be at least 2 characters long");
        }

        if !violations.is_empty() {
            let violation_msg = violations.join(", ");
            log_warning!("Naming convention violations detected",
                "identifier" => identifier,
                "violations" => violation_msg.as_str()
            );

            // Store violation for metrics but don't fail
            // In practice, you might want to make this configurable
        }

        Ok(())
    }

    fn infer_runtime_operation_type(
        &self,
        runtime_op: &RuntimeOperation,
    ) -> common::ast::nodes::DataType {
        use common::ast::nodes::{DataType, RuntimeOperationType};

        match runtime_op.operation_type {
            RuntimeOperationType::Concat
            | RuntimeOperationType::Split
            | RuntimeOperationType::Substring
            | RuntimeOperationType::RegexCapture
            | RuntimeOperationType::End => DataType::String,

            RuntimeOperationType::Arithmetic | RuntimeOperationType::Count => DataType::Int,

            RuntimeOperationType::Unique
            | RuntimeOperationType::Merge
            | RuntimeOperationType::Extract => DataType::String,
        }
    }

    // Context management with bounds checking
    fn current_context(&self) -> String {
        self.context_stack.join(" -> ")
    }

    fn push_context(&mut self, context: String) {
        // Check context depth limit
        if self.context_stack.len() >= MAX_SYMBOL_CONTEXT_DEPTH {
            if self.preferences.log_relationship_warnings {
                log_warning!("Symbol context stack depth limit reached, dropping oldest context");
            }
            self.context_stack.remove(0);
        }

        if self.preferences.detailed_relationships {
            log_debug!("Entering context with detailed tracking", "context" => context.as_str());
        }
        self.context_stack.push(context);
    }

    fn pop_context(&mut self) {
        if let Some(context) = self.context_stack.pop() {
            if self.preferences.detailed_relationships {
                log_debug!("Exiting context with detailed tracking", "context" => context.as_str());
            }
        }
    }

    fn get_ctn_context(&self) -> Option<String> {
        if let SymbolScope::Local(ctn_type) = &self.current_scope {
            Some(format!("CTN({})", ctn_type))
        } else {
            None
        }
    }
}

impl Default for SymbolCollector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AST VISITOR IMPLEMENTATION
// ============================================================================

impl AstVisitor for SymbolCollector {
    type Error = SymbolDiscoveryError;

    fn visit_variable(&mut self, var: &VariableDeclaration) -> Result<(), Self::Error> {
        let span = var
            .span
            .unwrap_or_else(|| Span::new(Position::start(), Position::start()));

        if self.preferences.detailed_relationships {
            log_debug!("Adding variable symbol with detailed analysis",
                "name" => var.name.as_str(),
                "type" => format!("{:?}", var.data_type),
                "has_initial_value" => var.initial_value.is_some()
            );
        }

        self.validate_identifier(&var.name, span)?;

        self.builder.add_global_variable(
            var.name.clone(),
            var.data_type,
            var.initial_value.clone(),
            span,
        )?;

        self.processed_variables += 1;

        // Track variable initialization dependency
        if let Some(Value::Variable(init_var)) = &var.initial_value {
            self.add_relationship_with_preferences(
                var.name.clone(),
                init_var.clone(),
                RelationshipType::VariableInitialization,
                span,
                "variable_initialization",
            )?;
        }

        Ok(())
    }

    fn visit_runtime_operation(
        &mut self,
        runtime_op: &RuntimeOperation,
    ) -> Result<(), Self::Error> {
        let span = runtime_op
            .span
            .unwrap_or_else(|| Span::new(Position::start(), Position::start()));

        if self.preferences.detailed_relationships {
            log_debug!("Adding runtime operation variable with detailed analysis",
                "target" => runtime_op.target_variable.as_str(),
                "operation" => format!("{:?}", runtime_op.operation_type),
                "parameters" => runtime_op.parameters.len()
            );
        }

        self.validate_identifier(&runtime_op.target_variable, span)?;

        let data_type = self.infer_runtime_operation_type(runtime_op);

        self.builder.add_global_variable(
            runtime_op.target_variable.clone(),
            data_type,
            None,
            span,
        )?;

        self.processed_variables += 1;
        self.push_context(runtime_op.target_variable.clone());

        Ok(())
    }

    fn visit_state(
        &mut self,
        state: &StateDefinition,
        scope: SymbolScope,
    ) -> Result<(), Self::Error> {
        let span = state
            .span
            .unwrap_or_else(|| Span::new(Position::start(), Position::start()));
        let element_count = state.fields.len() + state.record_checks.len();

        self.validate_identifier(&state.id, span)?;

        match scope {
            SymbolScope::Global => {
                self.builder
                    .add_global_state(state.id.clone(), element_count, span)?;
                if self.preferences.detailed_relationships {
                    log_debug!("Added global state symbol with detailed tracking",
                        "id" => state.id.as_str(),
                        "elements" => element_count
                    );
                }
            }
            SymbolScope::Local(ref ctn_type) => {
                self.builder
                    .add_local_state(state.id.clone(), element_count, span)?;
                if self.preferences.detailed_relationships {
                    log_debug!("Added local state symbol with detailed tracking",
                        "id" => state.id.as_str(),
                        "ctn_type" => ctn_type.as_str(),
                        "elements" => element_count
                    );
                }
            }
        }

        self.processed_states += 1;
        self.push_context(state.id.clone());

        Ok(())
    }

    fn visit_object(
        &mut self,
        object: &ObjectDefinition,
        scope: SymbolScope,
    ) -> Result<(), Self::Error> {
        let span = object
            .span
            .unwrap_or_else(|| Span::new(Position::start(), Position::start()));
        let element_count = object.elements.len();

        self.validate_identifier(&object.id, span)?;

        match scope {
            SymbolScope::Global => {
                self.builder
                    .add_global_object(object.id.clone(), element_count, span)?;
                if self.preferences.detailed_relationships {
                    log_debug!("Added global object symbol with detailed tracking",
                        "id" => object.id.as_str(),
                        "elements" => element_count
                    );
                }
            }
            SymbolScope::Local(ref ctn_type) => {
                self.builder
                    .add_local_object(object.id.clone(), element_count, span)?;
                if self.preferences.detailed_relationships {
                    log_debug!("Added local object symbol with detailed tracking",
                        "id" => object.id.as_str(),
                        "ctn_type" => ctn_type.as_str(),
                        "elements" => element_count
                    );
                }
            }
        }

        self.processed_objects += 1;
        self.push_context(object.id.clone());

        Ok(())
    }

    fn visit_set(&mut self, set: &SetOperation) -> Result<(), Self::Error> {
        let span = set
            .span
            .unwrap_or_else(|| Span::new(Position::start(), Position::start()));

        if self.preferences.detailed_relationships {
            log_debug!("Adding set symbol with detailed analysis",
                "id" => set.set_id.as_str(),
                "operation" => set.operation.as_str(),
                "operands" => set.operands.len(),
                "has_filter" => set.filter.is_some()
            );
        }

        self.validate_identifier(&set.set_id, span)?;

        self.builder.add_global_set(
            set.set_id.clone(),
            set.operation,
            set.operands.len(),
            set.filter.is_some(),
            span,
        )?;

        self.processed_sets += 1;
        self.push_context(set.set_id.clone());

        Ok(())
    }

    // Scope management
    fn enter_definition(&mut self, _def: &DefinitionNode) -> Result<(), Self::Error> {
        self.current_scope = SymbolScope::Global;
        if self.preferences.detailed_relationships {
            log_debug!("Entered DEF scope (global) with detailed tracking");
        }
        Ok(())
    }

    fn exit_definition(&mut self, _def: &DefinitionNode) -> Result<(), Self::Error> {
        if self.preferences.detailed_relationships {
            log_debug!("Exited DEF scope with detailed tracking");
        }
        Ok(())
    }

    fn enter_criterion(&mut self, ctn: &CriterionNode) -> Result<(), Self::Error> {
        self.current_scope = SymbolScope::Local(ctn.criterion_type.clone());

        match self.builder.enter_ctn_scope(ctn.criterion_type.clone()) {
            Ok(_ctn_id) => {
                if self.preferences.detailed_relationships {
                    log_debug!("Entered CTN scope with detailed tracking",
                        "type" => ctn.criterion_type.as_str()
                    );
                }
                Ok(())
            }
            Err(err) => {
                log_error!(err.error_code(), "Failed to enter CTN scope",
                    "ctn_type" => ctn.criterion_type.as_str(),
                    "error" => err.to_string()
                );
                Err(err)
            }
        }
    }

    fn exit_criterion(&mut self, ctn: &CriterionNode) -> Result<(), Self::Error> {
        if self.preferences.detailed_relationships {
            log_debug!("Exiting CTN scope with detailed tracking",
                "type" => ctn.criterion_type.as_str()
            );
        }
        self.builder.exit_ctn_scope();
        self.current_scope = SymbolScope::Global;
        Ok(())
    }

    // Reference tracking with preferences
    fn visit_state_ref(&mut self, state_ref: &StateRef) -> Result<(), Self::Error> {
        if self.preferences.detailed_relationships {
            log_debug!("Processing state reference with detailed analysis",
                "id" => state_ref.state_id.as_str()
            );
        }

        if let Some(current_context) = self
            .get_current_context()
            .or_else(|| self.get_ctn_context())
        {
            self.add_relationship_with_preferences(
                current_context,
                state_ref.state_id.clone(),
                RelationshipType::StateReference,
                state_ref
                    .span
                    .unwrap_or_else(|| Span::new(Position::start(), Position::start())),
                "state_reference",
            )?;
        } else if self.preferences.log_relationship_warnings {
            log_warning!("No context available for state reference",
                "id" => state_ref.state_id.as_str()
            );
        }
        Ok(())
    }

    fn visit_object_ref(&mut self, object_ref: &ObjectRef) -> Result<(), Self::Error> {
        if self.preferences.detailed_relationships {
            log_debug!("Processing object reference with detailed analysis",
                "id" => object_ref.object_id.as_str()
            );
        }

        if let Some(current_context) = self
            .get_current_context()
            .or_else(|| self.get_ctn_context())
        {
            self.add_relationship_with_preferences(
                current_context,
                object_ref.object_id.clone(),
                RelationshipType::ObjectReference,
                object_ref
                    .span
                    .unwrap_or_else(|| Span::new(Position::start(), Position::start())),
                "object_reference",
            )?;
        } else if self.preferences.log_relationship_warnings {
            log_warning!("No context available for object reference",
                "id" => object_ref.object_id.as_str()
            );
        }
        Ok(())
    }

    fn visit_set_ref(&mut self, set_ref: &SetRef) -> Result<(), Self::Error> {
        if self.preferences.detailed_relationships {
            log_debug!("Processing set reference with detailed analysis",
                "id" => set_ref.set_id.as_str()
            );
        }

        if let Some(current_context) = self
            .get_current_context()
            .or_else(|| self.get_ctn_context())
        {
            self.add_relationship_with_preferences(
                current_context,
                set_ref.set_id.clone(),
                RelationshipType::SetReference,
                set_ref
                    .span
                    .unwrap_or_else(|| Span::new(Position::start(), Position::start())),
                "set_reference",
            )?;
        } else if self.preferences.log_relationship_warnings {
            log_warning!("No context available for set reference",
                "id" => set_ref.set_id.as_str()
            );
        }
        Ok(())
    }

    fn visit_variable_ref(&mut self, var_name: &str, span: Span) -> Result<(), Self::Error> {
        if self.preferences.detailed_relationships {
            log_debug!("Processing variable reference with detailed analysis",
                "name" => var_name
            );
        }

        if let Some(current_context) = self.get_current_context() {
            // Avoid self-reference cycles
            if current_context != var_name {
                self.add_relationship_with_preferences(
                    current_context,
                    var_name.to_string(),
                    RelationshipType::VariableUsage,
                    span,
                    "variable_usage",
                )?;
            } else if self.preferences.detailed_relationships {
                log_debug!("Skipped self-reference with detailed tracking", "variable" => var_name);
            }
        } else if self.preferences.log_relationship_warnings {
            log_warning!("No context available for variable reference", "name" => var_name);
        }
        Ok(())
    }
}

impl SymbolCollector {
    /// Get the current context for this collector (used by trait default implementations)
    fn get_current_context(&self) -> Option<String> {
        self.context_stack.last().cloned()
    }
}
