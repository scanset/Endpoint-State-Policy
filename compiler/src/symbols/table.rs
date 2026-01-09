//! Symbol table structures for Pass 3: Symbol Discovery with Relationship Tracking

use crate::symbols::SymbolDiscoveryError;
use common::ast::nodes::{DataType, SetOperationType, Value};
use common::config::constants::compile_time::symbols::*;
use common::utils::Span;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type CtnNodeId = usize;

/// Types of relationships between symbols
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RelationshipType {
    VariableInitialization, // VAR x = VAR y
    VariableUsage,          // RUN operations using VAR
    ObjectFieldExtraction,  // OBJ obj_name field_name
    StateReference,         // STATE_REF usage
    ObjectReference,        // OBJECT_REF usage
    SetReference,           // SET_REF usage
    FilterDependency,       // FILTER blocks referencing states
    RunOperationInput,      // RUN operation parameter dependencies
    RunOperationTarget,
}

impl RelationshipType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RelationshipType::VariableInitialization => "variable_initialization",
            RelationshipType::VariableUsage => "variable_usage",
            RelationshipType::ObjectFieldExtraction => "object_field_extraction",
            RelationshipType::StateReference => "state_reference",
            RelationshipType::ObjectReference => "object_reference",
            RelationshipType::SetReference => "set_reference",
            RelationshipType::FilterDependency => "filter_dependency",
            RelationshipType::RunOperationInput => "run_operation_input",
            RelationshipType::RunOperationTarget => "run_operation_target",
        }
    }
}

/// Represents a dependency relationship between symbols
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SymbolRelationship {
    pub source: String, // Symbol that depends on another
    pub target: String, // Symbol being depended upon
    pub relationship_type: RelationshipType,
    #[serde(skip)]
    pub source_span: Span,
}

impl SymbolRelationship {
    pub fn new(
        source: String,
        target: String,
        relationship_type: RelationshipType,
        source_span: Span,
    ) -> Self {
        Self {
            source,
            target,
            relationship_type,
            source_span,
        }
    }
}

/// Complete result of symbol discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolDiscoveryResult {
    pub global_symbols: GlobalSymbolTable,
    pub local_symbol_tables: Vec<LocalSymbolTable>,
    pub relationships: Vec<SymbolRelationship>,
    #[serde(skip)]
    pub errors: Vec<SymbolDiscoveryError>,
}

impl SymbolDiscoveryResult {
    pub fn new() -> Self {
        Self {
            global_symbols: GlobalSymbolTable::new(),
            local_symbol_tables: Vec::new(),
            relationships: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn total_symbol_count(&self) -> usize {
        let global_count = self.global_symbols.total_count();
        let local_count: usize = self
            .local_symbol_tables
            .iter()
            .map(|t| t.symbol_count())
            .sum();
        global_count + local_count
    }

    pub fn relationship_count(&self) -> usize {
        self.relationships.len()
    }

    pub fn is_successful(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    pub fn warning_count(&self) -> usize {
        0 // Simplified: no warnings tracking
    }

    pub fn add_error(&mut self, error: SymbolDiscoveryError) {
        self.errors.push(error);
    }

    pub fn has_global_symbol(&self, identifier: &str) -> bool {
        self.global_symbols.has_symbol(identifier)
    }

    pub fn get_relationships_for_symbol(&self, symbol: &str) -> Vec<&SymbolRelationship> {
        self.relationships
            .iter()
            .filter(|rel| rel.source == symbol || rel.target == symbol)
            .collect()
    }

    pub fn get_dependencies_of(&self, symbol: &str) -> Vec<&SymbolRelationship> {
        self.relationships
            .iter()
            .filter(|rel| rel.source == symbol)
            .collect()
    }

    pub fn get_dependents_of(&self, symbol: &str) -> Vec<&SymbolRelationship> {
        self.relationships
            .iter()
            .filter(|rel| rel.target == symbol)
            .collect()
    }
}

impl Default for SymbolDiscoveryResult {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeOperationSymbol {
    pub identifier: String,     // e.g., "concat_result" (the target variable name)
    pub operation_type: String, // e.g., "Concat"
    pub parameter_count: usize,
    #[serde(skip)]
    pub declaration_span: Span,
}

impl RuntimeOperationSymbol {
    pub fn new(
        identifier: String,
        operation_type: String,
        parameter_count: usize,
        declaration_span: Span,
    ) -> Result<Self, SymbolDiscoveryError> {
        // Validate identifier length
        if identifier.len() > MAX_SYMBOL_IDENTIFIER_LENGTH {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "Runtime operation identifier '{}' exceeds maximum length: {} > {}",
                identifier,
                identifier.len(),
                MAX_SYMBOL_IDENTIFIER_LENGTH
            )));
        }

        Ok(Self {
            identifier,
            operation_type,
            parameter_count,
            declaration_span,
        })
    }
}

/// Global symbol table with bounds checking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalSymbolTable {
    pub variables: HashMap<String, VariableSymbol>,
    pub states: HashMap<String, StateSymbol>,
    pub objects: HashMap<String, ObjectSymbol>,
    pub sets: HashMap<String, SetSymbol>,
    pub runtime_operations: HashMap<String, RuntimeOperationSymbol>,
}

impl GlobalSymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_symbol(&self, identifier: &str) -> bool {
        self.variables.contains_key(identifier)
            || self.states.contains_key(identifier)
            || self.objects.contains_key(identifier)
            || self.sets.contains_key(identifier)
            || self.runtime_operations.contains_key(identifier)
    }

    pub fn total_count(&self) -> usize {
        self.variables.len()
            + self.states.len()
            + self.objects.len()
            + self.sets.len()
            + self.runtime_operations.len()
    }

    /// Check if adding a new symbol would exceed limits
    pub fn can_add_symbol(&self) -> bool {
        self.total_count() < MAX_GLOBAL_SYMBOLS
    }

    /// Validate symbol count doesn't exceed limits
    pub fn validate_symbol_limits(&self) -> Result<(), SymbolDiscoveryError> {
        if self.total_count() >= MAX_GLOBAL_SYMBOLS {
            return Err(SymbolDiscoveryError::symbol_table_corruption(&format!(
                "Global symbol table exceeds maximum size: {} >= {}",
                self.total_count(),
                MAX_GLOBAL_SYMBOLS
            )));
        }
        Ok(())
    }

    /// Check for duplicate identifier across all global symbol types
    /// Returns the span of the existing symbol if found
    pub fn check_duplicate(&self, identifier: &str) -> Option<Span> {
        self.check_shadows(identifier).map(|(_, span)| span)
    }

    /// Check if identifier exists as global symbol (for shadowing detection)
    /// Returns (type_name, span) if found
    pub fn check_shadows(&self, identifier: &str) -> Option<(&'static str, Span)> {
        if let Some(var) = self.variables.get(identifier) {
            return Some(("variable", var.declaration_span));
        }
        if let Some(state) = self.states.get(identifier) {
            return Some(("state", state.declaration_span));
        }
        if let Some(object) = self.objects.get(identifier) {
            return Some(("object", object.declaration_span));
        }
        if let Some(set) = self.sets.get(identifier) {
            return Some(("set", set.declaration_span));
        }
        if let Some(runtime_op) = self.runtime_operations.get(identifier) {
            return Some(("runtime_operation", runtime_op.declaration_span));
        }
        None
    }
}

/// Local symbol table for CTN scope with bounds checking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalSymbolTable {
    pub ctn_node_id: CtnNodeId,
    pub ctn_type: String,
    pub states: HashMap<String, LocalStateSymbol>,
    pub object: Option<LocalObjectSymbol>, // Max 1 per CTN
}

impl LocalSymbolTable {
    pub fn new(ctn_node_id: CtnNodeId, ctn_type: String) -> Self {
        Self {
            ctn_node_id,
            ctn_type,
            states: HashMap::new(),
            object: None,
        }
    }

    pub fn has_symbol(&self, identifier: &str) -> bool {
        self.states.contains_key(identifier)
            || self
                .object
                .as_ref()
                .is_some_and(|obj| obj.identifier == identifier)
    }

    pub fn symbol_count(&self) -> usize {
        self.states.len() + if self.object.is_some() { 1 } else { 0 }
    }

    /// Check if adding a new symbol would exceed local limits
    pub fn can_add_symbol(&self) -> bool {
        self.symbol_count() < MAX_LOCAL_SYMBOLS_PER_CTN
    }

    /// Validate local symbol count doesn't exceed limits
    pub fn validate_symbol_limits(&self) -> Result<(), SymbolDiscoveryError> {
        if self.symbol_count() >= MAX_LOCAL_SYMBOLS_PER_CTN {
            return Err(SymbolDiscoveryError::symbol_table_corruption(&format!(
                "Local symbol table for CTN '{}' exceeds maximum size: {} >= {}",
                self.ctn_type,
                self.symbol_count(),
                MAX_LOCAL_SYMBOLS_PER_CTN
            )));
        }
        Ok(())
    }

    pub fn check_duplicate(&self, identifier: &str) -> Option<Span> {
        if let Some(state) = self.states.get(identifier) {
            return Some(state.declaration_span);
        }
        if let Some(obj) = &self.object {
            if obj.identifier == identifier {
                return Some(obj.declaration_span);
            }
        }
        None
    }

    pub fn has_object(&self) -> bool {
        self.object.is_some()
    }

    pub fn first_object_span(&self) -> Option<Span> {
        self.object.as_ref().map(|obj| obj.declaration_span)
    }
}

/// Variable symbol with validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableSymbol {
    pub identifier: String,
    pub data_type: DataType,
    pub initial_value: Option<Value>,
    #[serde(skip)]
    pub declaration_span: Span,
}

impl VariableSymbol {
    pub fn new(
        identifier: String,
        data_type: DataType,
        initial_value: Option<Value>,
        declaration_span: Span,
    ) -> Result<Self, SymbolDiscoveryError> {
        // Validate identifier length
        if identifier.len() > MAX_SYMBOL_IDENTIFIER_LENGTH {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "Variable identifier '{}' exceeds maximum length: {} > {}",
                identifier,
                identifier.len(),
                MAX_SYMBOL_IDENTIFIER_LENGTH
            )));
        }

        Ok(Self {
            identifier,
            data_type,
            initial_value,
            declaration_span,
        })
    }
}

/// State symbol with element count validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSymbol {
    pub identifier: String,
    pub element_count: usize,
    #[serde(skip)]
    pub declaration_span: Span,
}

impl StateSymbol {
    pub fn new(
        identifier: String,
        element_count: usize,
        declaration_span: Span,
    ) -> Result<Self, SymbolDiscoveryError> {
        // Validate identifier length
        if identifier.len() > MAX_SYMBOL_IDENTIFIER_LENGTH {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "State identifier '{}' exceeds maximum length: {} > {}",
                identifier,
                identifier.len(),
                MAX_SYMBOL_IDENTIFIER_LENGTH
            )));
        }

        // Validate element count
        if element_count > MAX_ELEMENTS_PER_SYMBOL {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "State '{}' has too many elements: {} > {}",
                identifier, element_count, MAX_ELEMENTS_PER_SYMBOL
            )));
        }

        Ok(Self {
            identifier,
            element_count,
            declaration_span,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.element_count == 0
    }
}

/// Object symbol with element count validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSymbol {
    pub identifier: String,
    pub element_count: usize,
    #[serde(skip)]
    pub declaration_span: Span,
}

impl ObjectSymbol {
    pub fn new(
        identifier: String,
        element_count: usize,
        declaration_span: Span,
    ) -> Result<Self, SymbolDiscoveryError> {
        // Validate identifier length
        if identifier.len() > MAX_SYMBOL_IDENTIFIER_LENGTH {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "Object identifier '{}' exceeds maximum length: {} > {}",
                identifier,
                identifier.len(),
                MAX_SYMBOL_IDENTIFIER_LENGTH
            )));
        }

        // Validate element count
        if element_count > MAX_ELEMENTS_PER_SYMBOL {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "Object '{}' has too many elements: {} > {}",
                identifier, element_count, MAX_ELEMENTS_PER_SYMBOL
            )));
        }

        Ok(Self {
            identifier,
            element_count,
            declaration_span,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.element_count == 0
    }
}

/// Set symbol with validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetSymbol {
    pub identifier: String,
    pub operation: SetOperationType,
    pub operand_count: usize,
    pub has_filter: bool,
    #[serde(skip)]
    pub declaration_span: Span,
}

impl SetSymbol {
    pub fn new(
        identifier: String,
        operation: SetOperationType,
        operand_count: usize,
        has_filter: bool,
        declaration_span: Span,
    ) -> Result<Self, SymbolDiscoveryError> {
        // Validate identifier length
        if identifier.len() > MAX_SYMBOL_IDENTIFIER_LENGTH {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "Set identifier '{}' exceeds maximum length: {} > {}",
                identifier,
                identifier.len(),
                MAX_SYMBOL_IDENTIFIER_LENGTH
            )));
        }

        Ok(Self {
            identifier,
            operation,
            operand_count,
            has_filter,
            declaration_span,
        })
    }
}

/// Local state symbol (CTN scope) with validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalStateSymbol {
    pub identifier: String,
    pub element_count: usize,
    #[serde(skip)]
    pub declaration_span: Span,
}

impl LocalStateSymbol {
    pub fn new(
        identifier: String,
        element_count: usize,
        declaration_span: Span,
    ) -> Result<Self, SymbolDiscoveryError> {
        // Validate identifier length
        if identifier.len() > MAX_SYMBOL_IDENTIFIER_LENGTH {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "Local state identifier '{}' exceeds maximum length: {} > {}",
                identifier,
                identifier.len(),
                MAX_SYMBOL_IDENTIFIER_LENGTH
            )));
        }

        // Validate element count
        if element_count > MAX_ELEMENTS_PER_SYMBOL {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "Local state '{}' has too many elements: {} > {}",
                identifier, element_count, MAX_ELEMENTS_PER_SYMBOL
            )));
        }

        Ok(Self {
            identifier,
            element_count,
            declaration_span,
        })
    }
}

/// Local object symbol (CTN scope) with validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalObjectSymbol {
    pub identifier: String,
    pub element_count: usize,
    #[serde(skip)]
    pub declaration_span: Span,
}

impl LocalObjectSymbol {
    pub fn new(
        identifier: String,
        element_count: usize,
        declaration_span: Span,
    ) -> Result<Self, SymbolDiscoveryError> {
        // Validate identifier length
        if identifier.len() > MAX_SYMBOL_IDENTIFIER_LENGTH {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "Local object identifier '{}' exceeds maximum length: {} > {}",
                identifier,
                identifier.len(),
                MAX_SYMBOL_IDENTIFIER_LENGTH
            )));
        }

        // Validate element count
        if element_count > MAX_ELEMENTS_PER_SYMBOL {
            return Err(SymbolDiscoveryError::internal_symbol_error(&format!(
                "Local object '{}' has too many elements: {} > {}",
                identifier, element_count, MAX_ELEMENTS_PER_SYMBOL
            )));
        }

        Ok(Self {
            identifier,
            element_count,
            declaration_span,
        })
    }
}

/// Symbol table builder with comprehensive bounds checking
/// NOTE: This is NOT serialized - it's only used during the parsing/building phase
#[derive(Debug)]
pub struct SymbolTableBuilder {
    result: SymbolDiscoveryResult,
    current_ctn_id: Option<CtnNodeId>,
    next_ctn_id: CtnNodeId,
}

impl SymbolTableBuilder {
    pub fn new() -> Self {
        Self {
            result: SymbolDiscoveryResult::new(),
            current_ctn_id: None,
            next_ctn_id: 0,
        }
    }

    /// Add runtime operation symbol
    pub fn add_runtime_operation_symbol(
        &mut self,
        identifier: String,
        operation_type: String,
        parameter_count: usize,
        span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        // Check global symbol limits
        self.result.global_symbols.validate_symbol_limits()?;

        if !self.result.global_symbols.can_add_symbol() {
            return Err(SymbolDiscoveryError::symbol_table_corruption(
                "Cannot add runtime operation: symbol limit reached",
            ));
        }

        // Check for duplicates
        if let Some(existing_span) = self.result.global_symbols.check_duplicate(&identifier) {
            return Err(SymbolDiscoveryError::duplicate_symbol(
                &identifier,
                "global",
                existing_span,
                span,
            ));
        }

        let symbol =
            RuntimeOperationSymbol::new(identifier.clone(), operation_type, parameter_count, span)?;
        self.result
            .global_symbols
            .runtime_operations
            .insert(identifier, symbol);

        Ok(())
    }

    /// Add relationship with bounds checking
    pub fn add_relationship(
        &mut self,
        source: String,
        target: String,
        relationship_type: RelationshipType,
        source_span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        // Check relationship count limit
        if self.result.relationships.len() >= MAX_SYMBOL_RELATIONSHIPS {
            return Err(SymbolDiscoveryError::symbol_table_corruption(&format!(
                "Maximum symbol relationships exceeded: {} >= {}",
                self.result.relationships.len(),
                MAX_SYMBOL_RELATIONSHIPS
            )));
        }

        let relationship = SymbolRelationship::new(source, target, relationship_type, source_span);
        self.result.relationships.push(relationship);
        Ok(())
    }

    /// Enter CTN scope with bounds checking
    pub fn enter_ctn_scope(&mut self, ctn_type: String) -> Result<CtnNodeId, SymbolDiscoveryError> {
        // Check CTN scope limit
        if self.result.local_symbol_tables.len() >= MAX_CTN_SCOPES {
            return Err(SymbolDiscoveryError::symbol_table_corruption(&format!(
                "Maximum CTN scopes exceeded: {} >= {}",
                self.result.local_symbol_tables.len(),
                MAX_CTN_SCOPES
            )));
        }

        let ctn_id = self.next_ctn_id;
        self.next_ctn_id += 1;
        self.current_ctn_id = Some(ctn_id);

        let local_table = LocalSymbolTable::new(ctn_id, ctn_type);
        self.result.local_symbol_tables.push(local_table);

        Ok(ctn_id)
    }

    pub fn exit_ctn_scope(&mut self) {
        self.current_ctn_id = None;
    }

    /// Add global variable with validation and bounds checking
    pub fn add_global_variable(
        &mut self,
        identifier: String,
        data_type: DataType,
        initial_value: Option<Value>,
        span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        // Check global symbol limits
        self.result.global_symbols.validate_symbol_limits()?;

        if !self.result.global_symbols.can_add_symbol() {
            return Err(SymbolDiscoveryError::symbol_table_corruption(
                "Cannot add global variable: symbol limit reached",
            ));
        }

        // Check for duplicates
        if let Some(existing_span) = self.result.global_symbols.check_duplicate(&identifier) {
            return Err(SymbolDiscoveryError::duplicate_symbol(
                &identifier,
                "global",
                existing_span,
                span,
            ));
        }

        let symbol = VariableSymbol::new(identifier.clone(), data_type, initial_value, span)?;
        self.result
            .global_symbols
            .variables
            .insert(identifier, symbol);

        Ok(())
    }

    /// Add global state with validation and bounds checking
    pub fn add_global_state(
        &mut self,
        identifier: String,
        element_count: usize,
        span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        // Check global symbol limits
        self.result.global_symbols.validate_symbol_limits()?;

        if !self.result.global_symbols.can_add_symbol() {
            return Err(SymbolDiscoveryError::symbol_table_corruption(
                "Cannot add global state: symbol limit reached",
            ));
        }

        if let Some(existing_span) = self.result.global_symbols.check_duplicate(&identifier) {
            return Err(SymbolDiscoveryError::duplicate_symbol(
                &identifier,
                "global",
                existing_span,
                span,
            ));
        }

        if element_count == 0 {
            return Err(SymbolDiscoveryError::empty_symbol_block(
                "STATE",
                &identifier,
                span,
            ));
        }

        let symbol = StateSymbol::new(identifier.clone(), element_count, span)?;
        self.result.global_symbols.states.insert(identifier, symbol);

        Ok(())
    }

    /// Add global object with validation and bounds checking
    pub fn add_global_object(
        &mut self,
        identifier: String,
        element_count: usize,
        span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        // Check global symbol limits
        self.result.global_symbols.validate_symbol_limits()?;

        if !self.result.global_symbols.can_add_symbol() {
            return Err(SymbolDiscoveryError::symbol_table_corruption(
                "Cannot add global object: symbol limit reached",
            ));
        }

        if let Some(existing_span) = self.result.global_symbols.check_duplicate(&identifier) {
            return Err(SymbolDiscoveryError::duplicate_symbol(
                &identifier,
                "global",
                existing_span,
                span,
            ));
        }

        if element_count == 0 {
            return Err(SymbolDiscoveryError::empty_symbol_block(
                "OBJECT",
                &identifier,
                span,
            ));
        }

        let symbol = ObjectSymbol::new(identifier.clone(), element_count, span)?;
        self.result
            .global_symbols
            .objects
            .insert(identifier, symbol);

        Ok(())
    }

    /// Add global set with validation
    pub fn add_global_set(
        &mut self,
        identifier: String,
        operation: SetOperationType,
        operand_count: usize,
        has_filter: bool,
        span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        // Check global symbol limits
        self.result.global_symbols.validate_symbol_limits()?;

        if !self.result.global_symbols.can_add_symbol() {
            return Err(SymbolDiscoveryError::symbol_table_corruption(
                "Cannot add global set: symbol limit reached",
            ));
        }

        if let Some(existing_span) = self.result.global_symbols.check_duplicate(&identifier) {
            return Err(SymbolDiscoveryError::duplicate_symbol(
                &identifier,
                "global",
                existing_span,
                span,
            ));
        }

        let symbol = SetSymbol::new(
            identifier.clone(),
            operation,
            operand_count,
            has_filter,
            span,
        )?;
        self.result.global_symbols.sets.insert(identifier, symbol);

        Ok(())
    }

    /// Add local state with validation, bounds checking, and shadowing check (N-5)
    pub fn add_local_state(
        &mut self,
        identifier: String,
        element_count: usize,
        span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        let ctn_id = self.current_ctn_id.ok_or_else(|| {
            SymbolDiscoveryError::internal_symbol_error("Cannot add local symbol: not in CTN scope")
        })?;

        // Check for shadowing (N-5): local symbol cannot shadow global symbol
        if let Some((global_type, global_span)) =
            self.result.global_symbols.check_shadows(&identifier)
        {
            let ctn_type = self
                .result
                .local_symbol_tables
                .iter()
                .find(|t| t.ctn_node_id == ctn_id)
                .map(|t| t.ctn_type.clone())
                .unwrap_or_else(|| "unknown".to_string());

            return Err(SymbolDiscoveryError::shadowing(
                &identifier,
                "state",
                global_type,
                &ctn_type,
                span,
                global_span,
            ));
        }

        let local_table = self
            .result
            .local_symbol_tables
            .iter_mut()
            .find(|table| table.ctn_node_id == ctn_id)
            .ok_or_else(|| {
                SymbolDiscoveryError::symbol_table_corruption(
                    "Local symbol table not found for current CTN",
                )
            })?;

        // Check local symbol limits
        local_table.validate_symbol_limits()?;

        if !local_table.can_add_symbol() {
            return Err(SymbolDiscoveryError::symbol_table_corruption(&format!(
                "Cannot add local state to CTN '{}': symbol limit reached",
                local_table.ctn_type
            )));
        }

        if let Some(existing_span) = local_table.check_duplicate(&identifier) {
            return Err(SymbolDiscoveryError::duplicate_symbol(
                &identifier,
                &format!("CTN({})", local_table.ctn_type),
                existing_span,
                span,
            ));
        }

        if element_count == 0 {
            return Err(SymbolDiscoveryError::empty_symbol_block(
                "STATE",
                &identifier,
                span,
            ));
        }

        let symbol = LocalStateSymbol::new(identifier.clone(), element_count, span)?;
        local_table.states.insert(identifier, symbol);

        Ok(())
    }

    /// Add local object with validation, bounds checking, and shadowing check (N-5)
    pub fn add_local_object(
        &mut self,
        identifier: String,
        element_count: usize,
        span: Span,
    ) -> Result<(), SymbolDiscoveryError> {
        let ctn_id = self.current_ctn_id.ok_or_else(|| {
            SymbolDiscoveryError::internal_symbol_error("Cannot add local symbol: not in CTN scope")
        })?;

        // Check for shadowing (N-5): local symbol cannot shadow global symbol
        if let Some((global_type, global_span)) =
            self.result.global_symbols.check_shadows(&identifier)
        {
            let ctn_type = self
                .result
                .local_symbol_tables
                .iter()
                .find(|t| t.ctn_node_id == ctn_id)
                .map(|t| t.ctn_type.clone())
                .unwrap_or_else(|| "unknown".to_string());

            return Err(SymbolDiscoveryError::shadowing(
                &identifier,
                "object",
                global_type,
                &ctn_type,
                span,
                global_span,
            ));
        }

        let local_table = self
            .result
            .local_symbol_tables
            .iter_mut()
            .find(|table| table.ctn_node_id == ctn_id)
            .ok_or_else(|| {
                SymbolDiscoveryError::symbol_table_corruption(
                    "Local symbol table not found for current CTN",
                )
            })?;

        // Check for existing object (CTN can have max 1)
        if let Some(existing_span) = local_table.first_object_span() {
            return Err(SymbolDiscoveryError::multiple_ctn_objects(
                &local_table.ctn_type,
                existing_span,
                span,
            ));
        }

        if let Some(existing_span) = local_table.check_duplicate(&identifier) {
            return Err(SymbolDiscoveryError::duplicate_symbol(
                &identifier,
                &format!("CTN({})", local_table.ctn_type),
                existing_span,
                span,
            ));
        }

        if element_count == 0 {
            return Err(SymbolDiscoveryError::empty_symbol_block(
                "OBJECT",
                &identifier,
                span,
            ));
        }

        let symbol = LocalObjectSymbol::new(identifier, element_count, span)?;
        local_table.object = Some(symbol);

        Ok(())
    }

    pub fn finalize(self) -> SymbolDiscoveryResult {
        self.result
    }

    pub fn current_result(&self) -> &SymbolDiscoveryResult {
        &self.result
    }
}

impl Default for SymbolTableBuilder {
    fn default() -> Self {
        Self::new()
    }
}
