//! Complete AST node definitions for ESP Pass 2 Syntax Analysis
//!
//! This module provides the complete Abstract Syntax Tree nodes corresponding to the EBNF grammar.
//! These nodes represent the parsed structure of ESP files and are used throughout the parser pipeline.
//!
//! Design principles:
//! - EBNF compliant: Every grammar rule has corresponding AST node
//! - Span tracking: All nodes have Option<Span> for error reporting
//! - Complete coverage: All production rules represented
//! - Parser ready: Structures that parser can directly populate
//! - Serde compatible: Full serialization support for FFI consumption

use crate::utils::Span;
use serde::{Deserialize, Serialize};
use std::fmt;

// === IDENTIFIER TYPES ===
// All identifiers use the same validation rules: [a-zA-Z_][a-zA-Z0-9_]*

/// Generic identifier type for all identifiers in ESP
pub type Identifier = String;

// === DATA TYPES ===

/// Data types supported in ESP (EBNF: data_type)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataType {
    String,
    Int,
    Float,
    Boolean,
    Binary,
    RecordData,
    Version,
    EvrString,
}

impl DataType {
    /// Parse data type from string (exact match, case-sensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "string" => Some(Self::String),
            "int" => Some(Self::Int),
            "float" => Some(Self::Float),
            "boolean" => Some(Self::Boolean),
            "binary" => Some(Self::Binary),
            "record_data" => Some(Self::RecordData),
            "version" => Some(Self::Version),
            "evr_string" => Some(Self::EvrString),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Int => "int",
            Self::Float => "float",
            Self::Boolean => "boolean",
            Self::Binary => "binary",
            Self::RecordData => "record_data",
            Self::Version => "version",
            Self::EvrString => "evr_string",
        }
    }
}

// === OPERATIONS ===

/// All operations available in ESP (EBNF: operation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Operation {
    // Comparison operations (EBNF: comparison_op)
    Equals,
    NotEqual,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    // String operations
    CaseInsensitiveEquals,
    CaseInsensitiveNotEqual,
    Contains,
    StartsWith,
    EndsWith,
    NotContains,
    NotStartsWith,
    NotEndsWith,
    // Pattern operations
    PatternMatch,
    Matches,
    // Set operations
    SubsetOf,
    SupersetOf,
}

impl Operation {
    /// Parse operation from string (exact match, case-sensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "=" => Some(Self::Equals),
            "!=" => Some(Self::NotEqual),
            ">" => Some(Self::GreaterThan),
            "<" => Some(Self::LessThan),
            ">=" => Some(Self::GreaterThanOrEqual),
            "<=" => Some(Self::LessThanOrEqual),
            "ieq" => Some(Self::CaseInsensitiveEquals),
            "ine" => Some(Self::CaseInsensitiveNotEqual),
            "contains" => Some(Self::Contains),
            "starts" => Some(Self::StartsWith),
            "ends" => Some(Self::EndsWith),
            "not_contains" => Some(Self::NotContains),
            "not_starts" => Some(Self::NotStartsWith),
            "not_ends" => Some(Self::NotEndsWith),
            "pattern_match" => Some(Self::PatternMatch),
            "matches" => Some(Self::Matches),
            "subset_of" => Some(Self::SubsetOf),
            "superset_of" => Some(Self::SupersetOf),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Equals => "=",
            Self::NotEqual => "!=",
            Self::GreaterThan => ">",
            Self::LessThan => "<",
            Self::GreaterThanOrEqual => ">=",
            Self::LessThanOrEqual => "<=",
            Self::CaseInsensitiveEquals => "ieq",
            Self::CaseInsensitiveNotEqual => "ine",
            Self::Contains => "contains",
            Self::StartsWith => "starts",
            Self::EndsWith => "ends",
            Self::NotContains => "not_contains",
            Self::NotStartsWith => "not_starts",
            Self::NotEndsWith => "not_ends",
            Self::PatternMatch => "pattern_match",
            Self::Matches => "matches",
            Self::SubsetOf => "subset_of",
            Self::SupersetOf => "superset_of",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum ModuleField {
    ModuleName,
    ModuleVersion,
    ModuleType,
    ModulePath,
}

// === LOGICAL OPERATORS ===

/// Logical operators for criteria (EBNF: logical_operator)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogicalOp {
    And, // AND
    Or,  // OR
}

impl LogicalOp {
    /// Parse logical operator (case-sensitive, uppercase)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "AND" => Some(Self::And),
            "OR" => Some(Self::Or),
            _ => None,
        }
    }

    /// Get the operator as it appears in ESP source
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::And => "AND",
            Self::Or => "OR",
        }
    }
}

/// State join operators for test specifications (EBNF: state_operator)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StateJoinOp {
    And, // AND
    Or,  // OR
    One, // ONE
}

impl StateJoinOp {
    /// Parse state join operator (case-sensitive, uppercase)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "AND" => Some(Self::And),
            "OR" => Some(Self::Or),
            "ONE" => Some(Self::One),
            _ => None,
        }
    }

    /// Get the operator as it appears in ESP source
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::And => "AND",
            Self::Or => "OR",
            Self::One => "ONE",
        }
    }
}

// === TEST SPECIFICATIONS ===

/// Existence check options (EBNF: existence_check)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExistenceCheck {
    Any,        // any
    All,        // all
    None,       // none
    AtLeastOne, // at_least_one
    OnlyOne,    // only_one
}

impl ExistenceCheck {
    /// Parse existence check from string (exact match, case-sensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "any" => Some(Self::Any),
            "all" => Some(Self::All),
            "none" => Some(Self::None),
            "at_least_one" => Some(Self::AtLeastOne),
            "only_one" => Some(Self::OnlyOne),
            _ => None,
        }
    }

    /// Get the check as it appears in ESP source
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::All => "all",
            Self::None => "none",
            Self::AtLeastOne => "at_least_one",
            Self::OnlyOne => "only_one",
        }
    }
}

/// Item check options (EBNF: item_check)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ItemCheck {
    All,         // all
    AtLeastOne,  // at_least_one
    OnlyOne,     // only_one
    NoneSatisfy, // none_satisfy
}

impl ItemCheck {
    /// Parse item check from string (exact match, case-sensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Self::All),
            "at_least_one" => Some(Self::AtLeastOne),
            "only_one" => Some(Self::OnlyOne),
            "none_satisfy" => Some(Self::NoneSatisfy),
            _ => None,
        }
    }

    /// Get the check as it appears in ESP source
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::AtLeastOne => "at_least_one",
            Self::OnlyOne => "only_one",
            Self::NoneSatisfy => "none_satisfy",
        }
    }
}

/// Entity check for state fields (EBNF: entity_check)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntityCheck {
    All,        // all
    AtLeastOne, // at_least_one
    None,       // none
    OnlyOne,    // only_one
}

impl EntityCheck {
    /// Parse entity check from string (exact match, case-sensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Self::All),
            "at_least_one" => Some(Self::AtLeastOne),
            "none" => Some(Self::None),
            "only_one" => Some(Self::OnlyOne),
            _ => None,
        }
    }

    /// Get the check as it appears in ESP source
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::AtLeastOne => "at_least_one",
            Self::None => "none",
            Self::OnlyOne => "only_one",
        }
    }
}

// === VALUES ===

/// Value specification as per EBNF (value_spec)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// String literal (backtick_string)
    String(String),
    /// Integer value (integer_value) - 64-bit signed per EBNF limits
    Integer(i64),
    /// Float value (for metadata) - IEEE 754 double precision
    Float(f64),
    /// Boolean value (boolean_value)
    Boolean(bool),
    /// Variable reference (VAR variable_name)
    Variable(Identifier),
}

impl Value {
    /// Create a string value
    pub fn string(s: impl Into<String>) -> Self {
        Self::String(s.into())
    }

    /// Create an integer value
    pub fn integer(i: i64) -> Self {
        Self::Integer(i)
    }

    /// Create a float value
    pub fn float(f: f64) -> Self {
        Self::Float(f)
    }

    /// Create a boolean value
    pub fn boolean(b: bool) -> Self {
        Self::Boolean(b)
    }

    /// Create a variable reference
    pub fn variable(var: impl Into<Identifier>) -> Self {
        Self::Variable(var.into())
    }

    /// Check if this is a variable reference
    pub fn is_variable(&self) -> bool {
        matches!(self, Self::Variable(_))
    }
}

/// Field path for record datatypes (EBNF: field_path)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldPath {
    /// Path components (dot-separated identifiers)
    pub components: Vec<Identifier>,
}

impl FieldPath {
    /// Create a new field path
    pub fn new(components: Vec<Identifier>) -> Self {
        Self { components }
    }

    /// Create a single-component field path
    pub fn single(field: impl Into<Identifier>) -> Self {
        Self {
            components: vec![field.into()],
        }
    }

    /// Parse field path from dot-separated string
    pub fn parse(path: &str) -> Self {
        Self {
            components: path.split('.').map(|s| s.to_string()).collect(),
        }
    }

    /// Check if this is a simple (single component) field path
    pub fn is_simple(&self) -> bool {
        self.components.len() == 1
    }

    pub fn to_dot_notation(&self) -> String {
        self.components.join(".")
    }
}

// === RUNTIME OPERATIONS ===

/// Arithmetic operators for RUN parameters (EBNF: arithmetic_op)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArithmeticOperator {
    Add,      // +
    Multiply, // *
    Subtract, // -
    Divide,   // /
    Modulus,  // %
}

impl ArithmeticOperator {
    /// Parse arithmetic operator from string
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "+" => Some(Self::Add),
            "*" => Some(Self::Multiply),
            "-" => Some(Self::Subtract),
            "/" => Some(Self::Divide),
            "%" => Some(Self::Modulus),
            _ => None,
        }
    }

    /// Get the operator as it appears in ESP source
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Add => "+",
            Self::Multiply => "*",
            Self::Subtract => "-",
            Self::Divide => "/",
            Self::Modulus => "%",
        }
    }
}

/// Runtime operation parameters from EBNF (run_parameter)
/// UPDATED: Arithmetic operations now include paired operands
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RunParameter {
    /// Literal value (literal space value)
    Literal(Value),
    /// Variable reference (VAR space variable_name)
    Variable(String),
    /// Object field extraction (OBJ space object_id space field)
    ObjectExtraction { object_id: String, field: String },
    /// Pattern specification (pattern space backtick_string)
    Pattern(String),
    /// Delimiter specification (delimiter space backtick_string)
    Delimiter(String),
    /// Character specification (character space backtick_string)
    Character(String),
    /// Start position (start space integer_value)
    StartPosition(i64),
    /// Length value (length space integer_value)
    Length(i64),
    /// Arithmetic operation with operand (+ value, * value, etc.)
    ArithmeticOp(ArithmeticOperator, Value),
}

impl RunParameter {
    /// Create a literal parameter
    pub fn literal(value: Value) -> Self {
        Self::Literal(value)
    }

    /// Create a variable parameter
    pub fn variable(name: impl Into<String>) -> Self {
        Self::Variable(name.into())
    }

    /// Create an object extraction parameter
    pub fn object_extraction(object_id: impl Into<String>, field: impl Into<String>) -> Self {
        Self::ObjectExtraction {
            object_id: object_id.into(),
            field: field.into(),
        }
    }

    /// Create a pattern parameter
    pub fn pattern(pattern: impl Into<String>) -> Self {
        Self::Pattern(pattern.into())
    }

    /// Create a delimiter parameter
    pub fn delimiter(delimiter: impl Into<String>) -> Self {
        Self::Delimiter(delimiter.into())
    }

    /// Create an arithmetic operation parameter with value
    pub fn arithmetic_op(operator: ArithmeticOperator, value: Value) -> Self {
        Self::ArithmeticOp(operator, value)
    }
}

// === SET OPERATIONS ===

/// Set operation types (EBNF: set_operation)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SetOperationType {
    Union,        // union (1+ operands)
    Intersection, // intersection (2+ operands)
    Complement,   // complement (exactly 2 operands)
}

impl SetOperationType {
    /// Parse set operation from string (case-sensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "union" => Some(Self::Union),
            "intersection" => Some(Self::Intersection),
            "complement" => Some(Self::Complement),
            _ => None,
        }
    }

    /// Get the operation as it appears in ESP source
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Union => "union",
            Self::Intersection => "intersection",
            Self::Complement => "complement",
        }
    }

    /// Validate operand count for this operation type
    pub fn validate_operand_count(&self, count: usize) -> Result<(), String> {
        match self {
            Self::Union => {
                if count == 0 {
                    Err("Union operation requires at least 1 operand".to_string())
                } else {
                    Ok(())
                }
            }
            Self::Intersection => {
                if count < 2 {
                    Err("Intersection operation requires at least 2 operands".to_string())
                } else {
                    Ok(())
                }
            }
            Self::Complement => {
                if count != 2 {
                    Err("Complement operation requires exactly 2 operands".to_string())
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// Set operand types (EBNF: operand_type)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SetOperand {
    /// Reference to a global object (OBJECT_REF obj_id)
    ObjectRef(Identifier),
    /// Reference to another set (SET_REF set_id)
    SetRef(Identifier),
    /// Inline object definition
    InlineObject(ObjectDefinition),
    /// Filtered object reference with inline filter
    FilteredObjectRef {
        object_id: Identifier,
        filter: FilterSpec,
    },
}

/// Runtime operation types (EBNF: operation_type)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RuntimeOperationType {
    Concat,       // CONCAT
    Split,        // SPLIT
    Substring,    // SUBSTRING
    RegexCapture, // REGEX_CAPTURE
    Arithmetic,   // ARITHMETIC
    Count,        // COUNT
    Unique,       // UNIQUE
    End,          // END
    Merge,        // MERGE
    Extract,      // EXTRACT
}

impl RuntimeOperationType {
    /// Parse runtime operation from string (case-sensitive, uppercase)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "CONCAT" => Some(Self::Concat),
            "SPLIT" => Some(Self::Split),
            "SUBSTRING" => Some(Self::Substring),
            "REGEX_CAPTURE" => Some(Self::RegexCapture),
            "ARITHMETIC" => Some(Self::Arithmetic),
            "COUNT" => Some(Self::Count),
            "UNIQUE" => Some(Self::Unique),
            "END" => Some(Self::End),
            "MERGE" => Some(Self::Merge),
            "EXTRACT" => Some(Self::Extract),
            _ => None,
        }
    }

    /// Get the operation as it appears in ESP source
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Concat => "CONCAT",
            Self::Split => "SPLIT",
            Self::Substring => "SUBSTRING",
            Self::RegexCapture => "REGEX_CAPTURE",
            Self::Arithmetic => "ARITHMETIC",
            Self::Count => "COUNT",
            Self::Unique => "UNIQUE",
            Self::End => "END",
            Self::Merge => "MERGE",
            Self::Extract => "EXTRACT",
        }
    }
}

/// Filter actions (EBNF: filter_action)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FilterAction {
    Include, // include
    Exclude, // exclude
}

impl FilterAction {
    /// Parse filter action from string (case-sensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "include" => Some(Self::Include),
            "exclude" => Some(Self::Exclude),
            _ => None,
        }
    }

    /// Get the action as it appears in ESP source
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Include => "include",
            Self::Exclude => "exclude",
        }
    }
}

// === CORE AST NODES ===

/// Root AST node representing an entire ESP file
/// EBNF: esp_file ::= metadata? definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EspFile {
    /// Optional metadata block
    pub metadata: Option<MetadataBlock>,
    /// Definition block (required)
    pub definition: DefinitionNode,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Metadata block node
/// EBNF: metadata ::= "META" statement_end metadata_content "META_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetadataBlock {
    /// Individual metadata fields
    pub fields: Vec<MetadataField>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Individual metadata field
/// EBNF: metadata_field ::= field_name space field_value statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetadataField {
    /// Field name
    pub name: String,
    /// Field value (stored as string in AST)
    pub value: String,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Definition block node
/// EBNF: definition ::= "DEF" statement_end definition_content "DEF_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DefinitionNode {
    /// Variable declarations
    pub variables: Vec<VariableDeclaration>,
    /// Definition-level states (global, referenceable)
    pub states: Vec<StateDefinition>,
    /// Definition-level objects (global, referenceable)
    pub objects: Vec<ObjectDefinition>,
    /// Runtime operations
    pub runtime_operations: Vec<RuntimeOperation>,
    /// Set operations
    pub set_operations: Vec<SetOperation>,
    /// Criteria blocks (required - at least one)
    pub criteria: Vec<CriteriaNode>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Variable declaration node
/// EBNF: variable_declaration ::= "VAR" space variable_name space data_type (space initial_value)? statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VariableDeclaration {
    /// Variable name
    pub name: Identifier,
    /// Data type
    pub data_type: DataType,
    /// Optional initial value
    pub initial_value: Option<Value>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// State definition node (both global and local)
/// EBNF: definition_state ::= "STATE" space state_identifier statement_end state_content "STATE_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateDefinition {
    /// State identifier
    pub id: Identifier,
    /// State fields
    pub fields: Vec<StateField>,
    /// Record checks (for record datatype)
    pub record_checks: Vec<RecordCheck>,
    /// Whether this is a global (definition-level) state
    pub is_global: bool,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// State field node
/// EBNF: state_field ::= field_name space data_type space operation space value_spec (space entity_check)? statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateField {
    /// Field name
    pub name: Identifier,
    /// Field data type
    pub data_type: DataType,
    /// Operation to perform
    pub operation: Operation,
    /// Value to compare against
    pub value: Value,
    /// Optional entity check
    pub entity_check: Option<EntityCheck>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Record check for record datatypes
/// EBNF: record_check ::= "record" space data_type? statement_end record_content "record_end" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordCheck {
    /// Optional data type for the record
    pub data_type: Option<DataType>,
    /// Record content
    pub content: RecordContent,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Record content types
/// EBNF: record_content ::= direct_operation | nested_fields
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RecordContent {
    /// Direct operation on entire record
    Direct { operation: Operation, value: Value },
    /// Nested field operations
    Nested { fields: Vec<RecordField> },
}

/// Record field for nested record validation
/// EBNF: record_field ::= "field" space field_path space data_type space operation space value_spec (space entity_check)? statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordField {
    /// Field path (dot-separated)
    pub path: FieldPath,
    /// Field data type
    pub data_type: DataType,
    /// Operation to perform
    pub operation: Operation,
    /// Value to compare against
    pub value: Value,
    /// Optional entity check
    pub entity_check: Option<EntityCheck>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Object definition node (both global and local)
/// EBNF: definition_object ::= "OBJECT" space object_identifier statement_end object_content "OBJECT_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectDefinition {
    /// Object identifier
    pub id: Identifier,
    /// Object elements
    pub elements: Vec<ObjectElement>,
    /// Whether this is a global (definition-level) object
    pub is_global: bool,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Object element types as per EBNF (complete coverage)
/// EBNF: object_element ::= module_element | parameter_element | select_element | behavior_element | filter_spec | set_reference | object_field
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ObjectElement {
    /// Module specification
    Module { field: Identifier, value: String },
    /// Parameters with nested fields
    Parameter {
        data_type: DataType,
        fields: Vec<(Identifier, String)>,
    },
    /// Select with nested fields
    Select {
        data_type: DataType,
        fields: Vec<(Identifier, String)>,
    },
    /// Behavior specification
    Behavior { values: Vec<Identifier> },
    /// Filter specification
    Filter(FilterSpec),
    /// Set reference
    SetRef {
        set_id: Identifier,
        #[serde(skip)]
        span: Option<Span>,
    },
    /// Simple field
    Field(ObjectField),
    /// Record check element
    RecordCheck(RecordCheck),
    /// Inline SET definition
    InlineSet(SetOperation),
}

/// Simple object field
/// EBNF: object_field ::= field_name space field_value statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectField {
    /// Field name
    pub name: Identifier,
    /// Field value (string literal or variable reference)
    pub value: Value,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Runtime operation node (UPDATED: Now uses paired arithmetic parameters)
/// EBNF: run_block ::= "RUN" space variable_name space operation_type statement_end run_parameters "RUN_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeOperation {
    /// Variable to store result in
    pub target_variable: Identifier,
    /// Type of operation
    pub operation_type: RuntimeOperationType,
    /// Operation parameters (UPDATED: Now uses paired arithmetic operations)
    pub parameters: Vec<RunParameter>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Set operation node
/// EBNF: set_block ::= "SET" space set_identifier space set_operation statement_end set_content "SET_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetOperation {
    /// Set identifier
    pub set_id: Identifier,
    /// Type of set operation
    pub operation: SetOperationType,
    /// Set operands
    pub operands: Vec<SetOperand>,
    /// Optional filter
    pub filter: Option<FilterSpec>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Criteria node (CRI block)
/// EBNF: criteria ::= "CRI" space logical_operator space? negate_flag? statement_end criteria_content "CRI_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriteriaNode {
    /// Logical operator (AND/OR)
    pub logical_op: LogicalOp,
    /// Whether to negate the result
    pub negate: bool,
    /// Criteria content (nested criteria or criterion)
    pub content: Vec<CriteriaContent>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Criteria content types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CriteriaContent {
    /// Nested criteria block
    Criteria(Box<CriteriaNode>),
    /// Criterion (CTN block)
    Criterion(Box<CriterionNode>),
}

/// Criterion node (CTN block)
/// EBNF: criterion ::= "CTN" space criterion_type statement_end ctn_content "CTN_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriterionNode {
    /// Criterion type (identifier)
    pub criterion_type: Identifier,
    /// Test specification (required)
    pub test: TestSpecification,
    /// State references
    pub state_refs: Vec<StateRef>,
    /// Object references
    pub object_refs: Vec<ObjectRef>,
    /// Set references. Each SET_REF resolves at execution time into a
    /// list of object references via `set_expansion`. Lets policy authors
    /// keep the CTN block immutable while the bound-asset list (the SET
    /// body) changes -- the spec/AI workflow surface in
    /// `specs/ai-workflows.md` §3.2 relies on this shape.
    #[serde(default)]
    pub set_refs: Vec<SetRef>,
    /// Local states (CTN-level, non-referenceable)
    pub local_states: Vec<StateDefinition>,
    /// Local object (CTN-level, non-referenceable)
    pub local_object: Option<ObjectDefinition>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Test specification node (ENHANCED: Added entity_check support)
/// EBNF: test_specification ::= "TEST" space existence_check space item_check (space state_operator)? statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TestSpecification {
    /// How to check for existence of items
    pub existence_check: ExistenceCheck,
    /// How to validate items against states
    pub item_check: ItemCheck,
    /// Optional operator for combining multiple states
    pub state_operator: Option<StateJoinOp>,
    /// Optional entity check for direct integration
    pub entity_check: Option<EntityCheck>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// State reference node
/// EBNF: state_reference ::= "STATE_REF" space state_identifier statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateRef {
    /// Referenced state ID
    pub state_id: Identifier,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Object reference node
/// EBNF: object_reference ::= "OBJECT_REF" space object_identifier statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ObjectRef {
    /// Referenced object ID
    pub object_id: Identifier,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Set reference node
/// EBNF: set_reference ::= "SET_REF" space set_identifier statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SetRef {
    /// Referenced set ID
    pub set_id: Identifier,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

/// Filter specification node
/// EBNF: filter_spec ::= "FILTER" space filter_action? statement_end filter_references "FILTER_END" statement_end
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterSpec {
    /// Filter action (include/exclude)
    pub action: FilterAction,
    /// State references to filter by
    pub state_refs: Vec<StateRef>,
    /// Source location information
    #[serde(skip)]
    pub span: Option<Span>,
}

// === DISPLAY IMPLEMENTATIONS ===

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Display for RuntimeOperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Display for SetOperationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Display for ArithmeticOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl fmt::Display for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.components.join("."))
    }
}

impl fmt::Display for RunParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Literal(value) => write!(
                f,
                "literal {}",
                match value {
                    Value::String(s) => format!("`{}`", s),
                    Value::Integer(i) => i.to_string(),
                    Value::Float(fl) => fl.to_string(),
                    Value::Boolean(b) => b.to_string(),
                    Value::Variable(v) => format!("VAR {}", v),
                }
            ),
            Self::Variable(name) => write!(f, "VAR {}", name),
            Self::ObjectExtraction { object_id, field } => write!(f, "OBJ {} {}", object_id, field),
            Self::Pattern(pattern) => write!(f, "pattern `{}`", pattern),
            Self::Delimiter(delimiter) => write!(f, "delimiter `{}`", delimiter),
            Self::Character(character) => write!(f, "character `{}`", character),
            Self::StartPosition(pos) => write!(f, "start {}", pos),
            Self::Length(len) => write!(f, "length {}", len),
            Self::ArithmeticOp(op, value) => {
                write!(f, "{} ", op)?;
                match value {
                    Value::String(s) => write!(f, "`{}`", s),
                    Value::Integer(i) => write!(f, "{}", i),
                    Value::Float(fl) => write!(f, "{}", fl),
                    Value::Boolean(b) => write!(f, "{}", b),
                    Value::Variable(v) => write!(f, "VAR {}", v),
                }
            }
        }
    }
}
