//! Updated keyword system - structural keywords only
//!
//! ALL operators have been removed and converted to dedicated symbol tokens.
//! ALL data types have been removed and are now handled as identifiers.
use serde::{Deserialize, Serialize};
/// ESP structural keywords only - all operators and data types moved to other token types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Keyword {
    // === BLOCK STRUCTURE KEYWORDS (UPPERCASE) ===
    Meta,
    MetaEnd,
    Def,
    DefEnd,
    Cri,
    CriEnd,
    Ctn,
    CtnEnd,
    State,
    StateEnd,
    Object,
    ObjectEnd,
    Run,
    RunEnd,
    Filter,
    FilterEnd,
    Set,
    SetEnd,
    Test,

    // === BLOCK TERMINATORS (LOWERCASE) ===
    Parameters,
    ParametersEnd,
    Select,
    SelectEnd,
    Record,
    RecordEnd,

    // === REFERENCE KEYWORDS (UPPERCASE) ===
    Var,
    StateRef,
    ObjectRef,
    SetRef,

    // === LOGICAL OPERATORS (UPPERCASE) ===
    And,
    Or,
    One,

    // === RUNTIME OPERATIONS (UPPERCASE) ===
    Concat,
    Split,
    Substring,
    RegexCapture,
    Arithmetic,
    Count,
    Unique,
    End,
    Merge,
    Extract,

    // === OBJECT OPERATIONS (UPPERCASE) ===
    Obj,

    // === MODULE FIELDS (LOWERCASE WITH UNDERSCORE) ===
    ModuleName,
    Verb,
    Noun,
    ModuleId,
    ModuleVersion,

    // === OBJECT ELEMENT TYPES (LOWERCASE) ===
    Behavior,

    // === FILTER ACTIONS (LOWERCASE) ===
    Include,
    Exclude,

    // === SET OPERATIONS (LOWERCASE) ===
    Union,
    Intersection,
    Complement,

    // === TEST COMPONENTS (LOWERCASE) ===
    Any,
    All,
    AtLeastOne,
    OnlyOne,
    None,
    AllItems,
    AtLeastOneItems,
    OnlyOneItems,
    NoneSatisfy,
    // REMOVED: All data types (string, int, float, etc.) - now identifiers
    // REMOVED: All comparison operators (=, !=, >, <, etc.) - now symbol tokens
    // REMOVED: All string operators (ieq, contains, etc.) - now symbol tokens
    // REMOVED: All pattern operators (pattern_match, matches) - now symbol tokens
    // REMOVED: All set operators (subset_of, superset_of) - now symbol tokens
    // REMOVED: All arithmetic operators (+, -, *, /, %) - now symbol tokens
}

impl Keyword {
    /// Get the exact string representation as it appears in ESP source
    pub const fn as_str(self) -> &'static str {
        match self {
            // Block structure keywords
            Self::Meta => "META",
            Self::MetaEnd => "META_END",
            Self::Def => "DEF",
            Self::DefEnd => "DEF_END",
            Self::Cri => "CRI",
            Self::CriEnd => "CRI_END",
            Self::Ctn => "CTN",
            Self::CtnEnd => "CTN_END",
            Self::State => "STATE",
            Self::StateEnd => "STATE_END",
            Self::Object => "OBJECT",
            Self::ObjectEnd => "OBJECT_END",
            Self::Run => "RUN",
            Self::RunEnd => "RUN_END",
            Self::Filter => "FILTER",
            Self::FilterEnd => "FILTER_END",
            Self::Set => "SET",
            Self::SetEnd => "SET_END",
            Self::Test => "TEST",

            // Block terminators
            Self::Parameters => "parameters",
            Self::ParametersEnd => "parameters_end",
            Self::Select => "select",
            Self::SelectEnd => "select_end",
            Self::Record => "record",
            Self::RecordEnd => "record_end",

            // Reference keywords
            Self::Var => "VAR",
            Self::StateRef => "STATE_REF",
            Self::ObjectRef => "OBJECT_REF",
            Self::SetRef => "SET_REF",

            // Logical operators
            Self::And => "AND",
            Self::Or => "OR",
            Self::One => "ONE",

            // Runtime operations
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

            // Object operations
            Self::Obj => "OBJ",

            // Module fields
            Self::ModuleName => "module_name",
            Self::Verb => "verb",
            Self::Noun => "noun",
            Self::ModuleId => "module_id",
            Self::ModuleVersion => "module_version",

            // Object element types
            Self::Behavior => "behavior",

            // Filter actions
            Self::Include => "include",
            Self::Exclude => "exclude",

            // Set operations
            Self::Union => "union",
            Self::Intersection => "intersection",
            Self::Complement => "complement",

            // Test components
            Self::Any => "any",
            Self::All => "all",
            Self::AtLeastOne => "at_least_one",
            Self::OnlyOne => "only_one",
            Self::None => "none",
            Self::AllItems => "all", // Note: same as Self::All for item checks
            Self::AtLeastOneItems => "at_least_one", // Note: same as Self::AtLeastOne
            Self::OnlyOneItems => "only_one", // Note: same as Self::OnlyOne
            Self::NoneSatisfy => "none_satisfy",
        }
    }

    /// Parse keyword from string with exact case matching
    /// REMOVED: All operator keyword parsing - now handled by symbol tokens
    /// REMOVED: All data type parsing - now handled as identifiers
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            // Block structure
            "META" => Some(Self::Meta),
            "META_END" => Some(Self::MetaEnd),
            "DEF" => Some(Self::Def),
            "DEF_END" => Some(Self::DefEnd),
            "CRI" => Some(Self::Cri),
            "CRI_END" => Some(Self::CriEnd),
            "CTN" => Some(Self::Ctn),
            "CTN_END" => Some(Self::CtnEnd),
            "STATE" => Some(Self::State),
            "STATE_END" => Some(Self::StateEnd),
            "OBJECT" => Some(Self::Object),
            "OBJECT_END" => Some(Self::ObjectEnd),
            "RUN" => Some(Self::Run),
            "RUN_END" => Some(Self::RunEnd),
            "FILTER" => Some(Self::Filter),
            "FILTER_END" => Some(Self::FilterEnd),
            "SET" => Some(Self::Set),
            "SET_END" => Some(Self::SetEnd),
            "TEST" => Some(Self::Test),

            // Block terminators
            "parameters" => Some(Self::Parameters),
            "parameters_end" => Some(Self::ParametersEnd),
            "select" => Some(Self::Select),
            "select_end" => Some(Self::SelectEnd),
            "record" => Some(Self::Record),
            "record_end" => Some(Self::RecordEnd),

            // References
            "VAR" => Some(Self::Var),
            "STATE_REF" => Some(Self::StateRef),
            "OBJECT_REF" => Some(Self::ObjectRef),
            "SET_REF" => Some(Self::SetRef),

            // Logical operators
            "AND" => Some(Self::And),
            "OR" => Some(Self::Or),
            "ONE" => Some(Self::One),
            // Logical operators
            "and" => Some(Self::And),
            "or" => Some(Self::Or),
            "one" => Some(Self::One),

            // Runtime operations
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

            // Object operations
            "OBJ" => Some(Self::Obj),

            // Module fields
            "module_name" => Some(Self::ModuleName),
            "verb" => Some(Self::Verb),
            "noun" => Some(Self::Noun),
            "module_id" => Some(Self::ModuleId),
            "module_version" => Some(Self::ModuleVersion),

            // Object elements
            "behavior" => Some(Self::Behavior),

            // Filter actions
            "include" => Some(Self::Include),
            "exclude" => Some(Self::Exclude),

            // Set operations
            "union" => Some(Self::Union),
            "intersection" => Some(Self::Intersection),
            "complement" => Some(Self::Complement),

            // Test components
            "any" => Some(Self::Any),
            "all" => Some(Self::All),
            "at_least_one" => Some(Self::AtLeastOne),
            "only_one" => Some(Self::OnlyOne),
            "none" => Some(Self::None),
            "none_satisfy" => Some(Self::NoneSatisfy),

            // All other words return None (become identifiers or symbol tokens)
            // Data types: "string", "int", "float", etc. -> None (identifiers)
            // Operators: "=", "!=", "contains", etc. -> None (symbol tokens)
            // Context-sensitive: "literal", "pattern", etc. -> None (identifiers)
            _ => None,
        }
    }

    /// Get the corresponding end keyword for a block start keyword
    pub const fn corresponding_end(self) -> Option<Self> {
        match self {
            Self::Meta => Some(Self::MetaEnd),
            Self::Def => Some(Self::DefEnd),
            Self::Cri => Some(Self::CriEnd),
            Self::Ctn => Some(Self::CtnEnd),
            Self::State => Some(Self::StateEnd),
            Self::Object => Some(Self::ObjectEnd),
            Self::Run => Some(Self::RunEnd),
            Self::Filter => Some(Self::FilterEnd),
            Self::Set => Some(Self::SetEnd),
            Self::Parameters => Some(Self::ParametersEnd),
            Self::Select => Some(Self::SelectEnd),
            Self::Record => Some(Self::RecordEnd),
            _ => None,
        }
    }

    /// Check if this keyword is a block start keyword
    pub const fn is_block_start(self) -> bool {
        matches!(
            self,
            Self::Meta
                | Self::Def
                | Self::Cri
                | Self::Ctn
                | Self::State
                | Self::Object
                | Self::Run
                | Self::Filter
                | Self::Set
                | Self::Parameters
                | Self::Select
                | Self::Record
        )
    }

    /// Check if this keyword is a block end keyword
    pub const fn is_block_end(self) -> bool {
        matches!(
            self,
            Self::MetaEnd
                | Self::DefEnd
                | Self::CriEnd
                | Self::CtnEnd
                | Self::StateEnd
                | Self::ObjectEnd
                | Self::RunEnd
                | Self::FilterEnd
                | Self::SetEnd
                | Self::ParametersEnd
                | Self::SelectEnd
                | Self::RecordEnd
        )
    }

    /// Check if this keyword is a reference keyword
    pub const fn is_reference(self) -> bool {
        matches!(
            self,
            Self::Var | Self::StateRef | Self::ObjectRef | Self::SetRef
        )
    }

    /// Check if this keyword is a logical operator
    pub const fn is_logical_operator(self) -> bool {
        matches!(self, Self::And | Self::Or | Self::One)
    }

    /// Check if this keyword is a runtime operation
    pub const fn is_runtime_operation(self) -> bool {
        matches!(
            self,
            Self::Concat
                | Self::Split
                | Self::Substring
                | Self::RegexCapture
                | Self::Arithmetic
                | Self::Count
                | Self::Unique
                | Self::End
                | Self::Merge
                | Self::Extract
        )
    }

    /// Check if this keyword is a set operation
    pub const fn is_set_operation(self) -> bool {
        matches!(self, Self::Union | Self::Intersection | Self::Complement)
    }

    /// Check if this keyword is a filter action
    pub const fn is_filter_action(self) -> bool {
        matches!(self, Self::Include | Self::Exclude)
    }

    /// Check if this keyword is a test component
    pub const fn is_test_component(self) -> bool {
        matches!(
            self,
            Self::Any
                | Self::All
                | Self::AtLeastOne
                | Self::OnlyOne
                | Self::None
                | Self::AllItems
                | Self::AtLeastOneItems
                | Self::OnlyOneItems
                | Self::NoneSatisfy
        )
    }

    /// NO data type keywords anymore - all moved to identifiers
    pub const fn is_data_type(self) -> bool {
        false
    }

    /// NO operator keywords anymore - all moved to symbol tokens
    pub const fn is_operator(self) -> bool {
        false
    }

    /// NO context sensitivity in keywords anymore
    pub const fn is_context_sensitive(self) -> bool {
        false
    }
}

impl std::fmt::Display for Keyword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Generate the complete list of reserved keywords (structural only)
pub fn reserved_keywords() -> &'static [&'static str] {
    &[
        // Block structure
        "META",
        "META_END",
        "DEF",
        "DEF_END",
        "CRI",
        "CRI_END",
        "CTN",
        "CTN_END",
        "STATE",
        "STATE_END",
        "OBJECT",
        "OBJECT_END",
        "RUN",
        "RUN_END",
        "FILTER",
        "FILTER_END",
        "SET",
        "SET_END",
        "TEST",
        // Block terminators
        "parameters",
        "parameters_end",
        "select",
        "select_end",
        "record",
        "record_end",
        // References
        "VAR",
        "STATE_REF",
        "OBJECT_REF",
        "SET_REF",
        // Logical operators
        "AND",
        "OR",
        "ONE",
        // Runtime operations
        "CONCAT",
        "SPLIT",
        "SUBSTRING",
        "REGEX_CAPTURE",
        "ARITHMETIC",
        "COUNT",
        "UNIQUE",
        "END",
        "MERGE",
        "EXTRACT",
        "OBJ",
        // Module fields
        "module_name",
        "verb",
        "noun",
        "module_id",
        "module_version",
        // Object elements
        "behavior",
        // Filter actions
        "include",
        "exclude",
        // Set operations
        "union",
        "intersection",
        "complement",
        // Test components
        "any",
        "all",
        "at_least_one",
        "only_one",
        "none",
        "none_satisfy",
    ]
}

/// Data type identifiers (no longer keywords)
pub fn data_type_identifiers() -> &'static [&'static str] {
    &[
        "string",
        "int",
        "float",
        "boolean",
        "binary",
        "record_data",
        "version",
        "evr_string",
    ]
}

/// Context-sensitive identifiers (no longer keywords)
pub fn context_sensitive_identifiers() -> &'static [&'static str] {
    &[
        "literal",
        "pattern",
        "delimiter",
        "character",
        "start",
        "length",
        "field",
    ]
}

/// Symbol operator tokens (no longer keywords)
pub fn symbol_operators() -> &'static [&'static str] {
    &[
        // Single-character symbols
        "=",
        "!=",
        ">",
        "<",
        ">=",
        "<=",
        "+",
        "-",
        "*",
        "/",
        "%",
        // Multi-character symbol words
        "ieq",
        "ine",
        "contains",
        "starts",
        "ends",
        "not_contains",
        "not_starts",
        "not_ends",
        "pattern_match",
        "matches",
        "subset_of",
        "superset_of",
    ]
}

/// Check if a string is a reserved keyword
pub fn is_reserved_keyword(s: &str) -> bool {
    Keyword::parse(s).is_some()
}

/// Check if a word is a data type identifier (not keyword)
pub fn is_data_type_identifier(s: &str) -> bool {
    data_type_identifiers().contains(&s)
}

/// Check if a word is a context-sensitive identifier (not keyword)
pub fn is_context_sensitive_identifier(s: &str) -> bool {
    context_sensitive_identifiers().contains(&s)
}

/// Check if a string should be a symbol operator token
pub fn is_symbol_operator(s: &str) -> bool {
    symbol_operators().contains(&s)
}

/// Unified classification: keywords vs symbols vs identifiers
pub fn classify_word_type(word: &str) -> WordType {
    if is_reserved_keyword(word) {
        WordType::Keyword
    } else if is_symbol_operator(word) {
        WordType::SymbolOperator
    } else if is_data_type_identifier(word) {
        WordType::DataTypeIdentifier
    } else if is_context_sensitive_identifier(word) {
        WordType::ContextSensitiveIdentifier
    } else {
        WordType::RegularIdentifier
    }
}

/// Word classification for systematic tokenization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WordType {
    /// Structural keyword (becomes Token::Keyword)
    Keyword,
    /// Symbol operator (becomes Token::Equals, Token::Contains, etc.)
    SymbolOperator,
    /// Data type name (becomes Token::Identifier, handled by parser)
    DataTypeIdentifier,
    /// Context-sensitive identifier (becomes Token::Identifier, handled by parser)
    ContextSensitiveIdentifier,
    /// Regular user-defined identifier (becomes Token::Identifier)
    RegularIdentifier,
}
