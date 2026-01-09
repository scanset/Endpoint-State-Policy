//! Consolidated error codes and classification system
//!
//! Single source of truth for all error codes, their metadata, and classification functions.
//! This module combines code constants with their behavioral metadata in one place.

use std::collections::HashMap;
use std::sync::OnceLock;

// ============================================================================
// CODE WRAPPER TYPE
// ============================================================================

/// Universal code wrapper for both error and success codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Code(&'static str);

impl Code {
    pub const fn new(code: &'static str) -> Self {
        Self(code)
    }

    pub fn as_str(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for Code {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ============================================================================
// ERROR CLASSIFICATION TYPES
// ============================================================================

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical = 0,
    High = 1,
    Medium = 2,
    Low = 3,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "Critical",
            Severity::High => "High",
            Severity::Medium => "Medium",
            Severity::Low => "Low",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "Critical" => Some(Severity::Critical),
            "High" => Some(Severity::High),
            "Medium" => Some(Severity::Medium),
            "Low" => Some(Severity::Low),
            _ => None,
        }
    }
}

/// Complete metadata for an error code
#[derive(Debug, Clone)]
pub struct ErrorMetadata {
    pub code: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub recoverable: bool,
    pub requires_halt: bool,
    pub description: &'static str,
    pub recommended_action: &'static str,
}

impl ErrorMetadata {
    pub fn new(
        code: &'static str,
        category: &'static str,
        severity: Severity,
        recoverable: bool,
        requires_halt: bool,
        description: &'static str,
        recommended_action: &'static str,
    ) -> Self {
        Self {
            code,
            category,
            severity,
            recoverable,
            requires_halt,
            description,
            recommended_action,
        }
    }
}

// ============================================================================
// ERROR CODE CONSTANTS
// ============================================================================

/// System error codes
pub mod system {
    use super::Code;

    pub const INTERNAL_ERROR: Code = Code::new("ERR001");
    pub const INITIALIZATION_FAILURE: Code = Code::new("ERR002");
    pub const MEMORY_ALLOCATION_FAILURE: Code = Code::new("ERR003");
}

/// File processing error codes
pub mod file_processing {
    use super::Code;

    pub const FILE_NOT_FOUND: Code = Code::new("E005");
    pub const INVALID_EXTENSION: Code = Code::new("E006");
    pub const FILE_TOO_LARGE: Code = Code::new("E007");
    pub const EMPTY_FILE: Code = Code::new("E008");
    pub const PERMISSION_DENIED: Code = Code::new("E009");
    pub const INVALID_ENCODING: Code = Code::new("E010");
    pub const IO_ERROR: Code = Code::new("E011");
    pub const INVALID_PATH: Code = Code::new("E012");
}

/// Lexical analysis error codes
pub mod lexical {
    use super::Code;

    pub const INVALID_CHARACTER: Code = Code::new("E020");
    pub const UNTERMINATED_STRING: Code = Code::new("E021");
    pub const INVALID_NUMBER: Code = Code::new("E022");
    pub const IDENTIFIER_TOO_LONG: Code = Code::new("E023");
    pub const STRING_TOO_LARGE: Code = Code::new("E024");
    pub const RESERVED_KEYWORD: Code = Code::new("E025");

    // New security-related lexical error codes
    pub const COMMENT_TOO_LONG: Code = Code::new("E026");
    pub const TOO_MANY_TOKENS: Code = Code::new("E027");
    pub const STRING_NESTING_TOO_DEEP: Code = Code::new("E028");
}

/// Syntax analysis error codes
pub mod syntax {
    use super::Code;

    pub const MISSING_EOF: Code = Code::new("E040");
    pub const EMPTY_TOKEN_STREAM: Code = Code::new("E041");
    pub const UNMATCHED_BLOCK_DELIMITER: Code = Code::new("E042");
    pub const GRAMMAR_VIOLATION: Code = Code::new("E043");
    pub const SEMANTIC_ERROR: Code = Code::new("E044");
    pub const UNEXPECTED_TOKEN: Code = Code::new("E050");
    pub const INTERNAL_PARSER_ERROR: Code = Code::new("E086");
    pub const MAX_RECURSION_DEPTH: Code = Code::new("E087");
}

/// Symbol discovery error codes
pub mod symbols {
    use super::Code;

    pub const SYMBOL_DISCOVERY_ERROR: Code = Code::new("E051");
    pub const SYMBOL_TABLE_CONSTRUCTION_ERROR: Code = Code::new("E081");
    pub const DUPLICATE_SYMBOL: Code = Code::new("E090");
    pub const SYMBOL_SHADOWING: Code = Code::new("E091"); // NEW
    pub const MULTIPLE_LOCAL_OBJECTS: Code = Code::new("E094");
    pub const SYMBOL_SCOPE_VALIDATION_ERROR: Code = Code::new("E095");
}

/// Reference resolution error codes
pub mod references {
    use super::Code;

    pub const UNDEFINED_REFERENCE: Code = Code::new("E110");
    pub const CIRCULAR_DEPENDENCY: Code = Code::new("E140");
}

/// Semantic analysis error codes
pub mod semantic {
    use super::Code;

    pub const TYPE_INCOMPATIBILITY: Code = Code::new("E180");
    pub const RUNTIME_OPERATION_ERROR: Code = Code::new("E181");
    pub const SET_CONSTRAINT_VIOLATION: Code = Code::new("E200");
}

/// Structural validation error codes
pub mod structural {
    use super::Code;

    pub const INVALID_BLOCK_ORDERING: Code = Code::new("E230");
    pub const INCOMPLETE_DEFINITION_STRUCTURE: Code = Code::new("E240");
    pub const IMPLEMENTATION_LIMIT_EXCEEDED: Code = Code::new("E241");
    pub const EMPTY_CRITERIA_BLOCK: Code = Code::new("E242");
    pub const COMPLEXITY_VIOLATION: Code = Code::new("E243");
    pub const CONSISTENCY_VIOLATION: Code = Code::new("E244");
    pub const MULTIPLE_STRUCTURAL_ERRORS: Code = Code::new("E245");
    pub const MISSING_METADATA: Code = Code::new("E246");
    pub const METADATA_VALIDATION_ERROR: Code = Code::new("E247");
}

/// Consumer integration error codes
pub mod consumer {
    use super::Code;

    // Library integration
    pub const CONSUMER_INIT_FAILURE: Code = Code::new("C001");
    pub const CONSUMER_CONFIG_ERROR: Code = Code::new("C002");
    pub const CONSUMER_SHUTDOWN_ERROR: Code = Code::new("C003");

    // Pipeline integration
    pub const CONSUMER_PIPELINE_ERROR: Code = Code::new("C010");
    pub const CONSUMER_PASS_FAILURE: Code = Code::new("C011");
    pub const CONSUMER_STATE_MISMATCH: Code = Code::new("C012");

    // Data handling
    pub const CONSUMER_DATA_VALIDATION_ERROR: Code = Code::new("C020");
    pub const CONSUMER_FORMAT_ERROR: Code = Code::new("C021");
    pub const CONSUMER_ENCODING_ERROR: Code = Code::new("C022");

    // Resource management
    pub const CONSUMER_MEMORY_ERROR: Code = Code::new("C030");
    pub const CONSUMER_TIMEOUT_ERROR: Code = Code::new("C031");
    pub const CONSUMER_CAPACITY_ERROR: Code = Code::new("C032");

    // External system integration
    pub const CONSUMER_IO_ERROR: Code = Code::new("C040");
    pub const CONSUMER_NETWORK_ERROR: Code = Code::new("C041");
    pub const CONSUMER_PERMISSION_ERROR: Code = Code::new("C042");
}

/// FFI transformation error codes
pub mod transformation {
    use super::Code;

    // Core transformation errors
    pub const TRANSFORMATION_FAILED: Code = Code::new("T001");
    pub const AST_MAPPING_ERROR: Code = Code::new("T002");
    pub const CONTEXT_BUILDING_ERROR: Code = Code::new("T003");
    pub const DEPENDENCY_ANALYSIS_ERROR: Code = Code::new("T004");
    pub const VARIABLE_PROCESSING_ERROR: Code = Code::new("T005");
    pub const SET_RESOLUTION_ERROR: Code = Code::new("T006");
    pub const CROSS_REFERENCE_ERROR: Code = Code::new("T007");

    // Validation and serialization errors
    pub const SCHEMA_VALIDATION_ERROR: Code = Code::new("T008");
    pub const JSON_SERIALIZATION_ERROR: Code = Code::new("T009");
    pub const MEMORY_MANAGEMENT_ERROR: Code = Code::new("T010");

    // Advanced transformation errors
    pub const METADATA_EXTRACTION_ERROR: Code = Code::new("T011");
    pub const EXECUTION_ORDER_ERROR: Code = Code::new("T012");
    pub const SCOPE_MAPPING_ERROR: Code = Code::new("T013");
    pub const PARTIAL_TRANSFORMATION_ERROR: Code = Code::new("T014");
    pub const FFI_BOUNDARY_ERROR: Code = Code::new("T015");
}

// ============================================================================
// SUCCESS CODE CONSTANTS
// ============================================================================

/// Success codes
pub mod success {
    use super::Code;

    // General success codes
    pub const OPERATION_COMPLETED_SUCCESSFULLY: Code = Code::new("I001");
    pub const SYSTEM_INITIALIZATION_COMPLETED: Code = Code::new("I004");
    pub const SYSTEM_CLEANUP_COMPLETED: Code = Code::new("I005");

    // File processing success codes
    pub const FILE_PROCESSING_SUCCESS: Code = Code::new("I006");
    pub const FILE_VALIDATION_PASSED: Code = Code::new("I007");

    // Lexical success codes
    pub const TOKENIZATION_COMPLETE: Code = Code::new("I020");
    pub const LEXICAL_VALIDATION_PASSED: Code = Code::new("I021");

    // Syntax success codes
    pub const AST_CONSTRUCTION_COMPLETE: Code = Code::new("I040");
    pub const SYNTAX_VALIDATION_PASSED: Code = Code::new("I041");

    // Symbol success codes
    pub const SYMBOL_DISCOVERY_COMPLETE: Code = Code::new("I050");
    pub const SYMBOL_VALIDATION_PASSED: Code = Code::new("I051");

    // Reference resolution success codes
    pub const REFERENCE_RESOLUTION_COMPLETE: Code = Code::new("I060");
    pub const DEPENDENCY_ANALYSIS_COMPLETE: Code = Code::new("I061");

    // Semantic success codes
    pub const SEMANTIC_ANALYSIS_COMPLETE: Code = Code::new("I070");
    pub const TYPE_CHECKING_PASSED: Code = Code::new("I071");
    pub const RUNTIME_VALIDATION_COMPLETE: Code = Code::new("I072");
    pub const SET_VALIDATION_PASSED: Code = Code::new("I073");

    // Structural validation success codes
    pub const STRUCTURAL_VALIDATION_COMPLETE: Code = Code::new("I080");
    pub const COMPLETENESS_CHECK_PASSED: Code = Code::new("I081");
    pub const BLOCK_ORDERING_PASSED: Code = Code::new("I082");
    pub const LIMITS_CHECK_PASSED: Code = Code::new("I083");
    pub const REQUIREMENTS_CHECK_PASSED: Code = Code::new("I084");
    pub const METADATA_VALIDATION_PASSED: Code = Code::new("I085");
}

// ============================================================================
// ERROR METADATA REGISTRY
// ============================================================================

/// Error metadata registry using OnceLock for thread safety
static ERROR_REGISTRY: OnceLock<HashMap<&'static str, ErrorMetadata>> = OnceLock::new();

/// Initialize and get the error registry
fn get_error_registry() -> &'static HashMap<&'static str, ErrorMetadata> {
    ERROR_REGISTRY.get_or_init(|| {
        let mut registry = HashMap::new();

        // System errors
        registry.insert(
            "ERR001",
            ErrorMetadata::new(
                "ERR001",
                "System",
                Severity::Critical,
                false,
                true,
                "Critical internal system error",
                "Contact system administrator or file bug report",
            ),
        );
        registry.insert(
            "ERR002",
            ErrorMetadata::new(
                "ERR002",
                "System",
                Severity::Critical,
                false,
                true,
                "System initialization failure",
                "Check system configuration and dependencies",
            ),
        );
        registry.insert(
            "ERR003",
            ErrorMetadata::new(
                "ERR003",
                "System",
                Severity::Critical,
                false,
                true,
                "Memory allocation failure",
                "Reduce memory usage or increase available memory",
            ),
        );

        // File processing errors
        registry.insert(
            "E005",
            ErrorMetadata::new(
                "E005",
                "FileProcessing",
                Severity::Medium,
                false,
                true,
                "File not found at specified path",
                "Check file path and ensure file exists",
            ),
        );
        registry.insert(
            "E006",
            ErrorMetadata::new(
                "E006",
                "FileProcessing",
                Severity::Low,
                true,
                false,
                "File does not have .esp extension",
                "Rename file with .esp extension or verify file type",
            ),
        );
        registry.insert(
            "E007",
            ErrorMetadata::new(
                "E007",
                "FileProcessing",
                Severity::Medium,
                false,
                true,
                "File exceeds maximum size limit",
                "Reduce file size or increase processing limits",
            ),
        );
        registry.insert(
            "E008",
            ErrorMetadata::new(
                "E008",
                "FileProcessing",
                Severity::Medium,
                false,
                true,
                "File is empty when content expected",
                "Provide a file with content or check file integrity",
            ),
        );
        registry.insert(
            "E009",
            ErrorMetadata::new(
                "E009",
                "FileProcessing",
                Severity::Medium,
                false,
                true,
                "Permission denied accessing file",
                "Check file permissions and user access rights",
            ),
        );
        registry.insert(
            "E010",
            ErrorMetadata::new(
                "E010",
                "FileProcessing",
                Severity::Medium,
                false,
                true,
                "Invalid UTF-8 encoding in file",
                "Convert file to UTF-8 encoding or fix encoding issues",
            ),
        );
        registry.insert(
            "E011",
            ErrorMetadata::new(
                "E011",
                "FileProcessing",
                Severity::Medium,
                false,
                true,
                "I/O error during file operation",
                "Check disk space, permissions, and file system integrity",
            ),
        );
        registry.insert(
            "E012",
            ErrorMetadata::new(
                "E012",
                "FileProcessing",
                Severity::Medium,
                false,
                true,
                "Invalid file path provided",
                "Provide a valid file path",
            ),
        );

        // Lexical analysis errors
        registry.insert(
            "E020",
            ErrorMetadata::new(
                "E020",
                "Lexical",
                Severity::Medium,
                true,
                false,
                "Invalid character found in source text",
                "Remove or escape invalid characters",
            ),
        );
        registry.insert(
            "E021",
            ErrorMetadata::new(
                "E021",
                "Lexical",
                Severity::Medium,
                true,
                false,
                "String literal not properly terminated",
                "Add closing backtick to string literal",
            ),
        );
        registry.insert(
            "E022",
            ErrorMetadata::new(
                "E022",
                "Lexical",
                Severity::Low,
                true,
                false,
                "Number format is invalid",
                "Fix number format (remove extra decimal points, etc.)",
            ),
        );
        registry.insert(
            "E023",
            ErrorMetadata::new(
                "E023",
                "Lexical",
                Severity::Low,
                true,
                false,
                "Identifier exceeds maximum allowed length",
                "Reduce identifier length to 255 characters or less",
            ),
        );
        registry.insert(
            "E024",
            ErrorMetadata::new(
                "E024",
                "Lexical",
                Severity::Medium,
                true,
                false,
                "String literal exceeds maximum size limit",
                "Reduce string size or break into smaller parts",
            ),
        );
        registry.insert(
            "E025",
            ErrorMetadata::new(
                "E025",
                "Lexical",
                Severity::Low,
                true,
                false,
                "Reserved keyword used as identifier",
                "Choose a different identifier name",
            ),
        );

        // New security-related lexical error codes
        registry.insert(
            "E026",
            ErrorMetadata::new(
                "E026",
                "Lexical",
                Severity::Medium,
                false,
                true,
                "Comment exceeds maximum allowed length",
                "Reduce comment length or break into multiple comments",
            ),
        );
        registry.insert(
            "E027",
            ErrorMetadata::new(
                "E027",
                "Lexical",
                Severity::High,
                false,
                true,
                "File contains too many tokens, possible DoS attack",
                "Reduce file complexity or increase token limits",
            ),
        );
        registry.insert(
            "E028",
            ErrorMetadata::new(
                "E028",
                "Lexical",
                Severity::Medium,
                false,
                true,
                "String literal nesting exceeds maximum depth",
                "Reduce string nesting or simplify string structure",
            ),
        );

        // Syntax analysis errors
        registry.insert(
            "E040",
            ErrorMetadata::new(
                "E040",
                "Syntax",
                Severity::Medium,
                true,
                false,
                "Missing EOF token in token stream",
                "Ensure proper file termination",
            ),
        );
        registry.insert(
            "E041",
            ErrorMetadata::new(
                "E041",
                "Syntax",
                Severity::Medium,
                true,
                false,
                "Empty token stream - no significant tokens found",
                "Provide content in the source file",
            ),
        );
        registry.insert(
            "E042",
            ErrorMetadata::new(
                "E042",
                "Syntax",
                Severity::High,
                true,
                false,
                "Unmatched block delimiter (start without end)",
                "Add matching block terminator (e.g., DEF_END, CTN_END)",
            ),
        );
        registry.insert(
            "E043",
            ErrorMetadata::new(
                "E043",
                "Syntax",
                Severity::High,
                true,
                false,
                "Grammar violation during parsing",
                "Check EBNF compliance and fix grammar errors",
            ),
        );
        registry.insert(
            "E044",
            ErrorMetadata::new(
                "E044",
                "Syntax",
                Severity::Medium,
                true,
                false,
                "Semantic error during syntax analysis",
                "Fix semantic issues like duplicate identifiers or invalid operations",
            ),
        );
        registry.insert(
            "E050",
            ErrorMetadata::new(
                "E050",
                "Syntax",
                Severity::Medium,
                true,
                false,
                "Unexpected token during parsing",
                "Check token sequence and grammar compliance",
            ),
        );
        registry.insert(
            "E086",
            ErrorMetadata::new(
                "E086",
                "Syntax",
                Severity::Critical,
                false,
                true,
                "Internal parser error",
                "Report parser system bug",
            ),
        );
        registry.insert(
            "E087",
            ErrorMetadata::new(
                "E087",
                "Syntax",
                Severity::High,
                false,
                true,
                "Maximum recursion depth exceeded",
                "Reduce nesting depth or simplify structure",
            ),
        );

        // Symbol discovery errors
        registry.insert(
            "E051",
            ErrorMetadata::new(
                "E051",
                "Symbols",
                Severity::Medium,
                true,
                false,
                "Symbol discovery error during analysis",
                "Check symbol declarations and scope usage",
            ),
        );
        registry.insert(
            "E081",
            ErrorMetadata::new(
                "E081",
                "Symbols",
                Severity::Medium,
                true,
                false,
                "Symbol table construction error",
                "Check symbol definitions and references",
            ),
        );
        registry.insert(
            "E090",
            ErrorMetadata::new(
                "E090",
                "Symbols",
                Severity::Medium,
                true,
                false,
                "Duplicate symbol identifier within same scope",
                "Use unique identifiers within each scope",
            ),
        );
        registry.insert(
            "E094",
            ErrorMetadata::new(
                "E094",
                "Symbols",
                Severity::Medium,
                true,
                false,
                "Multiple local objects in same CTN scope",
                "Use only one local object per CTN block",
            ),
        );
        registry.insert(
            "E095",
            ErrorMetadata::new(
                "E095",
                "Symbols",
                Severity::Medium,
                true,
                false,
                "Symbol scope validation error",
                "Check symbol scope boundaries and references",
            ),
        );

        // Reference resolution errors
        registry.insert(
            "E110",
            ErrorMetadata::new(
                "E110",
                "ReferenceResolution",
                Severity::High,
                false,
                false,
                "Undefined reference target",
                "Check symbol declarations and reference names",
            ),
        );
        registry.insert(
            "E140",
            ErrorMetadata::new(
                "E140",
                "ReferenceResolution",
                Severity::High,
                true,
                false,
                "Circular variable dependency detected",
                "Break circular dependencies between variables",
            ),
        );

        // Semantic analysis errors
        registry.insert(
            "E180",
            ErrorMetadata::new(
                "E180",
                "SemanticAnalysis",
                Severity::Medium,
                true,
                false,
                "Operation not compatible with data type",
                "Use operations compatible with the data type",
            ),
        );
        registry.insert(
            "E181",
            ErrorMetadata::new(
                "E181",
                "SemanticAnalysis",
                Severity::Medium,
                true,
                false,
                "Runtime operation type error or parameter mismatch",
                "Fix runtime operation parameters - check types and counts",
            ),
        );
        registry.insert("E200", ErrorMetadata::new(
            "E200", "SemanticAnalysis", Severity::High, true, false,
            "SET operation operand count violation",
            "Check SET operation operand requirements (union: 1+, intersection: 2+, complement: 2)"
        ));

        // Structural validation errors
        registry.insert(
            "E230",
            ErrorMetadata::new(
                "E230",
                "StructuralValidation",
                Severity::Medium,
                true,
                false,
                "Invalid block ordering in ESP structure",
                "Reorder blocks according to ESP specification requirements",
            ),
        );
        registry.insert(
            "E240",
            ErrorMetadata::new(
                "E240",
                "StructuralValidation",
                Severity::High,
                true,
                false,
                "Incomplete definition structure - missing required elements",
                "Add missing required elements to complete the definition",
            ),
        );
        registry.insert(
            "E241",
            ErrorMetadata::new(
                "E241",
                "StructuralValidation",
                Severity::High,
                true,
                false,
                "Implementation limit exceeded",
                "Reduce complexity or increase implementation limits",
            ),
        );
        registry.insert(
            "E242",
            ErrorMetadata::new(
                "E242",
                "StructuralValidation",
                Severity::Medium,
                true,
                false,
                "Empty criteria block detected",
                "Add at least one CTN or nested CRI to criteria block",
            ),
        );
        registry.insert(
            "E243",
            ErrorMetadata::new(
                "E243",
                "StructuralValidation",
                Severity::Low,
                true,
                false,
                "Structural complexity violation",
                "Simplify structure to reduce complexity",
            ),
        );
        registry.insert(
            "E244",
            ErrorMetadata::new(
                "E244",
                "StructuralValidation",
                Severity::Medium,
                true,
                false,
                "Structural consistency violation",
                "Fix structural inconsistency",
            ),
        );
        registry.insert(
            "E245",
            ErrorMetadata::new(
                "E245",
                "StructuralValidation",
                Severity::High,
                true,
                false,
                "Multiple structural errors detected",
                "Review and fix all structural validation errors",
            ),
        );
        registry.insert(
            "I004",
            ErrorMetadata::new(
                "I004",
                "System",
                Severity::Low,
                true,
                false,
                "System initialization completed successfully",
                "Continue normal operation",
            ),
        );

        registry.insert(
            "I006",
            ErrorMetadata::new(
                "I006",
                "FileProcessing",
                Severity::Low,
                true,
                false,
                "File processing completed successfully",
                "Continue to next processing stage",
            ),
        );

        // Integration errors - typically medium severity, recoverable
        registry.insert(
            "C001",
            ErrorMetadata::new(
                "C001",
                "ConsumerIntegration",
                Severity::Medium,
                true,  // recoverable
                false, // doesn't require halt
                "Consumer application initialization failure",
                "Check consumer configuration and library dependencies",
            ),
        );

        // Pipeline errors - could be high severity if they affect core parsing
        registry.insert(
            "C010",
            ErrorMetadata::new(
                "C010",
                "ConsumerPipeline",
                Severity::High,
                true,
                false,
                "Consumer pipeline integration error",
                "Verify pipeline stage compatibility and data flow",
            ),
        );

        // Data validation - medium severity, usually recoverable at consumer level
        registry.insert(
            "C020",
            ErrorMetadata::new(
                "C020",
                "ConsumerData",
                Severity::Medium,
                true,
                false,
                "Consumer data validation error",
                "Validate input data format and content before processing",
            ),
        );

        // FFI Transformation errors - Core transformation failures
        registry.insert(
            "T001",
            ErrorMetadata::new(
                "T001",
                "FFITransformation",
                Severity::High,
                false,
                true,
                "Complete FFI transformation failed",
                "Check pipeline result integrity and retry transformation",
            ),
        );

        registry.insert(
            "T002",
            ErrorMetadata::new(
                "T002",
                "FFITransformation",
                Severity::Medium,
                true,
                false,
                "AST to FFI structure mapping failed",
                "Verify AST completeness and fix structural issues",
            ),
        );

        registry.insert(
            "T003",
            ErrorMetadata::new(
                "T003",
                "FFITransformation",
                Severity::Medium,
                true,
                false,
                "Execution context building from symbol tables failed",
                "Check symbol discovery results and scope definitions",
            ),
        );

        registry.insert(
            "T004",
            ErrorMetadata::new(
                "T004",
                "FFITransformation",
                Severity::High,
                true,
                false,
                "Dependency analysis for execution order failed",
                "Review variable relationships and circular dependencies",
            ),
        );

        registry.insert(
            "T005",
            ErrorMetadata::new(
                "T005",
                "FFITransformation",
                Severity::Medium,
                true,
                false,
                "Variable processing and initial value resolution failed",
                "Check variable declarations and initial value assignments",
            ),
        );

        registry.insert(
            "T006",
            ErrorMetadata::new(
                "T006",
                "FFITransformation",
                Severity::Medium,
                true,
                false,
                "Set resolution and object collection failed",
                "Verify OBJECT_REF targets exist and set operations are valid",
            ),
        );

        registry.insert(
            "T007",
            ErrorMetadata::new(
                "T007",
                "FFITransformation",
                Severity::High,
                false,
                false,
                "Cross-reference validation during transformation failed",
                "Ensure all STATE_REF, OBJECT_REF, and SET_REF targets exist",
            ),
        );

        // Validation and serialization errors
        registry.insert(
            "T008",
            ErrorMetadata::new(
                "T008",
                "FFITransformation",
                Severity::Medium,
                true,
                false,
                "FFI schema validation failed",
                "Check FFI structure completeness and field requirements",
            ),
        );

        registry.insert(
            "T009",
            ErrorMetadata::new(
                "T009",
                "FFITransformation",
                Severity::Medium,
                false,
                true,
                "JSON serialization for FFI boundary failed",
                "Check data structure compatibility and memory availability",
            ),
        );

        registry.insert(
            "T010",
            ErrorMetadata::new(
                "T010",
                "FFITransformation",
                Severity::Critical,
                false,
                true,
                "Memory management error during transformation",
                "Reduce data complexity or increase available memory",
            ),
        );

        // Advanced transformation errors
        registry.insert(
            "T011",
            ErrorMetadata::new(
                "T011",
                "FFITransformation",
                Severity::Low,
                true,
                false,
                "Scanner metadata extraction failed",
                "Check metadata block completeness and format",
            ),
        );

        registry.insert(
            "T012",
            ErrorMetadata::new(
                "T012",
                "FFITransformation",
                Severity::High,
                true,
                false,
                "Execution order generation failed",
                "Review dependency relationships and resolve circular references",
            ),
        );

        registry.insert(
            "T013",
            ErrorMetadata::new(
                "T013",
                "FFITransformation",
                Severity::Medium,
                true,
                false,
                "Symbol scope mapping to execution context failed",
                "Verify global and local symbol table integrity",
            ),
        );

        registry.insert(
            "T014",
            ErrorMetadata::new(
                "T014",
                "FFITransformation",
                Severity::Medium,
                true,
                false,
                "Partial transformation completed with recoverable errors",
                "Review error details and fix non-critical issues",
            ),
        );

        registry.insert(
            "T015",
            ErrorMetadata::new(
                "T015",
                "FFITransformation",
                Severity::Critical,
                false,
                true,
                "FFI boundary crossing error",
                "Check C FFI compatibility and memory layout",
            ),
        );

        // FFI Transformation success codes
        registry.insert(
            "I090",
            ErrorMetadata::new(
                "I090",
                "FFITransformation",
                Severity::Low,
                true,
                false,
                "FFI transformation completed successfully",
                "Continue to scanner interface",
            ),
        );

        registry.insert(
            "I091",
            ErrorMetadata::new(
                "I091",
                "FFITransformation",
                Severity::Low,
                true,
                false,
                "AST mapping to FFI structures completed successfully",
                "Continue to context building stage",
            ),
        );

        registry.insert(
            "I092",
            ErrorMetadata::new(
                "I092",
                "FFITransformation",
                Severity::Low,
                true,
                false,
                "Dependency analysis completed successfully",
                "Continue to variable processing stage",
            ),
        );

        registry.insert(
            "I093",
            ErrorMetadata::new(
                "I093",
                "FFITransformation",
                Severity::Low,
                true,
                false,
                "Variable resolution completed successfully",
                "Continue to set resolution stage",
            ),
        );

        registry.insert(
            "I094",
            ErrorMetadata::new(
                "I094",
                "FFITransformation",
                Severity::Low,
                true,
                false,
                "Set resolution completed successfully",
                "Continue to context building stage",
            ),
        );

        registry.insert(
            "I095",
            ErrorMetadata::new(
                "I095",
                "FFITransformation",
                Severity::Low,
                true,
                false,
                "Execution context building completed successfully",
                "FFI transformation ready for serialization",
            ),
        );

        // In get_error_registry(), after the E090 entry:

        registry.insert(
            "E091",
            ErrorMetadata::new(
                "E091",
                "Symbols",
                Severity::Medium,
                true,  // recoverable
                false, // doesn't require halt
                "Local symbol shadows global symbol with same identifier",
                "Use unique identifier for local symbol or reference the global symbol directly",
            ),
        );

        //Metadata validation error codes
        registry.insert(
            "E246",
            ErrorMetadata::new(
                "E246",
                "StructuralValidation",
                Severity::High,
                true,  // recoverable
                false, // doesn't require halt
                "Missing META block - required for v1.0.0 compliance",
                "Add META block with required fields: esp_id, version, dsl_schema_version, platform, criticality, control_mapping, title",
            ),
        );

        registry.insert(
            "E247",
            ErrorMetadata::new(
                "E247",
                "StructuralValidation",
                Severity::Medium,
                true,  // recoverable
                false, // doesn't require halt
                "META block validation error - field missing or invalid",
                "Check META block fields for v1.0.0 compliance: verify required fields are present and values are valid",
            ),
        );

        // Success code for metadata validation
        registry.insert(
            "I085",
            ErrorMetadata::new(
                "I085",
                "StructuralValidation",
                Severity::Low,
                true,
                false,
                "META block validation completed successfully",
                "Continue to next validation phase",
            ),
        );

        registry
    })
}

// ============================================================================
// CLASSIFICATION FUNCTIONS
// ============================================================================

/// Get error metadata for a specific error code
pub fn get_error_metadata(code: &str) -> Option<&'static ErrorMetadata> {
    get_error_registry().get(code)
}

/// Get error severity from error code
pub fn get_severity(code: &str) -> Severity {
    get_error_registry()
        .get(code)
        .map(|metadata| metadata.severity)
        .unwrap_or(Severity::Medium)
}

/// Check if error is recoverable
pub fn is_recoverable(code: &str) -> bool {
    get_error_registry()
        .get(code)
        .map(|metadata| metadata.recoverable)
        .unwrap_or(true)
}

/// Check if error requires immediate halt
pub fn requires_halt(code: &str) -> bool {
    get_error_registry()
        .get(code)
        .map(|metadata| metadata.requires_halt)
        .unwrap_or(false)
}

/// Get human-readable description for error code
pub fn get_description(code: &str) -> &'static str {
    get_error_registry()
        .get(code)
        .map(|metadata| metadata.description)
        .unwrap_or("Unknown error")
}

/// Get recommended action for error code
pub fn get_action(code: &str) -> &'static str {
    get_error_registry()
        .get(code)
        .map(|metadata| metadata.recommended_action)
        .unwrap_or("No specific action available")
}

/// Get error category from error code
pub fn get_category(code: &str) -> &'static str {
    get_error_registry()
        .get(code)
        .map(|metadata| metadata.category)
        .unwrap_or("Unknown")
}
