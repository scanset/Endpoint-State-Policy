pub mod compile_time {
    pub mod file_processing {
        /// Maximum file size allowed for processing (10MB)
        /// SECURITY: Prevents DoS attacks via large file uploads
        /// SSDF: PW.7.1 (Input Validation), PW.8.1 (DoS Protection)
        pub const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024;

        /// Threshold for considering a file "large" (1MB)
        /// PERFORMANCE: Affects processing strategy and complexity analysis
        pub const LARGE_FILE_THRESHOLD: u64 = 1024 * 1024;

        /// Maximum line count for complexity analysis
        /// SECURITY: Prevents algorithmic complexity attacks
        pub const MAX_LINE_COUNT_FOR_ANALYSIS: usize = 100_000;

        /// Performance logging buffer size
        /// RESOURCE: Controls memory usage for metrics collection
        pub const PERFORMANCE_LOG_BUFFER_SIZE: usize = 1000;
    }

    pub mod lexical {
        /// Maximum string literal size (1MB)
        /// SECURITY: Prevents DoS attacks via enormous string literals
        /// SSDF: PW.7.1 (Input Validation), PW.8.1 (DoS Protection)
        pub const MAX_STRING_SIZE: usize = 1_048_576;

        /// Maximum identifier length (255 characters)
        /// SECURITY: Prevents parser complexity attacks
        /// SSDF: PW.7.1 (Input Validation)
        pub const MAX_IDENTIFIER_LENGTH: usize = 255;

        /// Maximum comment length to prevent memory exhaustiona
        /// SECURITY: Limits resource consumption per comment
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_COMMENT_LENGTH: usize = 10_000;

        /// Maximum number tokens allowed in a single file
        /// SECURITY: Prevents DoS via token explosion attacks
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_TOKEN_COUNT: usize = 1_000_000;

        /// Buffer size for lexical metrics collection
        /// RESOURCE: Controls memory allocation for metrics
        pub const METRICS_BUFFER_SIZE: usize = 1000;

        /// Maximum depth for nested string parsing (multiline strings)
        /// SECURITY: Prevents stack overflow in recursive parsing
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_STRING_NESTING_DEPTH: u32 = 100;
    }

    pub mod syntax {
        /// Maximum parser recursion depth to prevent stack overflow
        /// SECURITY: Prevents DoS attacks via deeply nested structures
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_PARSE_DEPTH: usize = 100;

        /// Maximum error history buffer size
        /// RESOURCE: Controls memory usage for error tracking
        pub const MAX_ERROR_HISTORY: usize = 50;

        /// Maximum context stack depth for error reporting
        /// RESOURCE: Prevents unbounded memory growth
        pub const MAX_CONTEXT_STACK_DEPTH: usize = 20;

        /// Maximum tokens to examine during error recovery
        /// PERFORMANCE: Limits recovery scanning overhead
        pub const MAX_RECOVERY_SCAN_TOKENS: usize = 1000;

        /// Token lookahead limit for parsing decisions
        /// PERFORMANCE: Controls lookahead memory usage
        pub const MAX_LOOKAHEAD_TOKENS: usize = 10;
    }

    pub mod symbols {
        /// Maximum number of global symbols per table
        /// SECURITY: Prevents DoS attacks via symbol table explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_GLOBAL_SYMBOLS: usize = 50_000;

        /// Maximum number of local symbols per CTN scope
        /// SECURITY: Prevents memory exhaustion in local scopes
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_LOCAL_SYMBOLS_PER_CTN: usize = 1_000;

        /// Maximum number of symbol relationships to track
        /// SECURITY: Prevents DoS via relationship explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_SYMBOL_RELATIONSHIPS: usize = 100_000;

        /// Maximum symbol identifier length
        /// SECURITY: Prevents memory attacks via huge identifiers
        /// SSDF: PW.7.1 (Input Validation)
        pub const MAX_SYMBOL_IDENTIFIER_LENGTH: usize = 255;

        /// Maximum context stack depth for symbol collection
        /// RESOURCE: Prevents unbounded stack growth
        pub const MAX_SYMBOL_CONTEXT_DEPTH: usize = 50;

        /// Maximum elements per symbol (states/objects)
        /// SECURITY: Prevents complexity attacks on large structures
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_ELEMENTS_PER_SYMBOL: usize = 10_000;

        /// Maximum CTN scopes allowed
        /// RESOURCE: Controls local table memory usage
        pub const MAX_CTN_SCOPES: usize = 1_000;
    }

    pub mod references {
        /// Maximum reference chain depth to prevent infinite loops
        /// SECURITY: Prevents DoS via circular reference attacks
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_REFERENCE_DEPTH: usize = 50;

        /// Maximum number of references per symbol
        /// SECURITY: Prevents memory exhaustion via reference explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_REFERENCES_PER_SYMBOL: usize = 10_000;

        /// Maximum cycles to report (prevent log spam)
        /// RESOURCE: Controls logging output volume
        pub const MAX_REPORTED_CYCLES: usize = 10;

        /// Maximum cycle length to analyze (prevent deep recursion)
        /// SECURITY: Prevents stack overflow in cycle detection
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_CYCLE_LENGTH: usize = 100;

        /// Maximum nodes in dependency graph
        /// SECURITY: Prevents DoS via graph complexity attacks
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_DEPENDENCY_NODES: usize = 100_000;

        /// Maximum relationships to process in a single validation pass
        /// SECURITY: Prevents memory exhaustion during batch validation
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_RELATIONSHIPS_PER_PASS: usize = 1_000_000;
    }

    pub mod semantic {
        /// Maximum number of semantic errors to collect before stopping analysis
        /// SECURITY: Prevents DoS via error accumulation attacks
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_SEMANTIC_ERRORS: usize = 1_000;

        /// Maximum parameter count for runtime operations
        /// SECURITY: Prevents DoS via parameter explosion attacks
        /// SSDF: PW.7.1 (Input Validation), PW.8.1 (DoS Protection)
        pub const MAX_RUNTIME_OPERATION_PARAMETERS: usize = 100;

        /// Maximum operand count for SET operations
        /// SECURITY: Prevents memory exhaustion via operand explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_SET_OPERATION_OPERANDS: usize = 1_000;

        /// Maximum length for error messages
        /// SECURITY: Prevents memory attacks via huge error descriptions
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_ERROR_MESSAGE_LENGTH: usize = 10_000;

        /// Maximum cycle path length to report
        /// SECURITY: Prevents DoS via deep cycle reporting
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_CYCLE_PATH_LENGTH: usize = 100;

        /// Maximum filter state references per SET operation
        /// SECURITY: Prevents memory exhaustion via reference explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_FILTER_STATE_REFERENCES: usize = 1_000;
    }

    pub mod structural {
        /// Maximum symbols per definition (structural analysis)
        /// SECURITY: Prevents DoS attacks via symbol explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_SYMBOLS_PER_DEFINITION: usize = 10_000;

        /// Maximum nesting depth for structural analysis
        /// SECURITY: Prevents stack overflow in recursive validation
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_NESTING_DEPTH: usize = 10;

        /// Maximum criteria blocks per definition
        /// SECURITY: Prevents DoS via criteria block explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_CRITERIA_BLOCKS: usize = 1_000;

        /// Maximum SET operands for structural validation
        /// SECURITY: Prevents memory exhaustion via operand explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_SET_OPERANDS: usize = 100;

        /// Maximum variables per definition (structural limit)
        /// SECURITY: Prevents DoS via variable explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_VARIABLES_PER_DEFINITION: usize = 1_000;

        /// Maximum states per definition (structural limit)
        /// SECURITY: Prevents memory exhaustion via state explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_STATES_PER_DEFINITION: usize = 500;

        /// Maximum objects per definition (structural limit)
        /// SECURITY: Prevents DoS via object explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_OBJECTS_PER_DEFINITION: usize = 200;
    }

    pub mod batch_processing {
        /// Maximum number of worker threads for file processing
        /// RESOURCE: Controls system resource consumption
        pub const MAX_WORKER_THREADS: usize = 8;

        /// Maximum files per batch to prevent memory exhaustion
        /// SECURITY: Prevents DoS via batch size explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_FILES_PER_BATCH: usize = 1000;

        /// Maximum total memory for batch processing (1GB)
        /// RESOURCE: Prevents system memory exhaustion
        pub const MAX_BATCH_MEMORY: u64 = 1_000_000_000;
    }

    pub mod security {
        /// Maximum memory usage before triggering alerts (500MB)
        /// SECURITY: Resource monitoring threshold
        /// SSDF: RV.1 (Monitoring)
        pub const MEMORY_ALERT_THRESHOLD: u64 = 500_000_000;

        /// Maximum processing time per file (seconds)
        /// SECURITY: Prevents DoS via processing time attacks
        pub const MAX_PROCESSING_TIME_SECONDS: u64 = 300; // 5 minutes

        /// Audit log buffer size for security events
        /// SECURITY: Ensures audit trail completeness
        /// SSDF: PW.3.1 (Audit Logging)
        pub const AUDIT_LOG_BUFFER_SIZE: usize = 10_000;

        /// Maximum concurrent file operations
        /// SECURITY: Prevents resource exhaustion
        pub const MAX_CONCURRENT_OPERATIONS: usize = 100;
    }

    pub mod logging {
        /// Maximum errors to collect before stopping
        /// RESOURCE: Prevents unbounded error accumulation
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_ERROR_COLLECTION: usize = 1_000;

        /// Log buffer size for batch operations
        /// RESOURCE: Controls memory usage for logging
        /// SSDF: PW.8.1 (DoS Protection)
        pub const LOG_BUFFER_SIZE: usize = 10_000;

        /// Maximum log message length
        /// RESOURCE: Prevents memory attacks via huge messages
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_LOG_MESSAGE_LENGTH: usize = 10_000;

        /// Maximum log events per file before truncation
        /// SECURITY: Prevents DoS via log event explosion
        /// SSDF: PW.8.1 (DoS Protection)
        pub const MAX_LOG_EVENTS_PER_FILE: usize = 1_000;

        /// Maximum concurrent log operations
        /// RESOURCE: Controls concurrent logging overhead
        pub const MAX_CONCURRENT_LOG_OPERATIONS: usize = 100;

        /// Minimum log level for security events (cannot be changed at runtime)
        /// SECURITY: Ensures security events are always logged
        /// SSDF: PW.3.1 (Audit Logging)
        pub const SECURITY_MIN_LOG_LEVEL: u8 = 1; // Warning level minimum

        /// Maximum audit log retention buffer size
        /// SECURITY: Ensures audit trail completeness
        /// SSDF: PW.3.1 (Audit Logging)
        pub const AUDIT_LOG_RETENTION_BUFFER: usize = 50_000;
    }
}
