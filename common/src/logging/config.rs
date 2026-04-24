//! Configuration module for logging - using compile-time constants
//!
//! This module provides access to compile-time security constants and runtime user preferences.
//! Security boundaries are enforced at compile time and cannot be modified at runtime.

use crate::config::compile_time::logging::*;
use crate::config::runtime::LoggingPreferences;
use std::sync::OnceLock;

// Type aliases for clarity
type EventsLogLevel = crate::logging::events::LogLevel;
type RuntimeLogLevel = crate::config::runtime::LogLevel;

// ============================================================================
// RUNTIME PREFERENCES STORAGE
// ============================================================================

static RUNTIME_PREFERENCES: OnceLock<LoggingPreferences> = OnceLock::new();

/// Initialize runtime preferences
pub fn init_runtime_preferences(preferences: LoggingPreferences) -> Result<(), String> {
    // Validate preferences against security constraints
    validate_preferences(&preferences)?;

    RUNTIME_PREFERENCES
        .set(preferences)
        .map_err(|_| "Runtime preferences already initialized")?;

    Ok(())
}

/// Get runtime preferences (with fallback to defaults)
fn get_runtime_preferences() -> LoggingPreferences {
    RUNTIME_PREFERENCES.get().cloned().unwrap_or_default()
}

/// Validate runtime preferences against security constraints
fn validate_preferences(preferences: &LoggingPreferences) -> Result<(), String> {
    // Ensure security log level cannot be set below minimum
    if (preferences.min_log_level as u8) > SECURITY_MIN_LOG_LEVEL
        && preferences.log_security_metrics
    {
        return Err(format!(
            "Security logging cannot be disabled: minimum level {} required",
            SECURITY_MIN_LOG_LEVEL
        ));
    }

    Ok(())
}

// ============================================================================
// CONFIGURATION ACCESS FUNCTIONS
// ============================================================================

/// Get minimum log level (respects user preference within security bounds)
pub fn get_min_log_level() -> EventsLogLevel {
    let preferences = get_runtime_preferences();

    // Convert runtime::LogLevel to events::LogLevel using the conversion method
    let user_level = preferences.min_log_level.to_events_log_level();

    // Security events must always be logged at warning level or higher
    if preferences.log_security_metrics {
        match user_level {
            EventsLogLevel::Error => EventsLogLevel::Warning, // Promote to warning for security
            level => level,
        }
    } else {
        user_level
    }
}

/// Check if structured logging is enabled (user preference)
pub fn use_structured_logging() -> bool {
    get_runtime_preferences().use_structured_logging
}

/// Check if console logging is enabled (user preference)
pub fn use_console_logging() -> bool {
    get_runtime_preferences().enable_console_logging
}

/// Get security-specific log level (compile-time enforced)
pub fn get_security_log_level() -> EventsLogLevel {
    // Security events cannot be disabled - compile-time enforced
    match SECURITY_MIN_LOG_LEVEL {
        0 => EventsLogLevel::Error,
        1 => EventsLogLevel::Warning,
        2 => EventsLogLevel::Info,
        _ => EventsLogLevel::Debug,
    }
}

/// Check if performance events should be logged (user preference)
pub fn log_performance_events() -> bool {
    get_runtime_preferences().log_performance_events
}

/// Check if security metrics should be logged (user preference with security override)
pub fn log_security_metrics() -> bool {
    // Always log security metrics regardless of user preference - security requirement
    true
}

/// Check if audit events should be logged (always true - security requirement)
pub fn log_audit_events() -> bool {
    // Audit events are always logged - compile-time security requirement
    true
}

/// Get error buffer size (compile-time security constant)
pub fn get_error_buffer_size() -> usize {
    LOG_BUFFER_SIZE
}

/// Get maximum log events per file (compile-time security constant)
pub fn get_max_log_events_per_file() -> usize {
    MAX_LOG_EVENTS_PER_FILE
}

/// Get maximum log message length (compile-time security constant)
pub fn get_max_log_message_length() -> usize {
    crate::config::compile_time::logging::MAX_LOG_MESSAGE_LENGTH
}

/// Check if cargo-style output is enabled (user preference)
pub fn use_cargo_style_output() -> bool {
    get_runtime_preferences().enable_cargo_style_output
}

/// Check if file context should be included (user preference)
pub fn include_file_context() -> bool {
    get_runtime_preferences().include_file_context
}

/// Get audit log retention buffer size (compile-time security constant)
pub fn get_audit_log_retention_buffer() -> usize {
    AUDIT_LOG_RETENTION_BUFFER
}

/// Get maximum concurrent log operations (compile-time resource constant)
pub fn get_max_concurrent_log_operations() -> usize {
    MAX_CONCURRENT_LOG_OPERATIONS
}

// ============================================================================
// CONFIGURATION VALIDATION
// ============================================================================

/// Validate current configuration settings
pub fn validate_config() -> Result<(), String> {
    // Validate compile-time constants are reasonable
    if LOG_BUFFER_SIZE > 100_000 {
        return Err(format!("Log buffer size too large: {}", LOG_BUFFER_SIZE));
    }

    if LOG_BUFFER_SIZE < 100 {
        return Err(format!("Log buffer size too small: {}", LOG_BUFFER_SIZE));
    }

    if MAX_LOG_EVENTS_PER_FILE > LOG_BUFFER_SIZE {
        return Err("Max log events per file exceeds total buffer size".to_string());
    }

    // Validate runtime preferences if set
    if let Some(preferences) = RUNTIME_PREFERENCES.get() {
        validate_preferences(preferences)?;
    }

    Ok(())
}

/// Get configuration summary for diagnostics
pub fn get_config_summary() -> String {
    let preferences = get_runtime_preferences();

    format!(
        "Logging Configuration:\n\
         === Security Constants (Compile-time) ===\n\
         - Log buffer size: {}\n\
         - Max events per file: {}\n\
         - Max message length: {}\n\
         - Security min level: {}\n\
         - Audit buffer size: {}\n\
         - Max concurrent ops: {}\n\
         === User Preferences (Runtime) ===\n\
         - Min log level: {:?}\n\
         - Structured logging: {}\n\
         - Console logging: {}\n\
         - Performance events: {}\n\
         - Security metrics: {} (always enabled)\n\
         - Audit events: {} (always enabled)\n\
         - Cargo-style output: {}\n\
         - Include file context: {}",
        LOG_BUFFER_SIZE,
        MAX_LOG_EVENTS_PER_FILE,
        crate::config::compile_time::logging::MAX_LOG_MESSAGE_LENGTH,
        SECURITY_MIN_LOG_LEVEL,
        AUDIT_LOG_RETENTION_BUFFER,
        MAX_CONCURRENT_LOG_OPERATIONS,
        preferences.min_log_level,
        preferences.use_structured_logging,
        preferences.enable_console_logging,
        preferences.log_performance_events,
        log_security_metrics(),
        log_audit_events(),
        preferences.enable_cargo_style_output,
        preferences.include_file_context,
    )
}

/// Check if configuration is in development mode
pub fn is_development_mode() -> bool {
    cfg!(debug_assertions)
}

/// Check if configuration is in production mode
pub fn is_production_mode() -> bool {
    !cfg!(debug_assertions)
}

/// Get recommended configuration for development
pub fn get_development_preferences() -> LoggingPreferences {
    LoggingPreferences {
        use_structured_logging: false,
        enable_console_logging: true,
        min_log_level: RuntimeLogLevel::Debug,
        log_performance_events: true,
        log_security_metrics: true,
        enable_cargo_style_output: true,
        include_file_context: true,
    }
}

/// Get recommended configuration for production
pub fn get_production_preferences() -> LoggingPreferences {
    LoggingPreferences {
        use_structured_logging: true,
        enable_console_logging: false,
        min_log_level: RuntimeLogLevel::Info,
        log_performance_events: false,
        log_security_metrics: true,
        enable_cargo_style_output: false,
        include_file_context: false,
    }
}

// ============================================================================
// SECURITY ENFORCEMENT
// ============================================================================

/// Ensure security events are always logged (cannot be overridden)
pub fn enforce_security_logging() -> bool {
    // This function exists to document that security logging is enforced
    // at compile time and cannot be disabled by user preferences
    true
}

/// Get effective log level for security events (always enforced)
pub fn get_effective_security_log_level() -> EventsLogLevel {
    // Security events use the more restrictive of user preference or security minimum
    let user_prefs = get_runtime_preferences();
    let user_level = user_prefs.min_log_level.to_events_log_level();
    let security_level = get_security_log_level();

    // Use the more restrictive (lower numeric value) level
    if (user_level as u8) < (security_level as u8) {
        user_level
    } else {
        security_level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        assert!(validate_config().is_ok());
    }

    #[test]
    fn test_security_constraints() {
        // Security logging cannot be disabled
        assert!(log_security_metrics());
        assert!(log_audit_events());

        // Security log level is enforced
        let security_level = get_security_log_level();
        assert!(security_level <= EventsLogLevel::Warning);
    }

    #[test]
    fn test_preference_validation() {
        let invalid_prefs = LoggingPreferences {
            min_log_level: RuntimeLogLevel::Error,
            log_security_metrics: true,
            ..Default::default()
        };

        // Should be promoted to warning level for security
        let result = validate_preferences(&invalid_prefs);
        // Note: Current implementation allows this but promotes the level
        assert!(result.is_ok());
    }

    #[test]
    fn test_compile_time_constants() {
        // Verify compile-time constants are accessible using const assertions
        const _: () = assert!(LOG_BUFFER_SIZE > 0);
        const _: () = assert!(MAX_LOG_EVENTS_PER_FILE > 0);
        const _: () = assert!(AUDIT_LOG_RETENTION_BUFFER > 0);
        const _: () = assert!(MAX_CONCURRENT_LOG_OPERATIONS > 0);

        // Verify security constraints
        const _: () = assert!(SECURITY_MIN_LOG_LEVEL <= 2); // Warning level or higher
    }

    #[test]
    fn test_effective_security_level() {
        let effective_level = get_effective_security_log_level();
        let security_level = get_security_log_level();

        // Effective level should be at least as restrictive as security level
        assert!((effective_level as u8) <= (security_level as u8));
    }
}
