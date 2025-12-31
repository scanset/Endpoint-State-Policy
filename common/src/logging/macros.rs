//! Type-safe logging macros using Code types with Display support

// ============================================================================
// ERROR LOGGING MACROS - UPDATED FOR DISPLAY TYPES
// ============================================================================

/// Log error with Code type - accepts Display types for context values
#[macro_export]
macro_rules! log_error {
    ($code:expr, $message:expr) => {
        $crate::logging::log_error_with_context($code, $message, None, vec![])
    };

    ($code:expr, $message:expr, span = $span:expr) => {
        $crate::logging::log_error_with_context($code, $message, Some($span), vec![])
    };

    ($code:expr, $message:expr, $($key:expr => $value:expr),+) => {
        {
            // Convert Display types to strings, then create string storage and references
            let context_strings: Vec<(&str, String)> = vec![$(($key, format!("{}", $value))),+];
            let context_refs: Vec<(&str, &str)> = context_strings.iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            $crate::logging::log_error_with_context($code, $message, None, context_refs)
        }
    };

    ($code:expr, $message:expr, span = $span:expr, $($key:expr => $value:expr),+) => {
        {
            // Convert Display types to strings, then create string storage and references
            let context_strings: Vec<(&str, String)> = vec![$(($key, format!("{}", $value))),+];
            let context_refs: Vec<(&str, &str)> = context_strings.iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            $crate::logging::log_error_with_context($code, $message, Some($span), context_refs)
        }
    };
}

// ============================================================================
// SUCCESS LOGGING MACROS - UPDATED FOR DISPLAY TYPES
// ============================================================================

/// Log success with Code type - accepts Display types for context values
#[macro_export]
macro_rules! log_success {
    ($code:expr, $message:expr) => {
        $crate::logging::log_success_with_context($code, $message, vec![])
    };

    ($code:expr, $message:expr, $($key:expr => $value:expr),+) => {
        {
            // Convert Display types to strings, then create string storage and references
            let context_strings: Vec<(&str, String)> = vec![$(($key, format!("{}", $value))),+];
            let context_refs: Vec<(&str, &str)> = context_strings.iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            $crate::logging::log_success_with_context($code, $message, context_refs)
        }
    };
}

// ============================================================================
// INFO LOGGING MACROS - UPDATED FOR DISPLAY TYPES
// ============================================================================

/// Log informational message - accepts Display types for context values
#[macro_export]
macro_rules! log_info {
    ($message:expr) => {
        $crate::logging::log_info_with_context($message, vec![])
    };

    ($message:expr, $($key:expr => $value:expr),+) => {
        {
            // Convert Display types to strings, then create string storage and references
            let context_strings: Vec<(&str, String)> = vec![$(($key, format!("{}", $value))),+];
            let context_refs: Vec<(&str, &str)> = context_strings.iter()
                .map(|(k, v)| (*k, v.as_str()))
                .collect();
            $crate::logging::log_info_with_context($message, context_refs)
        }
    };
}

// ============================================================================
// WARNING LOGGING MACROS - UPDATED FOR DISPLAY TYPES
// ============================================================================

/// Log warning message - accepts Display types for context values
#[macro_export]
macro_rules! log_warning {
    ($message:expr) => {
        {
            let event = $crate::logging::LogEvent::warning($message);
            let event = if let Some(file_ctx) = $crate::logging::get_current_file_context() {
                event.with_context("file", &file_ctx.file_path.display().to_string())
            } else {
                event
            };
            if let Some(logger) = $crate::logging::try_get_global_logger() {
                logger.log_event(event);
            }
        }
    };

    ($message:expr, $($key:expr => $value:expr),+) => {
        {
            let mut event = $crate::logging::LogEvent::warning($message);
            $(
                // Convert Display types to strings automatically
                event = event.with_context($key, &format!("{}", $value));
            )+
            let event = if let Some(file_ctx) = $crate::logging::get_current_file_context() {
                event.with_context("file", &file_ctx.file_path.display().to_string())
            } else {
                event
            };
            if let Some(logger) = $crate::logging::try_get_global_logger() {
                logger.log_event(event);
            }
        }
    };
}

// ============================================================================
// DEBUG LOGGING MACROS - UPDATED FOR DISPLAY TYPES
// ============================================================================

/// Log debug message - accepts Display types for context values
#[macro_export]
macro_rules! log_debug {
    ($message:expr) => {
        {
            if $crate::logging::config::get_min_log_level() >= $crate::logging::LogLevel::Debug {
                let event = $crate::logging::LogEvent::debug($message);
                let event = if let Some(file_ctx) = $crate::logging::get_current_file_context() {
                    event.with_context("file", &file_ctx.file_path.display().to_string())
                } else {
                    event
                };
                if let Some(logger) = $crate::logging::try_get_global_logger() {
                    logger.log_event(event);
                }
            }
        }
    };

    ($message:expr, $($key:expr => $value:expr),+) => {
        {
            if $crate::logging::config::get_min_log_level() >= $crate::logging::LogLevel::Debug {
                let mut event = $crate::logging::LogEvent::debug($message);
                $(
                    // Convert Display types to strings automatically
                    event = event.with_context($key, &format!("{}", $value));
                )+
                let event = if let Some(file_ctx) = $crate::logging::get_current_file_context() {
                    event.with_context("file", &file_ctx.file_path.display().to_string())
                } else {
                    event
                };
                if let Some(logger) = $crate::logging::try_get_global_logger() {
                    logger.log_event(event);
                }
            }
        }
    };
}

// ============================================================================
// CONDITIONAL COMPILATION SUPPORT
// ============================================================================

/// Log only in debug builds
#[macro_export]
macro_rules! debug_log {
    ($($arg:tt)*) => {
        #[cfg(debug_assertions)]
        {
            log_debug!($($arg)*);
        }
    };
}

/// Log only in release builds
#[macro_export]
macro_rules! release_log {
    ($($arg:tt)*) => {
        #[cfg(not(debug_assertions))]
        {
            log_info!($($arg)*);
        }
    };
}

// ============================================================================
// ERROR CLASSIFICATION HELPERS - UPDATED FOR DISPLAY TYPES
// ============================================================================

/// Log error with automatic severity classification - accepts Display types
#[macro_export]
macro_rules! log_classified_error {
    ($code:expr, $message:expr) => {{
        let severity = $crate::logging::codes::get_severity($code.as_str());
        let requires_halt = $crate::logging::codes::requires_halt($code.as_str());
        let recoverable = $crate::logging::codes::is_recoverable($code.as_str());

        let context_strings: Vec<(&str, String)> = vec![
            ("severity", format!("{}", severity.as_str())),
            ("requires_halt", format!("{}", requires_halt)),
            ("recoverable", format!("{}", recoverable)),
        ];
        let context_refs: Vec<(&str, &str)> = context_strings
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();
        $crate::logging::log_error_with_context($code, $message, None, context_refs);
    }};

    ($code:expr, $message:expr, span = $span:expr) => {{
        let severity = $crate::logging::codes::get_severity($code.as_str());
        let requires_halt = $crate::logging::codes::requires_halt($code.as_str());
        let recoverable = $crate::logging::codes::is_recoverable($code.as_str());

        let context_strings: Vec<(&str, String)> = vec![
            ("severity", format!("{}", severity.as_str())),
            ("requires_halt", format!("{}", requires_halt)),
            ("recoverable", format!("{}", recoverable)),
        ];
        let context_refs: Vec<(&str, &str)> = context_strings
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect();
        $crate::logging::log_error_with_context($code, $message, Some($span), context_refs);
    }};
}

// ============================================================================
// CONVENIENCE MACROS FOR COMMON PATTERNS
// ============================================================================

/// Log performance metrics with standard format
#[macro_export]
macro_rules! log_performance {
    ($code:expr, $message:expr, duration = $duration:expr) => {
        log_success!($code, $message,
            "duration_ms" => $duration.as_secs_f64() * 1000.0
        );
    };

    ($code:expr, $message:expr, duration = $duration:expr, $($key:expr => $value:expr),+) => {
        log_success!($code, $message,
            "duration_ms" => $duration.as_secs_f64() * 1000.0,
            $($key => $value),+
        );
    };
}

/// Log file processing metrics with standard format
#[macro_export]
macro_rules! log_file_metrics {
    ($code:expr, $message:expr, file = $file:expr, size = $size:expr, lines = $lines:expr) => {
        log_success!($code, $message,
            "file" => $file,
            "size_bytes" => $size,
            "lines" => $lines
        );
    };

    ($code:expr, $message:expr, file = $file:expr, size = $size:expr, lines = $lines:expr, $($key:expr => $value:expr),+) => {
        log_success!($code, $message,
            "file" => $file,
            "size_bytes" => $size,
            "lines" => $lines,
            $($key => $value),+
        );
    };
}

#[cfg(test)]
mod tests {
    use crate::logging::codes;

    #[allow(dead_code)]
    fn example_usage() {
        // Now you can use Display types directly
        let file_size: u64 = 1024;
        let line_count: usize = 42;
        let duration: std::time::Duration = std::time::Duration::from_millis(150);

        // Error with numeric and string Display values
        log_error!(codes::lexical::INVALID_CHARACTER, "Invalid character",
            "position" => line_count,
            "file_size" => file_size,
            "char" => '€'
        );

        // Success with mixed Display types
        log_success!(codes::success::TOKENIZATION_COMPLETE, "Tokenization completed",
            "tokens" => 157,
            "duration_ms" => duration.as_secs_f64() * 1000.0,
            "file_size" => file_size
        );

        // Info with boolean and numeric values
        log_info!("Processing file",
            "is_large" => file_size > 1000,
            "lines" => line_count,
            "estimated_time" => duration.as_secs()
        );

        // Warning with path Display
        let path = std::path::PathBuf::from("/path/to/file.esp");
        log_warning!("File may be corrupted",
            "path" => path.display(),
            "size" => file_size
        );

        // Performance logging convenience macro
        log_performance!(codes::success::FILE_PROCESSING_SUCCESS,
            "File processed successfully",
            duration = duration,
            "file_size" => file_size,
            "lines" => line_count
        );

        // File metrics convenience macro
        log_file_metrics!(codes::success::FILE_PROCESSING_SUCCESS,
            "File processing complete",
            file = "test.esp",
            size = file_size,
            lines = line_count,
            "chars" => 2048,
            "encoding" => "UTF-8"
        );

        // Classification helpers
        log_classified_error!(codes::system::INTERNAL_ERROR, "Critical system failure");
    }
}
