//! Event system for ESP Parser logging

use super::codes::Code;
use crate::utils::Span;
use std::collections::HashMap;
use std::time::SystemTime;

/// Log severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warning => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
        }
    }
}

/// Core log event structure
#[derive(Debug, Clone)]
pub struct LogEvent {
    pub timestamp: SystemTime,
    pub level: LogLevel,
    pub code: Code,
    pub message: String,
    pub span: Option<Span>,
    pub context: HashMap<String, String>,
}

impl LogEvent {
    /// Create a new error event
    pub fn error(error_code: Code, message: &str) -> Self {
        Self {
            timestamp: SystemTime::now(),
            level: LogLevel::Error,
            code: error_code,
            message: message.to_string(),
            span: None,
            context: HashMap::new(),
        }
    }

    /// Create a new warning event (warnings may not have codes)
    pub fn warning(message: &str) -> Self {
        Self {
            timestamp: SystemTime::now(),
            level: LogLevel::Warning,
            code: Code::new("W000"), // Generic warning code
            message: message.to_string(),
            span: None,
            context: HashMap::new(),
        }
    }

    /// Create warning with specific code
    pub fn warning_with_code(warning_code: Code, message: &str) -> Self {
        Self {
            timestamp: SystemTime::now(),
            level: LogLevel::Warning,
            code: warning_code,
            message: message.to_string(),
            span: None,
            context: HashMap::new(),
        }
    }

    /// Create a new info event (info may not need codes)
    pub fn info(message: &str) -> Self {
        Self {
            timestamp: SystemTime::now(),
            level: LogLevel::Info,
            code: Code::new("I000"), // Generic info code
            message: message.to_string(),
            span: None,
            context: HashMap::new(),
        }
    }

    /// Create info with specific code
    pub fn info_with_code(info_code: Code, message: &str) -> Self {
        Self {
            timestamp: SystemTime::now(),
            level: LogLevel::Info,
            code: info_code,
            message: message.to_string(),
            span: None,
            context: HashMap::new(),
        }
    }

    /// Create a success event (info with success code)
    pub fn success(success_code: Code, message: &str) -> Self {
        Self {
            timestamp: SystemTime::now(),
            level: LogLevel::Info,
            code: success_code,
            message: message.to_string(),
            span: None,
            context: HashMap::new(),
        }
    }

    /// Create a debug event
    pub fn debug(message: &str) -> Self {
        Self {
            timestamp: SystemTime::now(),
            level: LogLevel::Debug,
            code: Code::new("D000"), // Generic debug code
            message: message.to_string(),
            span: None,
            context: HashMap::new(),
        }
    }

    /// Create debug with specific code
    pub fn debug_with_code(debug_code: Code, message: &str) -> Self {
        Self {
            timestamp: SystemTime::now(),
            level: LogLevel::Debug,
            code: debug_code,
            message: message.to_string(),
            span: None,
            context: HashMap::new(),
        }
    }

    /// Add span information
    pub fn with_span(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }

    /// Add context data
    pub fn with_context(mut self, key: &str, value: &str) -> Self {
        self.context.insert(key.to_string(), value.to_string());
        self
    }

    /// Add file path context
    pub fn with_file_path(self, path: &str) -> Self {
        self.with_context("file_path", path)
    }

    /// Check if this is an error event
    pub fn is_error(&self) -> bool {
        self.level == LogLevel::Error
    }

    /// Check if this is a warning event
    pub fn is_warning(&self) -> bool {
        self.level == LogLevel::Warning
    }

    /// Check if this is an info event
    pub fn is_info(&self) -> bool {
        self.level == LogLevel::Info
    }

    /// Check if this is a debug event
    pub fn is_debug(&self) -> bool {
        self.level == LogLevel::Debug
    }

    /// Check if this event requires halting
    pub fn requires_halt(&self) -> bool {
        super::codes::requires_halt(self.code.as_str())
    }

    /// Get severity from error code
    pub fn severity(&self) -> &'static str {
        super::codes::get_severity(self.code.as_str()).as_str()
    }

    /// Get error category
    pub fn category(&self) -> &'static str {
        super::codes::get_category(self.code.as_str())
    }

    /// Get error description
    pub fn description(&self) -> &'static str {
        super::codes::get_description(self.code.as_str())
    }

    /// Get recommended action
    pub fn recommended_action(&self) -> &'static str {
        super::codes::get_action(self.code.as_str())
    }

    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        super::codes::is_recoverable(self.code.as_str())
    }

    /// Format for display
    pub fn format(&self) -> String {
        let span_str = self
            .span
            .as_ref()
            .map(|s| format!(" at {}:{}", s.start().line, s.start().column))
            .unwrap_or_default();

        format!(
            "[{}] {} - {}{}",
            self.level.as_str(),
            self.code.as_str(),
            self.message,
            span_str
        )
    }

    /// Format with detailed error information
    pub fn format_detailed(&self) -> String {
        let mut output = self.format();

        // Add severity and category information
        output.push_str(&format!("\n  Category: {}", self.category()));
        output.push_str(&format!("\n  Severity: {}", self.severity()));

        if self.is_error() {
            output.push_str(&format!("\n  Recoverable: {}", self.is_recoverable()));
            output.push_str(&format!("\n  Requires halt: {}", self.requires_halt()));
        }

        // Add description and recommended action
        let description = self.description();
        if description != "Unknown error" {
            output.push_str(&format!("\n  Description: {}", description));
        }

        let action = self.recommended_action();
        if action != "No specific action available" {
            output.push_str(&format!("\n  Recommended action: {}", action));
        }

        // Add context if present
        if !self.context.is_empty() {
            output.push_str("\n  Context:");
            for (key, value) in &self.context {
                output.push_str(&format!("\n    {}: {}", key, value));
            }
        }

        output
    }

    /// Format as JSON for structured logging
    pub fn format_json(&self) -> Result<String, serde_json::Error> {
        let timestamp = self
            .timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut json = serde_json::json!({
            "timestamp": timestamp,
            "level": self.level.as_str(),
            "code": self.code.as_str(),
            "message": self.message,
            "category": self.category(),
            "severity": self.severity(),
        });

        // Add error-specific metadata
        if self.is_error() {
            json["error_metadata"] = serde_json::json!({
                "recoverable": self.is_recoverable(),
                "requires_halt": self.requires_halt(),
                "description": self.description(),
                "recommended_action": self.recommended_action(),
            });
        }

        // Add span information
        if let Some(span) = &self.span {
            json["span"] = serde_json::json!({
                "start_line": span.start().line,
                "start_column": span.start().column,
                "end_line": span.end().line,
                "end_column": span.end().column,
            });
        }

        // Add context
        if !self.context.is_empty() {
            json["context"] = serde_json::Value::Object(
                self.context
                    .iter()
                    .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                    .collect(),
            );
        }

        serde_json::to_string(&json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::codes;

    #[test]
    fn test_error_event_creation() {
        let event = LogEvent::error(codes::file_processing::FILE_NOT_FOUND, "File not found");

        assert!(event.is_error());
        assert_eq!(event.code.as_str(), "E005");
        assert_eq!(event.message, "File not found");
        assert_eq!(event.category(), "FileProcessing");
    }

    #[test]
    fn test_success_event_creation() {
        let event = LogEvent::success(codes::success::FILE_PROCESSING_SUCCESS, "File processed");

        assert!(event.is_info());
        assert_eq!(event.code.as_str(), "I006");
        assert_eq!(event.message, "File processed");
    }

    #[test]
    fn test_event_with_context() {
        let event = LogEvent::error(codes::file_processing::FILE_TOO_LARGE, "File too large")
            .with_context("size", "1024")
            .with_context("limit", "512");

        assert_eq!(event.context.get("size"), Some(&"1024".to_string()));
        assert_eq!(event.context.get("limit"), Some(&"512".to_string()));
    }

    #[test]
    fn test_event_formatting() {
        let event = LogEvent::error(codes::lexical::INVALID_CHARACTER, "Invalid character");
        let formatted = event.format();

        assert!(formatted.contains("[ERROR]"));
        assert!(formatted.contains("E020"));
        assert!(formatted.contains("Invalid character"));
    }

    #[test]
    fn test_event_metadata() {
        let event = LogEvent::error(codes::system::INTERNAL_ERROR, "System failure");

        assert_eq!(event.severity(), "Critical");
        assert_eq!(event.category(), "System");
        assert!(!event.is_recoverable());
        assert!(event.requires_halt());
    }

    #[test]
    fn test_warning_events() {
        let generic_warning = LogEvent::warning("Generic warning");
        assert!(generic_warning.is_warning());
        assert_eq!(generic_warning.code.as_str(), "W000");

        let specific_warning =
            LogEvent::warning_with_code(codes::lexical::RESERVED_KEYWORD, "Reserved keyword used");
        assert!(specific_warning.is_warning());
        assert_eq!(specific_warning.code.as_str(), "E025");
    }

    #[test]
    fn test_json_formatting() {
        let event = LogEvent::error(codes::file_processing::PERMISSION_DENIED, "Access denied")
            .with_context("file", "test.esp");

        let json_result = event.format_json();
        assert!(json_result.is_ok());

        let json = json_result.unwrap();
        assert!(json.contains("\"level\":\"ERROR\""));
        assert!(json.contains("\"code\":\"E009\""));
        assert!(json.contains("\"message\":\"Access denied\""));
    }
}
