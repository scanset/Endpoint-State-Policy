//! Error collector for batch file processing with cargo-style output
//!
//! Provides organized error collection and reporting for parallel file processing

use super::events::LogEvent;
use crate::config::compile_time::logging::*;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ============================================================================
// FILE PROCESSING CONTEXT
// ============================================================================

/// Context information for file processing
#[derive(Debug, Clone)]
pub struct FileProcessingContext {
    pub file_path: PathBuf,
    pub file_id: usize,
    pub start_time: Instant,
}

impl FileProcessingContext {
    pub fn new(file_path: PathBuf, file_id: usize) -> Self {
        Self {
            file_path,
            file_id,
            start_time: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}

// ============================================================================
// PROCESSING SUMMARY
// ============================================================================

/// Summary of batch processing results
#[derive(Debug, Clone)]
pub struct ProcessingSummary {
    pub total_files: usize,
    pub successful_files: usize,
    pub failed_files: usize,
    pub files_with_warnings: usize,
    pub total_errors: usize,
    pub total_warnings: usize,
    pub total_processing_time: Duration,
    pub average_file_time: Duration,
}

impl ProcessingSummary {
    pub fn new() -> Self {
        Self {
            total_files: 0,
            successful_files: 0,
            failed_files: 0,
            files_with_warnings: 0,
            total_errors: 0,
            total_warnings: 0,
            total_processing_time: Duration::new(0, 0),
            average_file_time: Duration::new(0, 0),
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_files == 0 {
            0.0
        } else {
            self.successful_files as f64 / self.total_files as f64
        }
    }

    pub fn has_errors(&self) -> bool {
        self.total_errors > 0
    }

    pub fn has_warnings(&self) -> bool {
        self.total_warnings > 0
    }
}

impl Default for ProcessingSummary {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ERROR COLLECTOR
// ============================================================================

/// Thread-safe error collector for batch processing
pub struct ErrorCollector {
    /// Events organized by file path for cargo-style output
    file_events: Mutex<BTreeMap<PathBuf, Vec<LogEvent>>>,

    /// Processing contexts for timing information
    file_contexts: Mutex<BTreeMap<PathBuf, FileProcessingContext>>,

    /// Global processing start time
    processing_start: Instant,
}

impl ErrorCollector {
    pub fn new() -> Self {
        Self {
            file_events: Mutex::new(BTreeMap::new()),
            file_contexts: Mutex::new(BTreeMap::new()),
            processing_start: Instant::now(),
        }
    }

    /// Record an event for a specific file
    pub fn record_event(&self, file_path: &Path, event: LogEvent) {
        let Ok(mut events) = self.file_events.lock() else {
            // Lock poisoned - log to stderr and continue
            eprintln!("Warning: Failed to acquire lock in record_event");
            return;
        };

        // Use compile-time constant for per-file event limits
        let max_events_per_file = MAX_LOG_EVENTS_PER_FILE;

        let file_events = events.entry(file_path.to_path_buf()).or_default();

        if file_events.len() < max_events_per_file {
            file_events.push(event);
        } else {
            // If we're at the limit, replace the last event with a summary
            if file_events.len() == max_events_per_file {
                let summary_event = LogEvent::warning(&format!(
                    "Too many events for file (limit: {})",
                    max_events_per_file
                ));
                file_events.push(summary_event);
            }
        }
    }

    /// Record file processing context
    pub fn record_file_context(&self, context: FileProcessingContext) {
        let Ok(mut contexts) = self.file_contexts.lock() else {
            eprintln!("Warning: Failed to acquire lock in record_file_context");
            return;
        };
        contexts.insert(context.file_path.clone(), context);
    }

    /// Get all events for a specific file
    pub fn get_file_events(&self, file_path: &Path) -> Vec<LogEvent> {
        let Ok(events) = self.file_events.lock() else {
            return Vec::new();
        };
        events.get(file_path).cloned().unwrap_or_default()
    }

    /// Get errors for a specific file
    pub fn get_file_errors(&self, file_path: &Path) -> Vec<LogEvent> {
        let Ok(events) = self.file_events.lock() else {
            return Vec::new();
        };
        events
            .get(file_path)
            .map(|events| events.iter().filter(|e| e.is_error()).cloned().collect())
            .unwrap_or_default()
    }

    /// Get warnings for a specific file
    pub fn get_file_warnings(&self, file_path: &Path) -> Vec<LogEvent> {
        let Ok(events) = self.file_events.lock() else {
            return Vec::new();
        };
        events
            .get(file_path)
            .map(|events| events.iter().filter(|e| e.is_warning()).cloned().collect())
            .unwrap_or_default()
    }

    /// Get all file events (for cargo-style output)
    pub fn get_all_file_events(&self) -> BTreeMap<PathBuf, Vec<LogEvent>> {
        let Ok(events) = self.file_events.lock() else {
            return BTreeMap::new();
        };
        events.clone()
    }

    /// Get processing summary
    pub fn get_summary(&self) -> ProcessingSummary {
        let Ok(events) = self.file_events.lock() else {
            return ProcessingSummary::default();
        };
        let Ok(contexts) = self.file_contexts.lock() else {
            return ProcessingSummary::default();
        };

        let mut summary = ProcessingSummary::new();
        summary.total_files = events.len();
        summary.total_processing_time = self.processing_start.elapsed();

        let mut total_file_time = Duration::new(0, 0);
        let mut file_count_with_timing = 0;

        for (file_path, file_events) in events.iter() {
            let has_errors = file_events.iter().any(|e| e.is_error());
            let has_warnings = file_events.iter().any(|e| e.is_warning());

            if has_errors {
                summary.failed_files += 1;
            } else if has_warnings {
                summary.files_with_warnings += 1;
            } else {
                summary.successful_files += 1;
            }

            // Count errors and warnings
            for event in file_events {
                if event.is_error() {
                    summary.total_errors += 1;
                } else if event.is_warning() {
                    summary.total_warnings += 1;
                }
            }

            // Add timing information if available
            if let Some(context) = contexts.get(file_path) {
                total_file_time += context.elapsed();
                file_count_with_timing += 1;
            }
        }

        // Calculate average file processing time
        if file_count_with_timing > 0 {
            summary.average_file_time = total_file_time / file_count_with_timing as u32;
        }

        summary
    }

    /// Get error count for a specific file
    pub fn get_file_error_count(&self, file_path: &Path) -> usize {
        let Ok(events) = self.file_events.lock() else {
            return 0;
        };
        events
            .get(file_path)
            .map(|events| events.iter().filter(|e| e.is_error()).count())
            .unwrap_or(0)
    }

    /// Get warning count for a specific file
    pub fn get_file_warning_count(&self, file_path: &Path) -> usize {
        let Ok(events) = self.file_events.lock() else {
            return 0;
        };
        events
            .get(file_path)
            .map(|events| events.iter().filter(|e| e.is_warning()).count())
            .unwrap_or(0)
    }

    /// Check if a file has any errors
    pub fn file_has_errors(&self, file_path: &Path) -> bool {
        self.get_file_error_count(file_path) > 0
    }

    /// Check if a file has any warnings
    pub fn file_has_warnings(&self, file_path: &Path) -> bool {
        self.get_file_warning_count(file_path) > 0
    }

    /// Get files with errors
    pub fn get_files_with_errors(&self) -> Vec<PathBuf> {
        let Ok(events) = self.file_events.lock() else {
            return Vec::new();
        };
        events
            .iter()
            .filter(|(_, events)| events.iter().any(|e| e.is_error()))
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Get files with warnings (but no errors)
    pub fn get_files_with_warnings(&self) -> Vec<PathBuf> {
        let Ok(events) = self.file_events.lock() else {
            return Vec::new();
        };
        events
            .iter()
            .filter(|(_, events)| {
                let has_warnings = events.iter().any(|e| e.is_warning());
                let has_errors = events.iter().any(|e| e.is_error());
                has_warnings && !has_errors
            })
            .map(|(path, _)| path.clone())
            .collect()
    }

    /// Get successful files (no errors or warnings)
    pub fn get_successful_files(&self) -> Vec<PathBuf> {
        let Ok(events) = self.file_events.lock() else {
            return Vec::new();
        };
        let all_files: std::collections::HashSet<PathBuf> = events.keys().cloned().collect();
        let files_with_issues: std::collections::HashSet<PathBuf> = events
            .iter()
            .filter(|(_, events)| events.iter().any(|e| e.is_error() || e.is_warning()))
            .map(|(path, _)| path.clone())
            .collect();

        all_files.difference(&files_with_issues).cloned().collect()
    }

    /// Get critical errors (errors that require halting)
    pub fn get_critical_errors(&self) -> Vec<(PathBuf, LogEvent)> {
        let Ok(events) = self.file_events.lock() else {
            return Vec::new();
        };
        let mut critical_errors = Vec::new();

        for (path, file_events) in events.iter() {
            for event in file_events {
                if event.is_error() && event.requires_halt() {
                    critical_errors.push((path.clone(), event.clone()));
                }
            }
        }

        critical_errors
    }

    /// Get events by severity
    pub fn get_events_by_severity(&self, min_severity: &str) -> Vec<(PathBuf, LogEvent)> {
        let Ok(events) = self.file_events.lock() else {
            return Vec::new();
        };
        let mut filtered_events = Vec::new();

        for (path, file_events) in events.iter() {
            for event in file_events {
                let event_severity = event.severity();
                // Compare severity levels (Critical=0, High=1, Medium=2, Low=3)
                let should_include = matches!(
                    (min_severity, event_severity),
                    ("Critical", "Critical")
                        | ("High", "Critical" | "High")
                        | ("Medium", "Critical" | "High" | "Medium")
                        | ("Low", _)
                );

                if should_include {
                    filtered_events.push((path.clone(), event.clone()));
                }
            }
        }

        filtered_events
    }

    /// Clear all collected data
    pub fn clear(&self) {
        if let Ok(mut events) = self.file_events.lock() {
            events.clear();
        }
        if let Ok(mut contexts) = self.file_contexts.lock() {
            contexts.clear();
        }
    }

    /// Get total event count across all files
    pub fn total_event_count(&self) -> usize {
        let Ok(events) = self.file_events.lock() else {
            return 0;
        };
        events.values().map(|v| v.len()).sum()
    }

    /// Check if collector is near capacity (using compile-time constants)
    pub fn is_near_capacity(&self) -> bool {
        let total_events = self.total_event_count();
        let max_events = LOG_BUFFER_SIZE;
        total_events > (max_events * 80 / 100) // 80% threshold
    }

    /// Get capacity information (using compile-time constants)
    pub fn get_capacity_info(&self) -> (usize, usize, f64) {
        let current = self.total_event_count();
        let max = LOG_BUFFER_SIZE;
        let percentage = if max > 0 {
            current as f64 / max as f64
        } else {
            0.0
        };
        (current, max, percentage)
    }

    /// Check if we're approaching per-file limits
    pub fn check_file_event_limits(&self, file_path: &Path) -> bool {
        let Ok(events) = self.file_events.lock() else {
            return false;
        };
        if let Some(file_events) = events.get(file_path) {
            file_events.len() >= (MAX_LOG_EVENTS_PER_FILE * 90 / 100) // 90% threshold
        } else {
            false
        }
    }

    /// Get per-file capacity information
    pub fn get_file_capacity_info(&self, file_path: &Path) -> (usize, usize, f64) {
        let Ok(events) = self.file_events.lock() else {
            return (0, MAX_LOG_EVENTS_PER_FILE, 0.0);
        };
        let current = events
            .get(file_path)
            .map(|events| events.len())
            .unwrap_or(0);
        let max = MAX_LOG_EVENTS_PER_FILE;
        let percentage = if max > 0 {
            current as f64 / max as f64
        } else {
            0.0
        };
        (current, max, percentage)
    }

    /// Get audit-level events (using security constants)
    pub fn get_audit_events(&self) -> Vec<(PathBuf, LogEvent)> {
        let Ok(events) = self.file_events.lock() else {
            return Vec::new();
        };
        let mut audit_events = Vec::new();

        for (path, file_events) in events.iter() {
            for event in file_events {
                // Audit events are typically error-level or security-related
                if event.is_error() || event.category() == "Security" {
                    audit_events.push((path.clone(), event.clone()));
                }
            }
        }

        // Limit to audit retention buffer size
        if audit_events.len() > AUDIT_LOG_RETENTION_BUFFER {
            audit_events.truncate(AUDIT_LOG_RETENTION_BUFFER);
        }

        audit_events
    }

    /// Get system resource usage information
    pub fn get_resource_usage(&self) -> CollectorResourceUsage {
        let (total_events, total_files) = {
            let Ok(events) = self.file_events.lock() else {
                return CollectorResourceUsage::default();
            };
            (events.values().map(|v| v.len()).sum(), events.len())
        };

        let total_contexts = {
            let Ok(contexts) = self.file_contexts.lock() else {
                return CollectorResourceUsage::default();
            };
            contexts.len()
        };

        // Estimate memory usage (rough approximation)
        let estimated_memory_bytes = total_events * 512 + total_contexts * 256; // Rough estimate

        CollectorResourceUsage {
            total_events,
            total_files,
            total_contexts,
            estimated_memory_bytes,
            capacity_percentage: if LOG_BUFFER_SIZE > 0 {
                (total_events as f64 / LOG_BUFFER_SIZE as f64) * 100.0
            } else {
                0.0
            },
            max_buffer_size: LOG_BUFFER_SIZE,
            max_events_per_file: MAX_LOG_EVENTS_PER_FILE,
        }
    }
}

impl Default for ErrorCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Resource usage information for the collector
#[derive(Debug, Clone, Default)]
pub struct CollectorResourceUsage {
    pub total_events: usize,
    pub total_files: usize,
    pub total_contexts: usize,
    pub estimated_memory_bytes: usize,
    pub capacity_percentage: f64,
    pub max_buffer_size: usize,
    pub max_events_per_file: usize,
}

impl CollectorResourceUsage {
    pub fn is_near_capacity(&self) -> bool {
        self.capacity_percentage > 80.0
    }

    pub fn is_over_capacity(&self) -> bool {
        self.capacity_percentage > 100.0
    }

    pub fn get_memory_usage_mb(&self) -> f64 {
        self.estimated_memory_bytes as f64 / (1024.0 * 1024.0)
    }

    pub fn get_summary(&self) -> String {
        format!(
            "Collector Usage: {:.1}% capacity ({}/{} events), {:.2}MB memory, {} files",
            self.capacity_percentage,
            self.total_events,
            self.max_buffer_size,
            self.get_memory_usage_mb(),
            self.total_files
        )
    }
}

// ============================================================================
// CARGO-STYLE FORMATTING
// ============================================================================

/// Format errors in cargo-style output
pub fn format_cargo_style_errors(collector: &ErrorCollector) -> String {
    let mut output = String::new();
    let all_events = collector.get_all_file_events();

    // Print errors grouped by file
    for (file_path, events) in &all_events {
        let error_events: Vec<_> = events.iter().filter(|e| e.is_error()).collect();
        let warning_events: Vec<_> = events.iter().filter(|e| e.is_warning()).collect();

        if !error_events.is_empty() || !warning_events.is_empty() {
            output.push_str(&format!("Checking {}...\n", file_path.display()));

            // Print errors
            for event in error_events {
                let span_info = event
                    .span
                    .as_ref()
                    .map(|s| {
                        format!(
                            " --> {}:{}:{}",
                            file_path.display(),
                            s.start().line,
                            s.start().column
                        )
                    })
                    .unwrap_or_default();

                output.push_str(&format!(
                    "error[{}]: {}{}\n",
                    event.code.as_str(),
                    event.message,
                    span_info
                ));

                // Add severity and category for errors
                output.push_str(&format!(
                    "  = severity: {}, category: {}\n",
                    event.severity(),
                    event.category()
                ));

                // Add context information if available
                if !event.context.is_empty() {
                    output.push_str("  |\n");
                    for (key, value) in &event.context {
                        if key != "file" && key != "file_id" {
                            output.push_str(&format!("  = {}: {}\n", key, value));
                        }
                    }
                }

                // Add recommended action for errors
                let action = event.recommended_action();
                if action != "No specific action available" {
                    output.push_str(&format!("  = help: {}\n", action));
                }
            }

            // Print warnings
            for event in warning_events {
                let span_info = event
                    .span
                    .as_ref()
                    .map(|s| {
                        format!(
                            " --> {}:{}:{}",
                            file_path.display(),
                            s.start().line,
                            s.start().column
                        )
                    })
                    .unwrap_or_default();

                output.push_str(&format!(
                    "warning[{}]: {}{}\n",
                    event.code.as_str(),
                    event.message,
                    span_info
                ));

                // Add context for warnings if present
                if !event.context.is_empty() {
                    for (key, value) in &event.context {
                        if key != "file" && key != "file_id" {
                            output.push_str(&format!("  = {}: {}\n", key, value));
                        }
                    }
                }
            }

            output.push('\n');
        }
    }

    // Add summary
    let summary = collector.get_summary();

    if summary.total_errors > 0 {
        output.push_str(&format!("\nTotal errors: {}\n", summary.total_errors));
    }
    if summary.total_warnings > 0 {
        output.push_str(&format!("Total warnings: {}\n", summary.total_warnings));
    }

    output
}

/// Format detailed error report with metadata
pub fn format_detailed_errors(collector: &ErrorCollector) -> String {
    let mut output = String::new();
    let all_events = collector.get_all_file_events();

    output.push_str("=== DETAILED ERROR REPORT ===\n\n");

    // Add resource usage summary
    let resource_usage = collector.get_resource_usage();
    output.push_str(&format!(
        "Resource Usage: {}\n\n",
        resource_usage.get_summary()
    ));

    for (file_path, events) in &all_events {
        let errors: Vec<_> = events.iter().filter(|e| e.is_error()).collect();
        if !errors.is_empty() {
            output.push_str(&format!("File: {}\n", file_path.display()));
            output.push_str(&format!("Errors: {}\n", errors.len()));

            // Add per-file capacity info
            let (current, max, percentage) = collector.get_file_capacity_info(file_path);
            output.push_str(&format!(
                "Events: {}/{} ({:.1}%)\n\n",
                current,
                max,
                percentage * 100.0
            ));

            for (i, event) in errors.iter().enumerate() {
                output.push_str(&format!("Error #{}: {}\n", i + 1, event.format_detailed()));
                output.push('\n');
            }
        }
    }

    output
}

#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::codes;
    use std::path::PathBuf;

    #[test]
    fn test_error_collector_basic() {
        let collector = ErrorCollector::new();

        let file_path = PathBuf::from("test.esp");
        let event = LogEvent::error(codes::file_processing::FILE_NOT_FOUND, "Test error");

        collector.record_event(&file_path, event);

        let events = collector.get_file_events(&file_path);
        assert_eq!(events.len(), 1);
        assert!(collector.file_has_errors(&file_path));
    }

    #[test]
    fn test_processing_summary() {
        let collector = ErrorCollector::new();

        // Add some test events
        let file1 = PathBuf::from("file1.esp");
        let file2 = PathBuf::from("file2.esp");

        collector.record_event(
            &file1,
            LogEvent::error(codes::lexical::INVALID_CHARACTER, "Error"),
        );
        collector.record_event(&file2, LogEvent::warning("Warning"));

        let summary = collector.get_summary();
        assert_eq!(summary.total_files, 2);
        assert_eq!(summary.failed_files, 1);
        assert_eq!(summary.files_with_warnings, 1);
        assert_eq!(summary.total_errors, 1);
        assert_eq!(summary.total_warnings, 1);
    }

    #[test]
    fn test_critical_errors() {
        let collector = ErrorCollector::new();

        let file_path = PathBuf::from("test.esp");
        let critical_event = LogEvent::error(codes::system::INTERNAL_ERROR, "Critical error");
        let normal_event = LogEvent::error(codes::lexical::INVALID_CHARACTER, "Normal error");

        collector.record_event(&file_path, critical_event);
        collector.record_event(&file_path, normal_event);

        let critical_errors = collector.get_critical_errors();
        assert_eq!(critical_errors.len(), 1);
        assert_eq!(critical_errors[0].1.code.as_str(), "ERR001");
    }

    #[test]
    fn test_capacity_limits() {
        let collector = ErrorCollector::new();
        let file_path = PathBuf::from("test.esp");

        // Test per-file limits
        let (current, max, _) = collector.get_file_capacity_info(&file_path);
        assert_eq!(current, 0);
        assert_eq!(max, MAX_LOG_EVENTS_PER_FILE);

        // Test global capacity
        let (current, max, _) = collector.get_capacity_info();
        assert_eq!(current, 0);
        assert_eq!(max, LOG_BUFFER_SIZE);
    }

    #[test]
    fn test_resource_usage() {
        let collector = ErrorCollector::new();
        let file_path = PathBuf::from("test.esp");

        collector.record_event(&file_path, LogEvent::warning("Test"));

        let usage = collector.get_resource_usage();
        assert_eq!(usage.total_events, 1);
        assert_eq!(usage.total_files, 1);
        assert!(usage.estimated_memory_bytes > 0);
        assert!(!usage.is_near_capacity());

        let summary = usage.get_summary();
        assert!(summary.contains("Collector Usage:"));
    }

    #[test]
    fn test_audit_events() {
        let collector = ErrorCollector::new();
        let file_path = PathBuf::from("test.esp");

        collector.record_event(
            &file_path,
            LogEvent::error(codes::system::INTERNAL_ERROR, "System error"),
        );
        collector.record_event(&file_path, LogEvent::warning("Warning"));

        let audit_events = collector.get_audit_events();
        assert_eq!(audit_events.len(), 1); // Only the error should be audited
        assert_eq!(audit_events[0].1.code.as_str(), "ERR001");
    }
}
