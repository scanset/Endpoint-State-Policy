//! File processor module with compile-time constants and global logging integration

mod processor;

use common::config::constants::compile_time::file_processing::{
    LARGE_FILE_THRESHOLD, MAX_FILE_SIZE, MAX_LINE_COUNT_FOR_ANALYSIS,
};
use common::config::runtime::FileProcessorPreferences;
use common::log_debug;
pub use processor::{FileMetadata, FileProcessingResult, FileProcessor, FileProcessorError};

/// Process a file with default settings
pub fn process_file(file_path: &str) -> Result<FileProcessingResult, FileProcessorError> {
    processor::process_file(file_path)
}

/// Create a file processor with default settings
pub fn create_processor() -> FileProcessor {
    processor::create_processor()
}

/// Create a file processor with custom runtime preferences
///
/// **BREAKING CHANGE**: The `max_file_size` parameter has been removed.
/// File size limits are now compile-time constants for SSDF compliance.
/// Use `get_max_file_size()` to check the current limit.
pub fn create_custom_processor(
    require_esp_extension: bool,
    enable_performance_logging: bool,
) -> FileProcessor {
    processor::create_custom_processor(require_esp_extension, enable_performance_logging)
}

/// Create a file processor from runtime preferences structure
pub fn create_processor_from_preferences(prefs: &FileProcessorPreferences) -> FileProcessor {
    processor::create_processor_from_preferences(prefs)
}

/// Check if an error should halt processing
pub fn should_halt_on_error(error: &FileProcessorError) -> bool {
    processor::should_halt_on_error(error)
}

/// Get error code for an error
pub fn get_error_code(error: &FileProcessorError) -> common::logging::Code {
    processor::get_error_code(error)
}

/// Get the compile-time maximum file size limit
///
/// This returns the security boundary that cannot be changed at runtime.
/// For SSDF compliance, this value is baked into the binary at compile time.
pub fn get_max_file_size() -> u64 {
    processor::get_max_file_size()
}

/// Get the compile-time large file threshold
///
/// This affects processing strategy and complexity analysis.
/// The value is optimized at compile time for performance.
pub fn get_large_file_threshold() -> u64 {
    processor::get_large_file_threshold()
}

/// Get default runtime preferences for file processing
pub fn get_default_preferences() -> FileProcessorPreferences {
    FileProcessorPreferences {
        require_esp_extension: false,
        enable_performance_logging: true,
        log_non_esp_processing: true,
        include_complexity_metrics: false,
    }
}

/// Initialize file processor logging validation (for system startup)
pub fn init_file_processor_logging() -> Result<(), String> {
    use common::config::constants::compile_time::file_processing::PERFORMANCE_LOG_BUFFER_SIZE;

    // Validate that all file processor error codes are properly configured
    let test_codes = [
        common::logging::codes::file_processing::FILE_NOT_FOUND,
        common::logging::codes::file_processing::INVALID_EXTENSION,
        common::logging::codes::file_processing::FILE_TOO_LARGE,
        common::logging::codes::file_processing::EMPTY_FILE,
        common::logging::codes::file_processing::PERMISSION_DENIED,
        common::logging::codes::file_processing::INVALID_ENCODING,
        common::logging::codes::file_processing::IO_ERROR,
        common::logging::codes::file_processing::INVALID_PATH,
    ];

    for code in &test_codes {
        let description = common::logging::codes::get_description(code.as_str());
        if description == "Unknown error" {
            return Err(format!(
                "File processor error code {} has no description",
                code.as_str()
            ));
        }

        // Verify the code exists in the error metadata registry
        if common::logging::codes::get_error_metadata(code.as_str()).is_none() {
            return Err(format!(
                "File processor error code {} not found in metadata registry",
                code.as_str()
            ));
        }
    }

    // Validate success code
    let success_code = common::logging::codes::success::FILE_PROCESSING_SUCCESS;
    if common::logging::codes::get_error_metadata(success_code.as_str()).is_none() {
        // Success codes might not be in error registry, which is fine
        log_debug!("Success code validation skipped (not in error registry)",
            "code" => success_code.as_str());
    }

    // Log compile-time configuration for startup validation
    let max_size_str = MAX_FILE_SIZE.to_string();
    let threshold_str = LARGE_FILE_THRESHOLD.to_string();
    let max_lines_str = MAX_LINE_COUNT_FOR_ANALYSIS.to_string();
    let buffer_size_str = PERFORMANCE_LOG_BUFFER_SIZE.to_string();

    log_debug!("File processor compile-time configuration loaded",
        "max_file_size" => max_size_str.as_str(),
        "large_file_threshold" => threshold_str.as_str(),
        "max_line_count" => max_lines_str.as_str(),
        "perf_buffer_size" => buffer_size_str.as_str());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_module_api() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.esp");
        fs::write(&file_path, "BEGIN:VCALENDAR\nEND:VCALENDAR\n").unwrap();

        // Test module-level function
        let result = process_file(file_path.to_str().unwrap());
        assert!(result.is_ok());
    }

    #[test]
    fn test_create_processor() {
        let _processor = create_processor();
        // Can no longer access max_file_size field directly - it's compile-time now
        assert_eq!(FileProcessor::max_file_size(), MAX_FILE_SIZE);
    }

    #[test]
    fn test_create_custom_processor_new_signature() {
        // BREAKING CHANGE: max_file_size parameter removed
        let processor = create_custom_processor(true, false);
        assert!(processor.require_esp_extension);
        assert!(!processor.enable_performance_logging);

        // File size is now compile-time constant
        assert_eq!(FileProcessor::max_file_size(), MAX_FILE_SIZE);
    }

    #[test]
    fn test_create_processor_from_preferences() {
        let prefs = FileProcessorPreferences {
            require_esp_extension: true,
            enable_performance_logging: false,
            log_non_esp_processing: false,
            include_complexity_metrics: true,
        };

        let processor = create_processor_from_preferences(&prefs);
        assert!(processor.require_esp_extension);
        assert!(!processor.enable_performance_logging);
        assert!(!processor.log_non_esp_processing);
        assert!(processor.include_complexity_metrics);
    }

    #[test]
    fn test_error_helpers() {
        let error = FileProcessorError::FileNotFound {
            path: "test.esp".to_string(),
        };

        assert!(should_halt_on_error(&error));
        let code = get_error_code(&error);
        assert_eq!(code.as_str(), "E005"); // FILE_NOT_FOUND code
    }

    #[test]
    fn test_compile_time_constants_access() {
        assert_eq!(get_max_file_size(), MAX_FILE_SIZE);
        assert_eq!(get_large_file_threshold(), LARGE_FILE_THRESHOLD);

        // Verify constants are reasonable values
        assert!(get_max_file_size() > 0);
        assert!(get_large_file_threshold() > 0);
        assert!(get_large_file_threshold() <= get_max_file_size());
    }

    #[test]
    fn test_default_preferences() {
        let prefs = get_default_preferences();
        assert!(!prefs.require_esp_extension);
        assert!(prefs.enable_performance_logging);
        assert!(prefs.log_non_esp_processing);
        assert!(!prefs.include_complexity_metrics);
    }

    #[test]
    fn test_init_logging() {
        let result = init_file_processor_logging();
        assert!(result.is_ok());
    }

    #[test]
    fn test_constants_are_accessible() {
        // Verify we can access compile-time constants from this module
        assert_eq!(MAX_FILE_SIZE, 10 * 1024 * 1024);
        assert_eq!(LARGE_FILE_THRESHOLD, 1024 * 1024);
        assert_eq!(MAX_LINE_COUNT_FOR_ANALYSIS, 100_000);
    }
}
