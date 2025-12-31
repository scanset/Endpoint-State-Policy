//! File processor implementation with compile-time constants and global logging integration

use common::config::constants::compile_time::file_processing::{
    LARGE_FILE_THRESHOLD, MAX_FILE_SIZE, MAX_LINE_COUNT_FOR_ANALYSIS,
};
use common::config::runtime::FileProcessorPreferences;
use common::logging::codes;
use common::{log_debug, log_error, log_success};
use std::fs;
use std::path::{Path, PathBuf};

/// File processor specific errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum FileProcessorError {
    #[error("File not found: {path}")]
    FileNotFound { path: String },

    #[error("Invalid file extension: expected .esp, found {extension:?}")]
    InvalidExtension { extension: Option<String> },

    #[error("File too large: {size} bytes (max: {max_size})")]
    FileTooLarge { size: u64, max_size: u64 },

    #[error("File is empty")]
    EmptyFile,

    #[error("Permission denied: {path}")]
    PermissionDenied { path: String },

    #[error("Invalid UTF-8 encoding in file: {path}")]
    InvalidEncoding { path: String },

    #[error("I/O error reading file: {message}")]
    IoError { message: String },

    #[error("Invalid file path: {path}")]
    InvalidPath { path: String },

    #[error("File exceeds maximum line count: {lines} (max: {max_lines})")]
    TooManyLines { lines: usize, max_lines: usize },
}

impl FileProcessorError {
    /// Get the appropriate error code for this error type
    pub fn error_code(&self) -> common::logging::Code {
        match self {
            FileProcessorError::FileNotFound { .. } => codes::file_processing::FILE_NOT_FOUND,
            FileProcessorError::InvalidExtension { .. } => {
                codes::file_processing::INVALID_EXTENSION
            }
            FileProcessorError::FileTooLarge { .. } => codes::file_processing::FILE_TOO_LARGE,
            FileProcessorError::EmptyFile => codes::file_processing::EMPTY_FILE,
            FileProcessorError::PermissionDenied { .. } => {
                codes::file_processing::PERMISSION_DENIED
            }
            FileProcessorError::InvalidEncoding { .. } => codes::file_processing::INVALID_ENCODING,
            FileProcessorError::IoError { .. } => codes::file_processing::IO_ERROR,
            FileProcessorError::InvalidPath { .. } => codes::file_processing::INVALID_PATH,
            FileProcessorError::TooManyLines { .. } => codes::file_processing::FILE_TOO_LARGE, // Reuse code
        }
    }

    /// Check if this error should halt processing
    pub fn requires_halt(&self) -> bool {
        // Use the error code system to determine halt behavior
        common::logging::codes::requires_halt(self.error_code().as_str())
    }

    /// Get error severity
    pub fn severity(&self) -> &'static str {
        common::logging::codes::get_severity(self.error_code().as_str()).as_str()
    }

    /// Get error category
    pub fn category(&self) -> &'static str {
        common::logging::codes::get_category(self.error_code().as_str())
    }

    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        common::logging::codes::is_recoverable(self.error_code().as_str())
    }
}

/// File metadata collected during processing
#[derive(Debug, Clone)]
pub struct FileMetadata {
    /// Canonical file path
    pub path: PathBuf,
    /// File size in bytes
    pub size: u64,
    /// File extension (if any)
    pub extension: Option<String>,
    /// Number of lines in file
    pub line_count: usize,
    /// Whether file has .esp extension
    pub is_esp_file: bool,
    /// File creation/modification time (if available)
    pub modified: Option<std::time::SystemTime>,
}

impl FileMetadata {
    /// Get file size in human-readable format
    pub fn human_readable_size(&self) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
        let mut size = self.size as f64;
        let mut unit_index = 0;

        while size >= 1024.0 && unit_index < UNITS.len() - 1 {
            size /= 1024.0;
            unit_index += 1;
        }

        if unit_index == 0 {
            format!("{} {}", self.size, UNITS[unit_index])
        } else {
            format!("{:.2} {}", size, UNITS[unit_index])
        }
    }

    /// Check if file is likely to be large for processing (uses compile-time threshold)
    pub fn is_large_file(&self) -> bool {
        self.size > LARGE_FILE_THRESHOLD
    }

    /// Get processing complexity estimate based on size and line count
    pub fn complexity_score(&self) -> f64 {
        // Simple heuristic: size in KB + line count factor
        let size_factor = self.size as f64 / 1024.0;
        let line_factor = self.line_count as f64 * 0.1;
        size_factor + line_factor
    }

    /// Check if line count is within safe bounds for analysis
    pub fn is_safe_for_analysis(&self) -> bool {
        self.line_count <= MAX_LINE_COUNT_FOR_ANALYSIS
    }
}

/// File processing result containing source and metadata
#[derive(Debug, Clone)]
pub struct FileProcessingResult {
    /// File contents as UTF-8 string
    pub source: String,
    /// File metadata
    pub metadata: FileMetadata,
    /// Processing duration
    pub processing_duration: std::time::Duration,
}

impl FileProcessingResult {
    /// Get character count
    pub fn char_count(&self) -> usize {
        self.source.chars().count()
    }

    /// Check if file is empty content-wise (only whitespace)
    pub fn is_effectively_empty(&self) -> bool {
        self.source.trim().is_empty()
    }

    /// Get processing rate (characters per millisecond)
    pub fn processing_rate(&self) -> f64 {
        let duration_ms = self.processing_duration.as_secs_f64() * 1000.0;
        if duration_ms > 0.0 {
            self.char_count() as f64 / duration_ms
        } else {
            0.0
        }
    }
}

/// File processor with compile-time security constants and runtime preferences
pub struct FileProcessor {
    /// Whether to require .esp extension (runtime preference)
    pub require_esp_extension: bool,
    /// Whether to enable detailed performance logging (runtime preference)
    pub enable_performance_logging: bool,
    /// Whether to log debug information for non-ESP files (runtime preference)
    pub log_non_esp_processing: bool,
    /// Whether to include complexity scores in output (runtime preference)
    pub include_complexity_metrics: bool,
}

impl FileProcessor {
    /// Create new file processor with default preferences
    pub fn new() -> Self {
        Self {
            require_esp_extension: false,
            enable_performance_logging: true,
            log_non_esp_processing: true,
            include_complexity_metrics: false,
        }
    }

    /// Create file processor from runtime preferences
    pub fn from_preferences(prefs: &FileProcessorPreferences) -> Self {
        Self {
            require_esp_extension: prefs.require_esp_extension,
            enable_performance_logging: prefs.enable_performance_logging,
            log_non_esp_processing: prefs.log_non_esp_processing,
            include_complexity_metrics: prefs.include_complexity_metrics,
        }
    }

    /// Require .esp extension
    pub fn with_esp_extension_required(mut self, required: bool) -> Self {
        self.require_esp_extension = required;
        self
    }

    /// Enable or disable performance logging
    pub fn with_performance_logging(mut self, enabled: bool) -> Self {
        self.enable_performance_logging = enabled;
        self
    }

    /// Enable or disable non-ESP file logging
    pub fn with_non_esp_logging(mut self, enabled: bool) -> Self {
        self.log_non_esp_processing = enabled;
        self
    }

    /// Enable or disable complexity metrics
    pub fn with_complexity_metrics(mut self, enabled: bool) -> Self {
        self.include_complexity_metrics = enabled;
        self
    }

    /// Get the compile-time maximum file size
    pub fn max_file_size() -> u64 {
        MAX_FILE_SIZE
    }

    /// Get the compile-time large file threshold
    pub fn large_file_threshold() -> u64 {
        LARGE_FILE_THRESHOLD
    }

    /// Process a file and return contents with metadata
    pub fn process_file(
        &self,
        file_path: &str,
    ) -> Result<FileProcessingResult, FileProcessorError> {
        let start_time = std::time::Instant::now();

        log_debug!("Starting file processing", "file" => file_path);

        // Step 1: Path validation
        let path = self.validate_path(file_path)?;

        // Step 2: Metadata collection
        let metadata = self.get_metadata(&path)?;

        // Step 3: File validation
        self.validate_file(&metadata, file_path)?;

        // Step 4: Content reading
        let source = self.read_file(&path, file_path)?;

        // Step 5: Line count validation and metadata update
        let line_count = source.lines().count();
        if line_count > MAX_LINE_COUNT_FOR_ANALYSIS {
            let error = FileProcessorError::TooManyLines {
                lines: line_count,
                max_lines: MAX_LINE_COUNT_FOR_ANALYSIS,
            };
            let lines_str = line_count.to_string();
            let max_str = MAX_LINE_COUNT_FOR_ANALYSIS.to_string();
            log_error!(error.error_code(), "File exceeds maximum line count for safe analysis",
                "file" => file_path,
                "lines" => lines_str.as_str(),
                "max_lines" => max_str.as_str());
            return Err(error);
        }

        // Update metadata with actual line count
        let mut final_metadata = metadata;
        final_metadata.line_count = line_count;

        let processing_duration = start_time.elapsed();

        let result = FileProcessingResult {
            source,
            metadata: final_metadata,
            processing_duration,
        };

        // Log successful completion with comprehensive metrics
        self.log_processing_success(&result, file_path);

        // Debug log for non-.esp files (if enabled and allowed)
        if !result.metadata.is_esp_file
            && !self.require_esp_extension
            && self.log_non_esp_processing
        {
            let ext_str = result.metadata.extension.as_deref().unwrap_or("none");
            log_debug!(
                "Processing non-ESP file",
                "extension" => ext_str,
                "file" => file_path
            );
        }

        Ok(result)
    }

    /// Log processing success with detailed metrics
    fn log_processing_success(&self, result: &FileProcessingResult, file_path: &str) {
        let size_str = result.metadata.size.to_string();
        let lines_str = result.metadata.line_count.to_string();
        let chars_str = result.char_count().to_string();
        let duration_str = format!("{:.2}", result.processing_duration.as_secs_f64() * 1000.0);

        if self.enable_performance_logging {
            let rate_str = format!("{:.2}", result.processing_rate());
            let human_size = result.metadata.human_readable_size();
            let max_size_str = MAX_FILE_SIZE.to_string();
            let is_large_str = result.metadata.is_large_file().to_string();
            let safe_analysis_str = result.metadata.is_safe_for_analysis().to_string();

            if self.include_complexity_metrics {
                let complexity_str = format!("{:.2}", result.metadata.complexity_score());
                log_success!(
                    codes::success::FILE_PROCESSING_SUCCESS,
                    "File processed successfully with full metrics",
                    "file" => file_path,
                    "size_bytes" => size_str.as_str(),
                    "size_human" => human_size.as_str(),
                    "lines" => lines_str.as_str(),
                    "chars" => chars_str.as_str(),
                    "duration_ms" => duration_str.as_str(),
                    "chars_per_ms" => rate_str.as_str(),
                    "complexity_score" => complexity_str.as_str(),
                    "max_size_bytes" => max_size_str.as_str(),
                    "is_large_file" => is_large_str.as_str(),
                    "safe_for_analysis" => safe_analysis_str.as_str()
                );
            } else {
                log_success!(
                    codes::success::FILE_PROCESSING_SUCCESS,
                    "File processed successfully with performance metrics",
                    "file" => file_path,
                    "size_bytes" => size_str.as_str(),
                    "size_human" => human_size.as_str(),
                    "lines" => lines_str.as_str(),
                    "chars" => chars_str.as_str(),
                    "duration_ms" => duration_str.as_str(),
                    "chars_per_ms" => rate_str.as_str(),
                    "max_size_bytes" => max_size_str.as_str(),
                    "is_large_file" => is_large_str.as_str()
                );
            }
        } else {
            log_success!(
                codes::success::FILE_PROCESSING_SUCCESS,
                "File processed successfully",
                "file" => file_path,
                "size_bytes" => size_str.as_str(),
                "lines" => lines_str.as_str(),
                "chars" => chars_str.as_str(),
                "duration_ms" => duration_str.as_str()
            );
        }
    }

    /// Validate file path and check existence
    fn validate_path(&self, file_path: &str) -> Result<PathBuf, FileProcessorError> {
        if file_path.is_empty() {
            let error = FileProcessorError::InvalidPath {
                path: file_path.to_string(),
            };
            log_error!(error.error_code(), "Empty file path provided");
            return Err(error);
        }

        let path = Path::new(file_path);

        if !path.exists() {
            let error = FileProcessorError::FileNotFound {
                path: file_path.to_string(),
            };
            log_error!(error.error_code(), "File not found", "path" => file_path);
            return Err(error);
        }

        if !path.is_file() {
            let error = FileProcessorError::InvalidPath {
                path: file_path.to_string(),
            };
            log_error!(error.error_code(), "Path is not a file", "path" => file_path);
            return Err(error);
        }

        match path.canonicalize() {
            Ok(canonical_path) => {
                let path_str = canonical_path.display().to_string();
                log_debug!("Path validation successful", "canonical_path" => path_str.as_str());
                Ok(canonical_path)
            }
            Err(e) => {
                let error = FileProcessorError::IoError {
                    message: format!("Failed to resolve path '{}': {}", file_path, e),
                };
                let io_error_str = e.to_string();
                log_error!(error.error_code(), "Failed to canonicalize path",
                    "path" => file_path,
                    "io_error" => io_error_str.as_str());
                Err(error)
            }
        }
    }

    /// Get file metadata
    fn get_metadata(&self, path: &Path) -> Result<FileMetadata, FileProcessorError> {
        let metadata = match fs::metadata(path) {
            Ok(meta) => meta,
            Err(e) => {
                let error = match e.kind() {
                    std::io::ErrorKind::PermissionDenied => {
                        let err = FileProcessorError::PermissionDenied {
                            path: path.display().to_string(),
                        };
                        let path_str = path.display().to_string();
                        log_error!(err.error_code(), "Permission denied accessing file",
                            "path" => path_str.as_str());
                        err
                    }
                    _ => {
                        let err = FileProcessorError::IoError {
                            message: format!(
                                "Failed to read metadata for '{}': {}",
                                path.display(),
                                e
                            ),
                        };
                        let path_str = path.display().to_string();
                        let io_error_str = e.to_string();
                        log_error!(err.error_code(), "Failed to read file metadata",
                            "path" => path_str.as_str(),
                            "io_error" => io_error_str.as_str());
                        err
                    }
                };
                return Err(error);
            }
        };

        let size = metadata.len();
        let extension = path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|s| s.to_lowercase());
        let is_esp_file = extension.as_deref() == Some("esp");
        let modified = metadata.modified().ok();

        let file_metadata = FileMetadata {
            path: path.to_path_buf(),
            size,
            extension: extension.clone(),
            line_count: 0, // Will be updated after reading
            is_esp_file,
            modified,
        };

        let size_str = size.to_string();
        let ext_str = extension.as_deref().unwrap_or("none");
        let is_esp_str = is_esp_file.to_string();
        let human_size = file_metadata.human_readable_size();
        let max_size_str = MAX_FILE_SIZE.to_string();
        let is_large_str = file_metadata.is_large_file().to_string();

        log_debug!("File metadata collected",
            "size_bytes" => size_str.as_str(),
            "size_human" => human_size.as_str(),
            "extension" => ext_str,
            "is_esp" => is_esp_str.as_str(),
            "max_size_bytes" => max_size_str.as_str(),
            "is_large_file" => is_large_str.as_str());

        Ok(file_metadata)
    }

    /// Validate file properties using compile-time constants
    fn validate_file(
        &self,
        metadata: &FileMetadata,
        file_path: &str,
    ) -> Result<(), FileProcessorError> {
        // Check file size against compile-time limit
        if metadata.size > MAX_FILE_SIZE {
            let error = FileProcessorError::FileTooLarge {
                size: metadata.size,
                max_size: MAX_FILE_SIZE,
            };
            let size_str = metadata.size.to_string();
            let limit_str = MAX_FILE_SIZE.to_string();
            let human_size = metadata.human_readable_size();
            let human_limit = {
                let mut temp_metadata = metadata.clone();
                temp_metadata.size = MAX_FILE_SIZE;
                temp_metadata.human_readable_size()
            };
            log_error!(error.error_code(), "File exceeds compile-time maximum size limit",
                "file" => file_path,
                "size_bytes" => size_str.as_str(),
                "size_human" => human_size.as_str(),
                "limit_bytes" => limit_str.as_str(),
                "limit_human" => human_limit.as_str());
            return Err(error);
        }

        // Check if file is empty
        if metadata.size == 0 {
            let error = FileProcessorError::EmptyFile;
            log_error!(error.error_code(), "File is empty", "file" => file_path);
            return Err(error);
        }

        // Check extension requirement (runtime preference)
        if self.require_esp_extension && !metadata.is_esp_file {
            let error = FileProcessorError::InvalidExtension {
                extension: metadata.extension.clone(),
            };
            let ext_str = metadata.extension.as_deref().unwrap_or("none");
            log_error!(error.error_code(), "File does not have required .esp extension",
                "file" => file_path,
                "extension" => ext_str,
                "required" => "esp");
            return Err(error);
        }

        Ok(())
    }

    /// Read file contents with validation
    fn read_file(&self, path: &Path, file_path: &str) -> Result<String, FileProcessorError> {
        match fs::read_to_string(path) {
            Ok(content) => {
                let chars_str = content.chars().count().to_string();
                let bytes_str = content.len().to_string();
                let lines_str = content.lines().count().to_string();

                log_debug!("File content read successfully",
                    "file" => file_path,
                    "chars" => chars_str.as_str(),
                    "bytes" => bytes_str.as_str(),
                    "lines" => lines_str.as_str());

                Ok(content)
            }
            Err(e) => {
                let error = match e.kind() {
                    std::io::ErrorKind::PermissionDenied => {
                        let err = FileProcessorError::PermissionDenied {
                            path: path.display().to_string(),
                        };
                        log_error!(err.error_code(), "Permission denied reading file",
                            "file" => file_path);
                        err
                    }
                    std::io::ErrorKind::InvalidData => {
                        let err = FileProcessorError::InvalidEncoding {
                            path: path.display().to_string(),
                        };
                        log_error!(err.error_code(), "Invalid UTF-8 encoding in file",
                            "file" => file_path);
                        err
                    }
                    _ => {
                        let err = FileProcessorError::IoError {
                            message: format!("Failed to read file '{}': {}", path.display(), e),
                        };
                        let io_error_str = e.to_string();
                        log_error!(err.error_code(), "I/O error reading file",
                            "file" => file_path,
                            "io_error" => io_error_str.as_str());
                        err
                    }
                };
                Err(error)
            }
        }
    }
}

impl Default for FileProcessor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MODULE API FUNCTIONS
// ============================================================================

/// Process a file with default settings
pub fn process_file(file_path: &str) -> Result<FileProcessingResult, FileProcessorError> {
    let processor = FileProcessor::new();
    processor.process_file(file_path)
}

/// Create a file processor with default settings
pub fn create_processor() -> FileProcessor {
    FileProcessor::new()
}

/// Create a file processor with custom runtime preferences (BREAKING CHANGE: max_file_size removed)
pub fn create_custom_processor(
    require_esp_extension: bool,
    enable_performance_logging: bool,
) -> FileProcessor {
    FileProcessor::new()
        .with_esp_extension_required(require_esp_extension)
        .with_performance_logging(enable_performance_logging)
}

/// Create a file processor from runtime preferences
pub fn create_processor_from_preferences(prefs: &FileProcessorPreferences) -> FileProcessor {
    FileProcessor::from_preferences(prefs)
}

/// Check if an error should halt processing
pub fn should_halt_on_error(error: &FileProcessorError) -> bool {
    error.requires_halt()
}

/// Get error code for an error
pub fn get_error_code(error: &FileProcessorError) -> common::logging::Code {
    error.error_code()
}

/// Get the compile-time maximum file size limit
pub fn get_max_file_size() -> u64 {
    MAX_FILE_SIZE
}

/// Get the compile-time large file threshold
pub fn get_large_file_threshold() -> u64 {
    LARGE_FILE_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_process_valid_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.esp");
        let content = "BEGIN:VCALENDAR\nEND:VCALENDAR\n";
        fs::write(&file_path, content).unwrap();

        let processor = FileProcessor::new();
        let result = processor.process_file(file_path.to_str().unwrap());

        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.metadata.line_count, 2);
        assert!(result.metadata.is_esp_file);
        assert_eq!(result.char_count(), content.chars().count());
        assert!(!result.is_effectively_empty());
    }

    #[test]
    fn test_file_not_found() {
        let processor = FileProcessor::new();
        let result = processor.process_file("nonexistent.esp");

        assert!(result.is_err());
        match result.unwrap_err() {
            FileProcessorError::FileNotFound { .. } => {}
            _ => panic!("Expected FileNotFound error"),
        }
    }

    #[test]
    fn test_compile_time_file_size_limit() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("large.esp");
        // Create file larger than compile-time limit (this test might fail if MAX_FILE_SIZE is very large)
        let large_content = "a".repeat((MAX_FILE_SIZE + 1) as usize);
        fs::write(&file_path, large_content).unwrap();

        let processor = FileProcessor::new();
        let result = processor.process_file(file_path.to_str().unwrap());

        assert!(result.is_err());
        match result.unwrap_err() {
            FileProcessorError::FileTooLarge { size, max_size } => {
                assert!(size > MAX_FILE_SIZE);
                assert_eq!(max_size, MAX_FILE_SIZE);
            }
            _ => panic!("Expected FileTooLarge error"),
        }
    }

    #[test]
    fn test_extension_requirement() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();

        let processor = FileProcessor::new().with_esp_extension_required(true);
        let result = processor.process_file(file_path.to_str().unwrap());

        assert!(result.is_err());
        match result.unwrap_err() {
            FileProcessorError::InvalidExtension { .. } => {}
            _ => panic!("Expected InvalidExtension error"),
        }
    }

    #[test]
    fn test_empty_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("empty.esp");
        fs::write(&file_path, "").unwrap();

        let processor = FileProcessor::new();
        let result = processor.process_file(file_path.to_str().unwrap());

        assert!(result.is_err());
        match result.unwrap_err() {
            FileProcessorError::EmptyFile => {}
            _ => panic!("Expected EmptyFile error"),
        }
    }

    #[test]
    fn test_too_many_lines() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("many_lines.esp");
        // Create file with more lines than the compile-time limit
        let many_lines = "line\n".repeat(MAX_LINE_COUNT_FOR_ANALYSIS + 1);
        fs::write(&file_path, many_lines).unwrap();

        let processor = FileProcessor::new();
        let result = processor.process_file(file_path.to_str().unwrap());

        assert!(result.is_err());
        match result.unwrap_err() {
            FileProcessorError::TooManyLines { lines, max_lines } => {
                assert!(lines > MAX_LINE_COUNT_FOR_ANALYSIS);
                assert_eq!(max_lines, MAX_LINE_COUNT_FOR_ANALYSIS);
            }
            _ => panic!("Expected TooManyLines error"),
        }
    }

    #[test]
    fn test_performance_logging() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.esp");
        fs::write(&file_path, "BEGIN:VCALENDAR\nEND:VCALENDAR\n").unwrap();

        let processor = FileProcessor::new().with_performance_logging(true);
        let result = processor.process_file(file_path.to_str().unwrap());

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.processing_rate() > 0.0);
    }

    #[test]
    fn test_metadata_helpers_with_constants() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.esp");
        let content = "A".repeat((LARGE_FILE_THRESHOLD + 100) as usize); // Make it larger than threshold
        fs::write(&file_path, &content).unwrap();

        let processor = FileProcessor::new();
        let result = processor.process_file(file_path.to_str().unwrap()).unwrap();

        assert!(result.metadata.is_large_file()); // Uses compile-time threshold
        assert!(result.metadata.complexity_score() > 0.0);
        assert!(result.metadata.is_safe_for_analysis()); // Should be true for reasonable test size
    }

    #[test]
    fn test_error_methods() {
        let error = FileProcessorError::FileNotFound {
            path: "test.esp".to_string(),
        };

        assert_eq!(error.error_code().as_str(), "E005");
        assert_eq!(error.category(), "FileProcessing");
        assert_eq!(error.severity(), "Medium");
        assert!(!error.is_recoverable());
        assert!(error.requires_halt());
    }

    #[test]
    fn test_compile_time_constants_access() {
        assert_eq!(FileProcessor::max_file_size(), MAX_FILE_SIZE);
        assert_eq!(FileProcessor::large_file_threshold(), LARGE_FILE_THRESHOLD);
        assert_eq!(get_max_file_size(), MAX_FILE_SIZE);
        assert_eq!(get_large_file_threshold(), LARGE_FILE_THRESHOLD);
    }

    #[test]
    fn test_from_preferences() {
        let prefs = FileProcessorPreferences {
            require_esp_extension: true,
            enable_performance_logging: false,
            log_non_esp_processing: false,
            include_complexity_metrics: true,
        };

        let processor = FileProcessor::from_preferences(&prefs);
        assert!(processor.require_esp_extension);
        assert!(!processor.enable_performance_logging);
        assert!(!processor.log_non_esp_processing);
        assert!(processor.include_complexity_metrics);
    }
}
