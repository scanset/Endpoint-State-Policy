//! Batch processing module for ESP file validation
//!
//! Provides directory-based batch processing with sequential and parallel execution modes.
//! Integrates with the global logging system and error collector for cargo-style output.

use crate::pipeline::{self, PipelineError, PipelineResult};
use common::logging::{self, codes};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

// ============================================================================
// BATCH PROCESSING TYPES
// ============================================================================

/// Batch processing configuration
#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub max_threads: usize,
    pub recursive: bool,
    pub max_files: Option<usize>,
    pub progress_reporting: bool,
    pub fail_fast: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_threads: std::thread::available_parallelism()
                .map(|n| n.get().min(8))
                .unwrap_or(4),
            recursive: true,
            max_files: None,
            progress_reporting: true,
            fail_fast: false,
        }
    }
}

/// Batch processing results
#[derive(Debug)]
pub struct BatchResults {
    pub successful_files: Vec<(PathBuf, PipelineResult)>,
    pub failed_files: Vec<(PathBuf, PipelineError)>,
    pub processing_duration: Duration,
    pub files_processed: usize,
    pub files_discovered: usize,
}

impl BatchResults {
    pub fn new() -> Self {
        Self {
            successful_files: Vec::new(),
            failed_files: Vec::new(),
            processing_duration: Duration::new(0, 0),
            files_processed: 0,
            files_discovered: 0,
        }
    }

    pub fn success_count(&self) -> usize {
        self.successful_files.len()
    }

    pub fn failure_count(&self) -> usize {
        self.failed_files.len()
    }

    pub fn success_rate(&self) -> f64 {
        if self.files_processed == 0 {
            0.0
        } else {
            self.successful_files.len() as f64 / self.files_processed as f64
        }
    }

    pub fn add_success(&mut self, file_path: PathBuf, result: PipelineResult) {
        self.successful_files.push((file_path, result));
        self.files_processed += 1;
    }

    pub fn add_failure(&mut self, file_path: PathBuf, error: PipelineError) {
        self.failed_files.push((file_path, error));
        self.files_processed += 1;
    }

    pub fn merge(&mut self, other: BatchResults) {
        self.successful_files.extend(other.successful_files);
        self.failed_files.extend(other.failed_files);
        self.files_processed += other.files_processed;
    }

    pub fn summary(&self) -> String {
        format!(
            "Batch processing completed: {} files processed, {} successful ({:.1}%), {} failed, {:.2}s total",
            self.files_processed,
            self.success_count(),
            self.success_rate() * 100.0,
            self.failure_count(),
            self.processing_duration.as_secs_f64()
        )
    }
}

impl Default for BatchResults {
    fn default() -> Self {
        Self::new()
    }
}

/// Batch processing errors
#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    #[error("Directory not found: {path}")]
    DirectoryNotFound { path: String },

    #[error("Permission denied accessing directory: {path}")]
    PermissionDenied { path: String },

    #[error("No ESP files found in directory: {path}")]
    NoFilesFound { path: String },

    #[error("Too many files found: {count} (max: {max})")]
    TooManyFiles { count: usize, max: usize },

    #[error("IO error during directory traversal: {error}")]
    IoError { error: String },

    #[error("Thread pool error: {message}")]
    ThreadError { message: String },
}

// ============================================================================
// FILE DISCOVERY
// ============================================================================

/// Discover ESP files in a directory
pub fn discover_esp_files(
    dir_path: &Path,
    config: &BatchConfig,
) -> Result<Vec<PathBuf>, BatchError> {
    common::log_info!("Starting file discovery",
        "directory" => dir_path.display(),
        "recursive" => config.recursive
    );

    if !dir_path.exists() {
        return Err(BatchError::DirectoryNotFound {
            path: dir_path.display().to_string(),
        });
    }

    if !dir_path.is_dir() {
        return Err(BatchError::DirectoryNotFound {
            path: format!("{} is not a directory", dir_path.display()),
        });
    }

    let mut files = Vec::new();

    if config.recursive {
        visit_directory_recursive(dir_path, &mut files, config)?;
    } else {
        visit_directory_single_level(dir_path, &mut files, config)?;
    }

    if files.is_empty() {
        return Err(BatchError::NoFilesFound {
            path: dir_path.display().to_string(),
        });
    }

    // Sort files for deterministic processing order
    files.sort();

    common::log_success!(
        codes::success::FILE_VALIDATION_PASSED,
        "File discovery completed",
        "files_found" => files.len(),
        "directory" => dir_path.display()
    );

    Ok(files)
}

/// Visit directory recursively
fn visit_directory_recursive(
    dir_path: &Path,
    files: &mut Vec<PathBuf>,
    config: &BatchConfig,
) -> Result<(), BatchError> {
    let entries = fs::read_dir(dir_path).map_err(|e| BatchError::IoError {
        error: e.to_string(),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| BatchError::IoError {
            error: e.to_string(),
        })?;

        let path = entry.path();

        if path.is_dir() {
            visit_directory_recursive(&path, files, config)?;
        } else if is_esp_file(&path) {
            files.push(path);

            // Check file count limit
            if let Some(max_files) = config.max_files {
                if files.len() >= max_files {
                    common::log_warning!(
                        "Reached maximum file limit",
                        "files_found" => files.len(),
                        "limit" => max_files
                    );
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

/// Visit directory at single level only
fn visit_directory_single_level(
    dir_path: &Path,
    files: &mut Vec<PathBuf>,
    config: &BatchConfig,
) -> Result<(), BatchError> {
    let entries = fs::read_dir(dir_path).map_err(|e| BatchError::IoError {
        error: e.to_string(),
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| BatchError::IoError {
            error: e.to_string(),
        })?;

        let path = entry.path();

        if is_esp_file(&path) {
            files.push(path);

            // Check file count limit
            if let Some(max_files) = config.max_files {
                if files.len() >= max_files {
                    common::log_warning!(
                        "Reached maximum file limit",
                        "files_found" => files.len(),
                        "limit" => max_files
                    );
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Check if a path represents an ESP file
fn is_esp_file(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.eq_ignore_ascii_case("esp"))
            .unwrap_or(false)
}

/// Validate files before processing
fn validate_files(files: &[PathBuf]) -> (Vec<PathBuf>, Vec<(PathBuf, String)>) {
    let mut valid_files = Vec::new();
    let mut invalid_files = Vec::new();

    for file in files {
        match validate_single_file(file) {
            Ok(_) => valid_files.push(file.clone()),
            Err(reason) => invalid_files.push((file.clone(), reason)),
        }
    }

    if !invalid_files.is_empty() {
        common::log_warning!(
            "Some files failed validation",
            "valid_files" => valid_files.len(),
            "invalid_files" => invalid_files.len()
        );
    }

    (valid_files, invalid_files)
}

/// Validate a single file for processing
fn validate_single_file(file_path: &Path) -> Result<(), String> {
    // Check file exists and is readable
    if !file_path.exists() {
        return Err("File does not exist".to_string());
    }

    if !file_path.is_file() {
        return Err("Path is not a file".to_string());
    }

    // Check file size (50MB limit)
    match std::fs::metadata(file_path) {
        Ok(metadata) => {
            const MAX_FILE_SIZE: u64 = 50 * 1024 * 1024; // 50MB
            if metadata.len() > MAX_FILE_SIZE {
                return Err(format!(
                    "File too large: {} bytes (max: {} bytes)",
                    metadata.len(),
                    MAX_FILE_SIZE
                ));
            }
        }
        Err(e) => return Err(format!("Cannot read file metadata: {}", e)),
    }

    Ok(())
}

// ============================================================================
// BATCH PROCESSING
// ============================================================================

/// Process a directory of ESP files sequentially
pub fn process_directory_sequential(
    dir_path: &Path,
    config: &BatchConfig,
) -> Result<BatchResults, BatchError> {
    let start_time = Instant::now();

    common::log_info!("Starting sequential batch processing",
        "directory" => dir_path.display()
    );

    // Discover files
    let discovered_files = discover_esp_files(dir_path, config)?;
    let (valid_files, invalid_files) = validate_files(&discovered_files);

    // Log invalid files
    for (file_path, reason) in &invalid_files {
        common::log_error!(
            codes::file_processing::INVALID_PATH,
            "File validation failed",
            "file" => file_path.display(),
            "reason" => reason
        );
    }

    let mut results = BatchResults::new();
    results.files_discovered = discovered_files.len();

    // Process each valid file
    for (file_id, file_path) in valid_files.iter().enumerate() {
        if config.progress_reporting {
            println!(
                "Processing file {} of {}: {}",
                file_id + 1,
                valid_files.len(),
                file_path.display()
            );
        }

        // Process with file context for automatic error collection
        let should_continue = logging::with_file_context(file_path.clone(), file_id, || {
            match pipeline::process_file(file_path.to_str().unwrap()) {
                Ok(pipeline_result) => {
                    results.add_success(file_path.clone(), pipeline_result);

                    common::log_success!(
                        codes::success::FILE_PROCESSING_SUCCESS,
                        "File processed successfully",
                        "file" => file_path.display(),
                        "file_id" => file_id
                    );
                    true
                }
                Err(pipeline_error) => {
                    results.add_failure(file_path.clone(), pipeline_error);

                    common::log_error!(
                        codes::file_processing::IO_ERROR,
                        "File processing failed",
                        "file" => file_path.display(),
                        "file_id" => file_id
                    );

                    // Check for fail-fast mode
                    if config.fail_fast {
                        common::log_warning!("Fail-fast mode enabled, stopping batch processing");
                        return false;
                    }
                    true
                }
            }
        });

        if !should_continue {
            break;
        }
    }

    results.processing_duration = start_time.elapsed();

    common::log_success!(
        codes::success::OPERATION_COMPLETED_SUCCESSFULLY,
        "Sequential batch processing completed",
        "files_processed" => results.files_processed,
        "successful" => results.success_count(),
        "failed" => results.failure_count(),
        "duration_ms" => format!("{:.2}", results.processing_duration.as_secs_f64() * 1000.0)
    );

    Ok(results)
}

/// Process files in parallel using a thread pool
pub fn process_directory_parallel(
    dir_path: &Path,
    config: &BatchConfig,
) -> Result<BatchResults, BatchError> {
    let start_time = Instant::now();

    common::log_info!("Starting parallel batch processing",
        "directory" => dir_path.display(),
        "max_threads" => config.max_threads
    );

    // Discover and validate files
    let discovered_files = discover_esp_files(dir_path, config)?;
    let (valid_files, invalid_files) = validate_files(&discovered_files);

    // Log invalid files
    for (file_path, reason) in &invalid_files {
        common::log_error!(
            codes::file_processing::INVALID_PATH,
            "File validation failed",
            "file" => file_path.display(),
            "reason" => reason
        );
    }

    let mut results = BatchResults::new();
    results.files_discovered = discovered_files.len();

    if valid_files.is_empty() {
        results.processing_duration = start_time.elapsed();
        return Ok(results);
    }

    // Calculate optimal chunk size for memory management
    let chunk_size = calculate_chunk_size(&valid_files, config.max_threads);

    common::log_debug!("Parallel processing configuration",
        "total_files" => valid_files.len(),
        "chunk_size" => chunk_size,
        "threads" => config.max_threads
    );

    // Process files in chunks
    for chunk in valid_files.chunks(chunk_size) {
        let chunk_results = process_chunk_parallel(chunk, config)?;
        results.merge(chunk_results);

        // Check for fail-fast mode
        if config.fail_fast && results.failure_count() > 0 {
            common::log_warning!("Fail-fast mode enabled, stopping batch processing");
            break;
        }
    }

    results.processing_duration = start_time.elapsed();

    common::log_success!(
        codes::success::OPERATION_COMPLETED_SUCCESSFULLY,
        "Parallel batch processing completed",
        "files_processed" => results.files_processed,
        "successful" => results.success_count(),
        "failed" => results.failure_count(),
        "threads_used" => config.max_threads,
        "duration_ms" => format!("{:.2}", results.processing_duration.as_secs_f64() * 1000.0)
    );

    Ok(results)
}

/// Process a chunk of files in parallel
fn process_chunk_parallel(
    files: &[PathBuf],
    config: &BatchConfig,
) -> Result<BatchResults, BatchError> {
    let results = Arc::new(std::sync::Mutex::new(BatchResults::new()));

    // Create thread handles
    let mut handles = Vec::new();
    let files_per_thread = files.len().div_ceil(config.max_threads);

    for thread_id in 0..config.max_threads {
        let start_idx = thread_id * files_per_thread;
        let end_idx = ((thread_id + 1) * files_per_thread).min(files.len());

        if start_idx >= files.len() {
            break;
        }

        let thread_files: Vec<PathBuf> = files[start_idx..end_idx].to_vec();
        let results_clone = Arc::clone(&results);

        let handle = thread::spawn(move || {
            for (local_file_id, file_path) in thread_files.iter().enumerate() {
                let global_file_id = start_idx + local_file_id;

                logging::with_file_context(file_path.clone(), global_file_id, || {
                    match pipeline::process_file(file_path.to_str().unwrap()) {
                        Ok(pipeline_result) => {
                            let mut results_guard = results_clone.lock().unwrap();
                            results_guard.add_success(file_path.clone(), pipeline_result);
                        }
                        Err(pipeline_error) => {
                            let mut results_guard = results_clone.lock().unwrap();
                            results_guard.add_failure(file_path.clone(), pipeline_error);
                        }
                    }
                });
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to complete
    for handle in handles {
        handle.join().map_err(|_| BatchError::ThreadError {
            message: "Thread panicked during processing".to_string(),
        })?;
    }

    // Extract results
    let final_results = Arc::try_unwrap(results)
        .map_err(|_| BatchError::ThreadError {
            message: "Failed to extract results from thread pool".to_string(),
        })?
        .into_inner()
        .unwrap();

    Ok(final_results)
}

/// Calculate optimal chunk size for parallel processing
fn calculate_chunk_size(files: &[PathBuf], max_threads: usize) -> usize {
    const MIN_CHUNK_SIZE: usize = 1;
    const MAX_CHUNK_SIZE: usize = 50; // Prevent memory pressure

    let ideal_chunk_size = files.len().div_ceil(max_threads);

    ideal_chunk_size.clamp(MIN_CHUNK_SIZE, MAX_CHUNK_SIZE)
}

// ============================================================================
// PUBLIC API
// ============================================================================

/// Process a directory with default configuration
pub fn process_directory(dir_path: &Path) -> Result<BatchResults, BatchError> {
    let config = BatchConfig::default();
    if config.max_threads == 1 {
        process_directory_sequential(dir_path, &config)
    } else {
        process_directory_parallel(dir_path, &config)
    }
}

/// Process a directory with custom configuration
pub fn process_directory_with_config(
    dir_path: &Path,
    config: &BatchConfig,
) -> Result<BatchResults, BatchError> {
    if config.max_threads == 1 {
        process_directory_sequential(dir_path, config)
    } else {
        process_directory_parallel(dir_path, config)
    }
}

/// Get batch processing capabilities
pub fn get_batch_info() -> BatchInfo {
    BatchInfo {
        max_recommended_threads: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
        supports_recursive_discovery: true,
        supports_parallel_processing: true,
        supports_progress_reporting: true,
        supports_fail_fast: true,
        max_files_per_batch: None,
        supported_file_extensions: vec!["esp".to_string()],
    }
}

/// Batch processing capabilities
#[derive(Debug, Clone)]
pub struct BatchInfo {
    pub max_recommended_threads: usize,
    pub supports_recursive_discovery: bool,
    pub supports_parallel_processing: bool,
    pub supports_progress_reporting: bool,
    pub supports_fail_fast: bool,
    pub max_files_per_batch: Option<usize>,
    pub supported_file_extensions: Vec<String>,
}

impl BatchInfo {
    pub fn summary(&self) -> String {
        format!(
            "Batch processor: {} threads, recursive discovery, parallel processing, progress reporting",
            self.max_recommended_threads
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_file_discovery() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        // Create test files
        fs::write(temp_path.join("test1.esp"), "DEF\nDEF_END\n").unwrap();
        fs::write(temp_path.join("test2.esp"), "DEF\nDEF_END\n").unwrap();
        fs::write(temp_path.join("not_esp.txt"), "not esp").unwrap();

        let config = BatchConfig::default();
        let files = discover_esp_files(temp_path, &config).unwrap();

        assert_eq!(files.len(), 2);
        assert!(files.iter().all(|f| f.extension().unwrap() == "esp"));
    }

    #[test]
    fn test_file_validation() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        let valid_file = temp_path.join("valid.esp");
        fs::write(&valid_file, "DEF\nDEF_END\n").unwrap();

        let files = vec![valid_file, temp_path.join("nonexistent.esp")];
        let (valid, invalid) = validate_files(&files);

        assert_eq!(valid.len(), 1);
        assert_eq!(invalid.len(), 1);
    }

    #[test]
    fn test_is_esp_file() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        let esp_file = temp_path.join("test.esp");
        let txt_file = temp_path.join("test.txt");

        fs::write(&esp_file, "content").unwrap();
        fs::write(&txt_file, "content").unwrap();

        assert!(is_esp_file(&esp_file));
        assert!(!is_esp_file(&txt_file));
        assert!(!is_esp_file(temp_path)); // Directory
    }

    #[test]
    fn test_batch_results() {
        let mut results = BatchResults::new();
        assert_eq!(results.success_rate(), 0.0);

        // Test basic functionality without creating complex mock objects
        results.files_processed = 2;
        // Just test the counting logic
        assert_eq!(results.success_count(), 0);
        assert_eq!(results.failure_count(), 0);
    }

    #[test]
    fn test_chunk_size_calculation() {
        assert_eq!(calculate_chunk_size(&vec![PathBuf::new(); 100], 4), 25);
        assert_eq!(calculate_chunk_size(&vec![PathBuf::new(); 10], 4), 3);
        assert_eq!(calculate_chunk_size(&vec![PathBuf::new(); 1], 4), 1);
        assert_eq!(calculate_chunk_size(&vec![PathBuf::new(); 200], 4), 50); // Max limit
    }

    #[test]
    fn test_batch_config_default() {
        let config = BatchConfig::default();
        assert!(config.max_threads >= 1);
        assert!(config.recursive);
        assert!(config.progress_reporting);
        assert!(!config.fail_fast);
        assert!(config.max_files.is_none());
    }
}
