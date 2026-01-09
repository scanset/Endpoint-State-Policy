//! File discovery utilities
//!
//! Functions for discovering ESP files in directories.

use std::path::{Path, PathBuf};

/// Discover all ESP files from an input path
///
/// If the path is a file, returns a vec containing just that file.
/// If the path is a directory, returns all .esp files in it (non-recursive).
pub fn discover_esp_files(input_path: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
    if input_path.is_file() {
        Ok(vec![input_path.to_path_buf()])
    } else if input_path.is_dir() {
        discover_in_directory(input_path)
    } else {
        Err(DiscoveryError::InvalidPath(input_path.to_path_buf()))
    }
}

/// Discover ESP files in a directory (non-recursive)
fn discover_in_directory(dir_path: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
    let mut esp_files = Vec::new();

    let entries = std::fs::read_dir(dir_path)
        .map_err(|e| DiscoveryError::ReadDir(dir_path.to_path_buf(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| DiscoveryError::ReadEntry(dir_path.to_path_buf(), e))?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "esp" {
                    esp_files.push(path);
                }
            }
        }
    }

    esp_files.sort();
    Ok(esp_files)
}

/// Discover ESP files recursively in a directory
#[allow(dead_code)]
pub fn discover_esp_files_recursive(dir_path: &Path) -> Result<Vec<PathBuf>, DiscoveryError> {
    let mut esp_files = Vec::new();
    discover_recursive_inner(dir_path, &mut esp_files)?;
    esp_files.sort();
    Ok(esp_files)
}

fn discover_recursive_inner(
    dir_path: &Path,
    esp_files: &mut Vec<PathBuf>,
) -> Result<(), DiscoveryError> {
    let entries = std::fs::read_dir(dir_path)
        .map_err(|e| DiscoveryError::ReadDir(dir_path.to_path_buf(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| DiscoveryError::ReadEntry(dir_path.to_path_buf(), e))?;
        let path = entry.path();

        if path.is_dir() {
            discover_recursive_inner(&path, esp_files)?;
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "esp" {
                    esp_files.push(path);
                }
            }
        }
    }

    Ok(())
}

/// Errors that can occur during file discovery
#[derive(Debug)]
pub enum DiscoveryError {
    /// Path is neither a file nor a directory
    InvalidPath(PathBuf),
    /// Failed to read directory
    ReadDir(PathBuf, std::io::Error),
    /// Failed to read directory entry
    ReadEntry(PathBuf, std::io::Error),
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryError::InvalidPath(p) => write!(f, "Invalid path: {}", p.display()),
            DiscoveryError::ReadDir(p, e) => {
                write!(f, "Failed to read directory {}: {}", p.display(), e)
            }
            DiscoveryError::ReadEntry(p, e) => {
                write!(f, "Failed to read entry in {}: {}", p.display(), e)
            }
        }
    }
}

impl std::error::Error for DiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DiscoveryError::InvalidPath(_) => None,
            DiscoveryError::ReadDir(_, e) | DiscoveryError::ReadEntry(_, e) => Some(e),
        }
    }
}
