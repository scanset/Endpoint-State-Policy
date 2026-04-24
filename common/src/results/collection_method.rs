//! Collection Method Types for Assessor Evidence Traceability
//!
//! This module provides types for documenting exactly how evidence was collected,
//! enabling assessors to verify and reproduce collection operations.
//!
//! # Architecture
//!
//! Collectors always populate `CollectionMethod` with full details (command, inputs).
//! The output format controls what gets serialized:
//!
//! - `attestation` mode: Only `method_type` in summary (CUI-free)
//! As of v2.0.0 there are no feature gates: every `CollectionMethod` carries
//! `command` + `inputs` unconditionally. The envelope is always the full
//! assessor shape — consumers that don't want those fields can drop them
//! post-serialization.
//!
//! # Example
//!
//! ```rust,ignore
//! use common::results::{CollectionMethod, CollectionMethodType};
//!
//! // Collectors always populate everything
//! let method = CollectionMethod::builder()
//!     .method_type(CollectionMethodType::Command)
//!     .description("Query Kubernetes API for Pod resources")
//!     .target("Pod:kube-system:component=kube-apiserver")
//!     .command("kubectl get pod -n kube-system -l component=kube-apiserver -o json")
//!     .input("kind", "Pod")
//!     .input("namespace", "kube-system")
//!     .build();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Collection Method Type
// ============================================================================

/// How evidence was collected
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionMethodType {
    /// System command execution (e.g., rpm, systemctl, kubectl)
    Command,

    /// File system read operation
    FileRead,

    /// File system metadata query (stat)
    FileStat,

    /// API call (REST, gRPC, etc.)
    ApiCall,

    /// Registry query (Windows)
    RegistryQuery,

    /// WMI query (Windows)
    WmiQuery,

    /// Process inspection
    ProcessInspection,

    /// Network socket inspection
    SocketInspection,

    /// Computed/derived value (no actual collection)
    Computed,

    /// Custom/other collection method
    Custom(String),
}

impl CollectionMethodType {
    /// Convert to string representation
    pub fn as_str(&self) -> &str {
        match self {
            CollectionMethodType::Command => "command",
            CollectionMethodType::FileRead => "file_read",
            CollectionMethodType::FileStat => "file_stat",
            CollectionMethodType::ApiCall => "api_call",
            CollectionMethodType::RegistryQuery => "registry_query",
            CollectionMethodType::WmiQuery => "wmi_query",
            CollectionMethodType::ProcessInspection => "process_inspection",
            CollectionMethodType::SocketInspection => "socket_inspection",
            CollectionMethodType::Computed => "computed",
            CollectionMethodType::Custom(s) => s.as_str(),
        }
    }

    /// Parse from string
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "command" => CollectionMethodType::Command,
            "file_read" => CollectionMethodType::FileRead,
            "file_stat" => CollectionMethodType::FileStat,
            "api_call" => CollectionMethodType::ApiCall,
            "registry_query" => CollectionMethodType::RegistryQuery,
            "wmi_query" => CollectionMethodType::WmiQuery,
            "process_inspection" => CollectionMethodType::ProcessInspection,
            "socket_inspection" => CollectionMethodType::SocketInspection,
            "computed" => CollectionMethodType::Computed,
            other => CollectionMethodType::Custom(other.to_string()),
        }
    }
}

impl std::fmt::Display for CollectionMethodType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ============================================================================
// Collection Method
// ============================================================================

/// Documents how evidence was collected for assessor traceability
///
/// This type captures the full details of how data was collected, allowing
/// assessors to verify and reproduce collection operations. The serialization
/// behavior varies based on the output format feature flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionMethod {
    /// Type of collection method used
    pub method_type: CollectionMethodType,

    /// Human-readable description of what was collected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Target resource identifier (e.g., file path, API endpoint, package name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// The exact command executed (v2.0.0: always serialized when present).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub command: Option<String>,

    /// Input parameters used in collection (v2.0.0: always serialized when present).
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub inputs: HashMap<String, String>,
}

impl CollectionMethod {
    /// Create a new CollectionMethod with just the method type
    pub fn new(method_type: CollectionMethodType) -> Self {
        Self {
            method_type,
            description: None,
            target: None,
            command: None,
            inputs: HashMap::new(),
        }
    }

    /// Create a builder for fluent construction
    pub fn builder() -> CollectionMethodBuilder {
        CollectionMethodBuilder::new()
    }

    /// Create a command-based collection method with description and target
    pub fn command(description: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            method_type: CollectionMethodType::Command,
            description: Some(description.into()),
            target: Some(target.into()),
            command: None,
            inputs: HashMap::new(),
        }
    }

    /// Create a command-based collection method with just the command string
    pub fn from_command(command: impl Into<String>) -> Self {
        Self {
            method_type: CollectionMethodType::Command,
            description: None,
            target: None,
            command: Some(command.into()),
            inputs: HashMap::new(),
        }
    }

    /// Create an API call collection method with description and endpoint
    pub fn api(description: impl Into<String>, endpoint: impl Into<String>) -> Self {
        Self {
            method_type: CollectionMethodType::ApiCall,
            description: Some(description.into()),
            target: Some(endpoint.into()),
            command: None,
            inputs: HashMap::new(),
        }
    }

    /// Create a file read collection method
    pub fn file_read(path: impl Into<String>) -> Self {
        Self {
            method_type: CollectionMethodType::FileRead,
            description: Some("Read file contents".to_string()),
            target: Some(path.into()),
            command: None,
            inputs: HashMap::new(),
        }
    }

    /// Create a file stat collection method
    pub fn file_stat(path: impl Into<String>) -> Self {
        Self {
            method_type: CollectionMethodType::FileStat,
            description: Some("Query file metadata".to_string()),
            target: Some(path.into()),
            command: None,
            inputs: HashMap::new(),
        }
    }

    /// Create an API call collection method
    pub fn api_call(endpoint: impl Into<String>) -> Self {
        Self {
            method_type: CollectionMethodType::ApiCall,
            description: None,
            target: Some(endpoint.into()),
            command: None,
            inputs: HashMap::new(),
        }
    }

    /// Create a socket inspection collection method
    pub fn socket_inspection() -> Self {
        Self {
            method_type: CollectionMethodType::SocketInspection,
            description: Some("Inspect network socket state".to_string()),
            target: None,
            command: None,
            inputs: HashMap::new(),
        }
    }

    /// Create a computed value collection method
    pub fn computed() -> Self {
        Self {
            method_type: CollectionMethodType::Computed,
            description: Some("Computed/derived value".to_string()),
            target: None,
            command: None,
            inputs: HashMap::new(),
        }
    }

    /// Add description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add target
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Add command
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Add an input parameter
    pub fn with_input(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inputs.insert(key.into(), value.into());
        self
    }

    /// Check if this method has assessor-level details
    pub fn has_assessor_details(&self) -> bool {
        self.command.is_some() || !self.inputs.is_empty()
    }
}

// ============================================================================
// Collection Method Builder
// ============================================================================

/// Builder for constructing CollectionMethod instances
#[derive(Debug, Default)]
pub struct CollectionMethodBuilder {
    method_type: Option<CollectionMethodType>,
    description: Option<String>,
    target: Option<String>,
    command: Option<String>,
    inputs: HashMap<String, String>,
}

impl CollectionMethodBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the method type
    pub fn method_type(mut self, method_type: CollectionMethodType) -> Self {
        self.method_type = Some(method_type);
        self
    }

    /// Set the description
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the target resource
    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Set the command
    pub fn command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Add an input parameter
    pub fn input(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inputs.insert(key.into(), value.into());
        self
    }

    /// Build the CollectionMethod
    ///
    /// # Panics
    ///
    /// Panics if method_type was not set
    #[allow(clippy::expect_used)]
    pub fn build(self) -> CollectionMethod {
        CollectionMethod {
            method_type: self.method_type.expect("method_type is required"),
            description: self.description,
            target: self.target,
            command: self.command,
            inputs: self.inputs,
        }
    }

    /// Try to build the CollectionMethod, returning None if method_type wasn't set
    pub fn try_build(self) -> Option<CollectionMethod> {
        Some(CollectionMethod {
            method_type: self.method_type?,
            description: self.description,
            target: self.target,
            command: self.command,
            inputs: self.inputs,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_method_type_parsing() {
        assert_eq!(
            CollectionMethodType::parse("command"),
            CollectionMethodType::Command
        );
        assert_eq!(
            CollectionMethodType::parse("file_read"),
            CollectionMethodType::FileRead
        );
        assert_eq!(
            CollectionMethodType::parse("api_call"),
            CollectionMethodType::ApiCall
        );

        // Custom type
        if let CollectionMethodType::Custom(s) = CollectionMethodType::parse("custom_type") {
            assert_eq!(s, "custom_type");
        } else {
            panic!("Expected Custom variant");
        }
    }

    #[test]
    fn test_builder() {
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Query RPM packages")
            .target("openssl")
            .command("rpm -q openssl")
            .input("package", "openssl")
            .build();

        assert_eq!(method.method_type, CollectionMethodType::Command);
        assert_eq!(method.description, Some("Query RPM packages".to_string()));
        assert_eq!(method.target, Some("openssl".to_string()));
        assert_eq!(method.command, Some("rpm -q openssl".to_string()));
        assert_eq!(method.inputs.get("package"), Some(&"openssl".to_string()));
    }

    #[test]
    fn test_convenience_constructors() {
        let file_read = CollectionMethod::file_read("/etc/passwd");
        assert_eq!(file_read.method_type, CollectionMethodType::FileRead);
        assert_eq!(file_read.target, Some("/etc/passwd".to_string()));

        let file_stat = CollectionMethod::file_stat("/etc/shadow");
        assert_eq!(file_stat.method_type, CollectionMethodType::FileStat);
        assert_eq!(file_stat.target, Some("/etc/shadow".to_string()));

        let api = CollectionMethod::api_call("https://api.example.com/v1/resource");
        assert_eq!(api.method_type, CollectionMethodType::ApiCall);

        let computed = CollectionMethod::computed();
        assert_eq!(computed.method_type, CollectionMethodType::Computed);
    }

    #[test]
    fn test_has_assessor_details() {
        let without_details = CollectionMethod::new(CollectionMethodType::FileRead);
        assert!(!without_details.has_assessor_details());

        let with_command = CollectionMethod::from_command("rpm -qa");
        assert!(with_command.has_assessor_details());

        let with_inputs =
            CollectionMethod::new(CollectionMethodType::ApiCall).with_input("namespace", "default");
        assert!(with_inputs.has_assessor_details());
    }

    #[test]
    fn test_serialization() {
        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Test command")
            .target("test-target")
            .build();

        let json = serde_json::to_string(&method).unwrap();
        assert!(json.contains("\"method_type\":\"command\""));
        assert!(json.contains("\"description\":\"Test command\""));
        assert!(json.contains("\"target\":\"test-target\""));
    }
}
